// ============================================================================
//  entropy.rs - GuitaRNG MPU node, entropy core
//  Jupiter Labs / CHIRASU Network
//
//  Pure `core` code. No allocator, no HAL, no hash dependency. Everything in
//  here is host-testable, which is the point: the parts that decide whether a
//  key is safe to mint should not require a flash cycle to verify.
//
//  What lives here:
//    - SourceId       : the fixed set of noise sources on this node
//    - Rct / Apt      : NIST SP 800-90B continuous health tests, PER SOURCE,
//                       on RAW samples, before any conditioning
//    - Markov         : SP 800-90B 6.3.3 binary Markov dependency estimate
//    - Stuck          : distinct-value detector, catches what RCT and APT miss
//    - SourceHealth   : all four tests plus a verdict for one source
//    - Budget         : credited-bit accounting, the thing that gates release
//
//  What does NOT live here: the hash. The extractor takes an `Absorb` so the
//  accounting can be tested without pulling in SHA3 or the HAL.
//
//  DESIGN NOTE (the Spectra fix):
//    Spectra ran its health tests on bytes pulled out of the mixed pool. Six
//    sources went in, one stream came out, and a dead source was invisible
//    because the survivors carried the statistics. Here every source is tested
//    on its own raw samples and carries its own credit. A dead axis loses its
//    credit and nothing else.
// ============================================================================

#![allow(dead_code)]

// ---------------------------------------------------------------------------
// Fixed-point min-entropy
// ---------------------------------------------------------------------------
//
// Min-entropy is carried in units of 1/256 bit as a u16. 4.0 bits/sample is
// 1024. This keeps the whole accounting path integer-only: no soft-float on a
// hot path, and identical arithmetic on host and device.

pub const H_UNIT: u32 = 256;

/// Convert whole-and-fractional bits to fixed point. `h_fixed(4, 0) == 1024`.
pub const fn h_fixed(whole: u16, two_fifty_sixths: u16) -> u16 {
    whole * 256 + two_fifty_sixths
}

// ---------------------------------------------------------------------------
// Sources
// ---------------------------------------------------------------------------

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum SourceId {
    AccelX = 0,
    AccelY = 1,
    AccelZ = 2,
    GyroX = 3,
    GyroY = 4,
    GyroZ = 5,
    MpuTemp = 6,
    /// MPU data-ready edge timed against the CPU cycle counter. Two
    /// independent oscillators beating; not MEMS noise, genuinely separate
    /// physics from the axes above.
    ClockBeat = 7,
    /// Time of a detected motion frame. Sparse, environmental and uncredited.
    MotionTiming = 8,
    /// I2C transaction duration. Mixed because bus/interrupt contention adds
    /// useful diversity, but correlated with firmware scheduling.
    BusTiming = 9,
    /// The high bytes of the MPU frame (orientation and gross motion). These
    /// are deliberately not used to fund the entropy budget.
    MpuFrame = 10,
    /// ESP32-S3 hardware RNG. Espressif documents it as a true random source
    /// whenever the radio is on, which on this node is always (the setup
    /// network never shuts off). Credited at the same cautious provisional
    /// 0.5 bit/sample as the MPU sources, and measured on-device like them.
    HwRng = 11,
    /// Associated AP RSSI. Environment-dependent and slowly sampled.
    WifiRssi = 12,
    /// UDP receive/send completion timing. Remote-influenced, never credited.
    NetworkTiming = 13,
    /// Native USB packet arrival timing. Host-influenced, never credited.
    UsbTiming = 14,
    /// Low byte of an ADC1 reading on an unconnected pin (GPIO1): thermal and
    /// coupled noise at the converter input. Mixed, never credited, until it
    /// has been measured.
    AdcNoise = 15,
}

pub const SOURCE_COUNT: usize = 16;

impl SourceId {
    pub const ALL: [SourceId; SOURCE_COUNT] = [
        SourceId::AccelX,
        SourceId::AccelY,
        SourceId::AccelZ,
        SourceId::GyroX,
        SourceId::GyroY,
        SourceId::GyroZ,
        SourceId::MpuTemp,
        SourceId::ClockBeat,
        SourceId::MotionTiming,
        SourceId::BusTiming,
        SourceId::MpuFrame,
        SourceId::HwRng,
        SourceId::WifiRssi,
        SourceId::NetworkTiming,
        SourceId::UsbTiming,
        SourceId::AdcNoise,
    ];

    pub fn index(self) -> usize {
        self as usize
    }

    /// Sources that may ever fund a release, once given an assessment above
    /// zero. The rest stay mixed-only whatever is typed in: timing seen by
    /// the network or USB host is influenced from outside, RSSI can be steered
    /// by anyone with a transmitter, bus and motion timing are driven by the
    /// firmware and the player, and the frame's high bytes are orientation.
    pub fn creditable(self) -> bool {
        matches!(
            self,
            SourceId::AccelX
                | SourceId::AccelY
                | SourceId::AccelZ
                | SourceId::GyroX
                | SourceId::GyroY
                | SourceId::GyroZ
                | SourceId::MpuTemp
                | SourceId::ClockBeat
                | SourceId::HwRng
                | SourceId::AdcNoise
        )
    }

    /// Sampled only on an MPU data-ready edge. Everything else is also
    /// sampled on the ESP32's own clock while the MPU is missing.
    pub fn needs_mpu(self) -> bool {
        matches!(
            self,
            SourceId::AccelX
                | SourceId::AccelY
                | SourceId::AccelZ
                | SourceId::GyroX
                | SourceId::GyroY
                | SourceId::GyroZ
                | SourceId::MpuTemp
                | SourceId::ClockBeat
                | SourceId::MotionTiming
                | SourceId::BusTiming
                | SourceId::MpuFrame
        )
    }

    pub fn name(self) -> &'static str {
        match self {
            SourceId::AccelX => "accel_x",
            SourceId::AccelY => "accel_y",
            SourceId::AccelZ => "accel_z",
            SourceId::GyroX => "gyro_x",
            SourceId::GyroY => "gyro_y",
            SourceId::GyroZ => "gyro_z",
            SourceId::MpuTemp => "mpu_temp",
            SourceId::ClockBeat => "clock_beat",
            SourceId::MotionTiming => "motion_timing",
            SourceId::BusTiming => "bus_timing",
            SourceId::MpuFrame => "mpu_frame",
            SourceId::HwRng => "hw_rng",
            SourceId::WifiRssi => "wifi_rssi",
            SourceId::NetworkTiming => "network_timing",
            SourceId::UsbTiming => "usb_timing",
            SourceId::AdcNoise => "adc_noise",
        }
    }
}

// ---------------------------------------------------------------------------
// Health verdicts
// ---------------------------------------------------------------------------

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Verdict {
    /// Not enough samples yet to judge. Mixed, not credited.
    Warming,
    /// All continuous tests passing. Credited.
    Healthy,
    /// A test is close to its cutoff. Still credited, but worth surfacing.
    Degraded,
    /// A test tripped. Latched off: mixed, never credited, until reset.
    Failed,
}

impl Verdict {
    pub fn credits(self) -> bool {
        matches!(self, Verdict::Healthy | Verdict::Degraded)
    }
}

// ---------------------------------------------------------------------------
// Repetition Count Test (SP 800-90B 4.4.1)
// ---------------------------------------------------------------------------
//
// Cutoff C = 1 + ceil(20 / H). Fails when a single value occurs C times in a
// row. Note the cutoff is DERIVED from the assessed min-entropy of that
// source, which is why Spectra's hardcoded 32 was wrong: 32 silently asserts
// H ~= 0.645 bits/sample for every source at once.

#[derive(Copy, Clone, Debug)]
pub struct Rct {
    cutoff: u32,
    last: u8,
    run: u32,
    have_last: bool,
    pub max_run: u32,
    pub failures: u32,
}

impl Rct {
    pub fn new(cutoff: u32) -> Self {
        Rct {
            cutoff,
            last: 0,
            run: 0,
            have_last: false,
            max_run: 0,
            failures: 0,
        }
    }

    /// Returns true if this sample tripped the test.
    pub fn push(&mut self, s: u8) -> bool {
        if self.have_last && s == self.last {
            self.run += 1;
        } else {
            self.last = s;
            self.have_last = true;
            self.run = 1;
        }
        if self.run > self.max_run {
            self.max_run = self.run;
        }
        if self.run >= self.cutoff {
            self.failures += 1;
            // Restart the run so one dead stretch reports once per cutoff
            // window rather than once per sample forever after.
            self.run = 0;
            self.have_last = false;
            return true;
        }
        false
    }

    /// Samples in a row that fail this test.
    pub fn cutoff(&self) -> u32 {
        self.cutoff
    }

    /// Fraction of the cutoff currently reached, in percent. Drives the
    /// Degraded verdict without a second tunable.
    pub fn pressure(&self) -> u32 {
        if self.cutoff == 0 {
            return 0;
        }
        self.run * 100 / self.cutoff
    }
}

// ---------------------------------------------------------------------------
// Adaptive Proportion Test (SP 800-90B 4.4.2)
// ---------------------------------------------------------------------------
//
// The real one. Take the FIRST sample of each window, then count how many of
// the window's W samples equal it. Fail if that count reaches the cutoff.
//
// Spectra implemented a monobit test under this name: it counted ones across a
// bit window. That detects bias but not a source that has collapsed onto a
// small set of values, which is the failure APT exists to catch.

pub const APT_WINDOW: u32 = 512;

#[derive(Copy, Clone, Debug)]
pub struct Apt {
    cutoff: u32,
    window: u32,
    reference: u8,
    have_ref: bool,
    seen: u32,
    matches: u32,
    pub max_matches: u32,
    pub failures: u32,
}

impl Apt {
    pub fn new(cutoff: u32, window: u32) -> Self {
        Apt {
            cutoff,
            window,
            reference: 0,
            have_ref: false,
            seen: 0,
            matches: 0,
            max_matches: 0,
            failures: 0,
        }
    }

    pub fn push(&mut self, s: u8) -> bool {
        if !self.have_ref {
            self.reference = s;
            self.have_ref = true;
            self.seen = 1;
            self.matches = 1;
        } else {
            self.seen += 1;
            if s == self.reference {
                self.matches += 1;
            }
        }

        let mut tripped = false;
        if self.matches >= self.cutoff {
            self.failures += 1;
            tripped = true;
        }

        if self.matches > self.max_matches {
            self.max_matches = self.matches;
        }

        if self.seen >= self.window || tripped {
            // Start a fresh window. A trip ends the window early so the next
            // window gets a clean reference sample.
            self.have_ref = false;
            self.seen = 0;
            self.matches = 0;
        }

        tripped
    }

    /// Matches within one window that fail this test.
    pub fn cutoff(&self) -> u32 {
        self.cutoff
    }

    pub fn pressure(&self) -> u32 {
        if self.cutoff == 0 {
            return 0;
        }
        self.matches * 100 / self.cutoff
    }
}

// ---------------------------------------------------------------------------
// Distinct-value detector
// ---------------------------------------------------------------------------
//
// Not a NIST test. It covers the gap between RCT and APT: a source that
// alternates between a handful of values passes RCT (no long runs) and can
// pass APT (no single value dominates) while carrying almost no entropy.
//
// A snapped I2C line that latches, or an axis whose LSBs stop moving while the
// mid bits dither, both look like this. 32 bytes of bitmap per source.

#[derive(Copy, Clone, Debug)]
pub struct Stuck {
    seen: [u8; 32],
    count: u32,
    window: u32,
    min_distinct: u32,
    pub last_distinct: u32,
    pub failures: u32,
}

impl Stuck {
    pub fn new(window: u32, min_distinct: u32) -> Self {
        Stuck {
            seen: [0u8; 32],
            count: 0,
            window,
            min_distinct,
            last_distinct: 0,
            failures: 0,
        }
    }

    pub fn push(&mut self, s: u8) -> bool {
        self.seen[(s >> 3) as usize] |= 1u8 << (s & 7);
        self.count += 1;

        if self.count < self.window {
            return false;
        }

        let mut distinct = 0u32;
        for b in self.seen.iter() {
            distinct += b.count_ones();
        }
        self.last_distinct = distinct;

        self.seen = [0u8; 32];
        self.count = 0;

        if distinct < self.min_distinct {
            self.failures += 1;
            return true;
        }
        false
    }
}

// ---------------------------------------------------------------------------
// Markov dependency estimate (SP 800-90B section 6.3.3)
// ---------------------------------------------------------------------------
//
// The finalized SP 800-90B Markov estimator is defined for a binary alphabet.
// Each raw byte is therefore serialized MSB-first into eight binary symbols.
// For each window we estimate P(0), P(1), and the four one-step transition
// probabilities. Dynamic programming then finds the most likely 128-bit path.
// Its -log2 probability divided by 128 is the Markov min-entropy estimate.
//
// This is an online *dependency gate*, not a replacement for the offline
// `ea_non_iid` assessment. RCT and APT remain the required continuous health
// tests. Markov is extra and deliberately latches a source off when it finds a
// more predictable raw stream than that source's claimed entropy permits.

const MARKOV_SEQUENCE_BITS: usize = 128;
const LOG_Q: u32 = 256;
const LOG_INF: u32 = u32::MAX / 4;

#[derive(Copy, Clone, Debug)]
pub struct Markov {
    transition: [[u32; 2]; 2],
    symbols: [u32; 2],
    bits: u32,
    last: u8,
    have_last: bool,
    window_bits: u32,
    /// Minimum acceptable entropy per input bit, Q8.8.
    threshold_q8: u16,
    /// Most recent SP 800-90B Markov estimate, Q8.8 bits/input-bit.
    pub last_h_q8: u16,
    pub windows: u32,
    pub failures: u32,
}

impl Markov {
    pub fn new(window_bits: u32, threshold_q8: u16) -> Self {
        Markov {
            transition: [[0; 2]; 2],
            symbols: [0; 2],
            bits: 0,
            last: 0,
            have_last: false,
            window_bits,
            threshold_q8,
            last_h_q8: 0,
            windows: 0,
            failures: 0,
        }
    }

    /// Feed one raw byte. Returns true if a completed Markov window failed.
    pub fn push(&mut self, sample: u8) -> bool {
        let mut tripped = false;
        for shift in (0..8).rev() {
            let bit = (sample >> shift) & 1;
            self.symbols[bit as usize] += 1;
            self.bits += 1;
            if self.have_last {
                self.transition[self.last as usize][bit as usize] += 1;
            }
            self.last = bit;
            self.have_last = true;

            if self.bits >= self.window_bits {
                self.last_h_q8 = self.estimate_q8();
                self.windows += 1;
                if self.last_h_q8 < self.threshold_q8 {
                    self.failures += 1;
                    tripped = true;
                }
                self.transition = [[0; 2]; 2];
                self.symbols = [0; 2];
                self.bits = 0;
                self.have_last = false;
            }
        }
        tripped
    }

    fn estimate_q8(&self) -> u16 {
        let total = self.symbols[0] + self.symbols[1];
        if total == 0 {
            return 0;
        }

        let initial = [
            neg_log2_ratio_q8(self.symbols[0], total),
            neg_log2_ratio_q8(self.symbols[1], total),
        ];
        let row0 = self.transition[0][0] + self.transition[0][1];
        let row1 = self.transition[1][0] + self.transition[1][1];
        let cost = [
            [
                neg_log2_ratio_q8(self.transition[0][0], row0),
                neg_log2_ratio_q8(self.transition[0][1], row0),
            ],
            [
                neg_log2_ratio_q8(self.transition[1][0], row1),
                neg_log2_ratio_q8(self.transition[1][1], row1),
            ],
        ];

        let mut end = initial;
        for _ in 1..MARKOV_SEQUENCE_BITS {
            let next0 = add_log(end[0], cost[0][0]).min(add_log(end[1], cost[1][0]));
            let next1 = add_log(end[0], cost[0][1]).min(add_log(end[1], cost[1][1]));
            end = [next0, next1];
        }

        let path_q8 = end[0].min(end[1]);
        if path_q8 >= LOG_INF {
            return 0;
        }
        (path_q8 / MARKOV_SEQUENCE_BITS as u32).min(u16::MAX as u32) as u16
    }

    pub fn degraded(&self) -> bool {
        self.windows != 0
            && self.last_h_q8 < self.threshold_q8.saturating_add(self.threshold_q8 / 2)
    }
}

fn add_log(a: u32, b: u32) -> u32 {
    if a >= LOG_INF || b >= LOG_INF {
        LOG_INF
    } else {
        a.saturating_add(b).min(LOG_INF)
    }
}

/// Return -log2(numerator / denominator) in Q8.8. The iterative-square
/// fractional logarithm avoids floats and is deterministic on host and target.
fn neg_log2_ratio_q8(numerator: u32, denominator: u32) -> u32 {
    if numerator == 0 || denominator == 0 || numerator > denominator {
        return LOG_INF;
    }
    if numerator == denominator {
        return 0;
    }

    let ratio_q32 = ((denominator as u128) << 32) / numerator as u128;
    let integer = (127 - ratio_q32.leading_zeros()) as u32 - 32;
    let mut normalized = ratio_q32 >> integer; // [1.0, 2.0) in Q32
    let mut fractional = 0u32;
    for bit in (0..8).rev() {
        normalized = (normalized * normalized) >> 32;
        if normalized >= (2u128 << 32) {
            normalized >>= 1;
            fractional |= 1 << bit;
        }
    }
    integer * LOG_Q + fractional
}

// ---------------------------------------------------------------------------
// Per-source health
// ---------------------------------------------------------------------------

#[derive(Copy, Clone, Debug)]
pub struct SourceHealth {
    pub id: SourceId,
    /// Assessed min-entropy per sample, fixed point (1/256 bit units).
    pub h: u16,
    /// False for sources we mix but never count toward the budget.
    pub credited: bool,
    pub rct: Rct,
    pub apt: Apt,
    pub markov: Markov,
    pub stuck: Stuck,
    pub samples: u64,
    pub verdict: Verdict,
    warmup: u64,
}

/// Verdicts stay Warming until a source has produced this many samples, so a
/// cold start cannot mint a key off three lucky readings.
pub const DEFAULT_WARMUP: u64 = 4096;

impl SourceHealth {
    /// `credited` is honoured only for a creditable source with an assessment
    /// above zero; see `SourceId::creditable`.
    pub fn new(id: SourceId, h: u16, credited: bool) -> Self {
        let credited = credited && h > 0 && id.creditable();
        let (rct_c, apt_c) = cutoffs_for(h);
        // Convert the per-byte assessment to a conservative per-serialized-bit
        // floor. Uncredited sources still get a small dependency tripwire so
        // their status remains informative, but they never fund a release.
        let markov_floor = if h == 0 {
            8
        } else {
            ((h as u32 + 7) / 8) as u16
        };
        SourceHealth {
            id,
            h,
            credited,
            rct: Rct::new(rct_c),
            apt: Apt::new(apt_c, APT_WINDOW),
            markov: Markov::new(crate::config::MARKOV_WINDOW_BITS, markov_floor),
            stuck: Stuck::new(1024, 16),
            samples: 0,
            verdict: Verdict::Warming,
            warmup: DEFAULT_WARMUP,
        }
    }

    pub fn with_warmup(mut self, n: u64) -> Self {
        self.warmup = n;
        self
    }

    /// Feed one raw sample. Returns the credit earned, in 1/256-bit units.
    ///
    /// Credit is zero unless the source is credited AND currently passing.
    /// The sample is still the caller's to mix either way: a failed source is
    /// never trusted, but it is also never thrown away.
    pub fn push(&mut self, s: u8) -> u32 {
        self.samples += 1;

        let rct_trip = self.rct.push(s);
        let apt_trip = self.apt.push(s);
        let markov_trip = self.markov.push(s);
        let stuck_trip = self.stuck.push(s);

        if rct_trip || apt_trip || markov_trip || stuck_trip {
            // Latched. A source that has demonstrably failed does not get to
            // heal itself back into the budget without an explicit reset.
            self.verdict = Verdict::Failed;
            return 0;
        }

        if self.verdict == Verdict::Failed {
            return 0;
        }

        if self.samples < self.warmup {
            self.verdict = Verdict::Warming;
            return 0;
        }

        self.verdict =
            if self.rct.pressure() >= 70 || self.apt.pressure() >= 70 || self.markov.degraded() {
                Verdict::Degraded
            } else {
                Verdict::Healthy
            };

        if self.credited && self.verdict.credits() {
            self.h as u32
        } else {
            0
        }
    }

    /// Clear a latched failure. Deliberately explicit: reached from the
    /// control plane, never automatically.
    pub fn reset(&mut self) {
        let (rct_c, apt_c) = cutoffs_for(self.h);
        self.rct = Rct::new(rct_c);
        self.apt = Apt::new(apt_c, APT_WINDOW);
        let markov_floor = if self.h == 0 {
            8
        } else {
            ((self.h as u32 + 7) / 8) as u16
        };
        self.markov = Markov::new(crate::config::MARKOV_WINDOW_BITS, markov_floor);
        self.stuck = Stuck::new(1024, 16);
        self.samples = 0;
        self.verdict = Verdict::Warming;
    }
}

// ---------------------------------------------------------------------------
// Cutoff table
// ---------------------------------------------------------------------------
//
// RCT: C = 1 + ceil(20 / H)
// APT: C = 1 + CRITBINOM(W = 512, p = 2^-H, 1 - 2^-20)
//
// Both are functions of the assessed min-entropy, so they are tabulated in
// 0.5-bit steps from 0.5 to 8.0 and looked up by rounding H DOWN. Rounding
// down is the conservative direction: it assumes less entropy than measured,
// which yields a tighter cutoff and a test that trips sooner.
//
// The table is verified against a from-scratch binomial computation in the
// host harness rather than trusted as typed.

// The APT window counts the reference sample itself as a match, so the
// binomial is over W trials, not W-1. Implementations differ by one count on
// this point; W is the tighter of the two, which is the side to be on.
const CUTOFFS: [(u16, u32, u32); 16] = [
    // (h_fixed, rct_cutoff, apt_cutoff)
    (h_fixed(0, 128), 41, 410), // 0.5
    (h_fixed(1, 0), 21, 311),   // 1.0
    (h_fixed(1, 128), 15, 234), // 1.5
    (h_fixed(2, 0), 11, 177),   // 2.0
    (h_fixed(2, 128), 9, 135),  // 2.5
    (h_fixed(3, 0), 8, 103),    // 3.0
    (h_fixed(3, 128), 7, 80),   // 3.5
    (h_fixed(4, 0), 6, 62),     // 4.0
    (h_fixed(4, 128), 6, 49),   // 4.5
    (h_fixed(5, 0), 5, 39),     // 5.0
    (h_fixed(5, 128), 5, 31),   // 5.5
    (h_fixed(6, 0), 5, 25),     // 6.0
    (h_fixed(6, 128), 5, 21),   // 6.5
    (h_fixed(7, 0), 4, 18),     // 7.0
    (h_fixed(7, 128), 4, 15),   // 7.5
    (h_fixed(8, 0), 4, 13),     // 8.0
];

/// Look up (rct_cutoff, apt_cutoff) for an assessed min-entropy, rounding the
/// entropy DOWN to the nearest tabulated step.
pub fn cutoffs_for(h: u16) -> (u32, u32) {
    let mut chosen = CUTOFFS[0];
    for entry in CUTOFFS.iter() {
        if entry.0 <= h {
            chosen = *entry;
        }
    }
    (chosen.1, chosen.2)
}

// ---------------------------------------------------------------------------
// Credit budget
// ---------------------------------------------------------------------------
//
// The release gate. Key material leaves this node only once the CREDITED
// sources have supplied at least `target_bits` of assessed min-entropy since
// the last release. Uncredited sources are mixed in and contribute nothing to
// this counter, which is the whole point of the distinction.
//
// The counter is capped at two releases' worth. The conditioner is SHA3-512:
// one digest holds at most 512 bits, and after a release only the 256-bit
// chaining half stays behind. Credit beyond that is not in the state, so
// counting it would let a node that sat unreleased for an hour (MPU missing,
// floor not met) later emit thousands of blocks on entropy it no longer holds.

#[derive(Copy, Clone, Debug)]
pub struct Budget {
    /// Accumulated credit in 1/256-bit units.
    accrued: u32,
    /// Release threshold in 1/256-bit units.
    target: u32,
    pub releases: u32,
}

impl Budget {
    pub fn new(target_bits: u32) -> Self {
        Budget {
            accrued: 0,
            target: target_bits * H_UNIT,
            releases: 0,
        }
    }

    /// Add credit, up to the cap. Returns how much was accepted.
    ///
    /// Private: only `Harvester` may move credit, so its per-source record of
    /// who holds the pool can never drift from the pool itself.
    fn add(&mut self, credit_units: u32) -> u32 {
        let cap = self.target.saturating_mul(2);
        let accepted = credit_units.min(cap.saturating_sub(self.accrued));
        self.accrued += accepted;
        accepted
    }

    /// Discard credit accumulated since the last release. Reached only
    /// through `Harvester::discard_credit`: a credited source failing a
    /// health test, a health reset, an assessment change or the end of a
    /// DUMP.
    fn clear(&mut self) {
        self.accrued = 0;
    }

    pub fn ready(&self) -> bool {
        self.accrued >= self.target
    }

    /// Spend one release worth of credit. Returns false if not ready.
    ///
    /// Subtracts the target rather than zeroing: credit earned beyond the
    /// threshold, at most one release's worth, is held by the chaining half
    /// and carries into the next key.
    pub fn consume(&mut self) -> bool {
        if !self.ready() {
            return false;
        }
        self.accrued -= self.target;
        self.releases += 1;
        true
    }

    /// Progress toward the next release, in percent, capped at 100.
    pub fn percent(&self) -> u32 {
        if self.target == 0 {
            return 100;
        }
        let p = self.accrued * 100 / self.target;
        if p > 100 {
            100
        } else {
            p
        }
    }

    pub fn accrued_bits(&self) -> u32 {
        self.accrued / H_UNIT
    }
}


// ---------------------------------------------------------------------------
// Measurement: Shannon and most-common-value min-entropy
// ---------------------------------------------------------------------------
//
// The health tests above answer "has this source broken?". These answer "how
// much is it actually giving?", per source, on the raw samples, so the
// provisional assessments can be checked against the instrument itself.
//
// Each source fills a 256-bin histogram over a fixed window of samples. When
// the window completes, two estimates are taken and the histogram starts over:
//
//   Shannon       H = -sum p log2 p            (average surprise, an upper
//                                               bound on usable entropy)
//   Min-entropy   SP 800-90B 6.3.1, most common value:
//                 p_u = p_hat + 2.576 sqrt(p_hat (1 - p_hat) / (N - 1))
//                 H   = -log2(p_u)             (what a best guesser faces,
//                                               with the 99% upper bound NIST
//                                               applies)
//
// Both are in the same 1/256-bit units as `h`, so all three line up.
//
// These are SCREENING numbers, and conservative ones. Simulated on a perfect
// 8-bit source, the ceilings are:
//
//   window    Shannon   MCV min-entropy
//     256       7.17        4.64
//    4096       7.95        6.61
//    8192       7.98        6.93
//
// MCV is also only one of the SP 800-90B estimators. The full assessment is still NIST's ea_non_iid on a raw capture
// of at least a million samples (see DUMP in main.rs).

/// Samples per estimate for sources that produce every frame.
pub const STATS_WINDOW_FAST: u16 = 4096;
/// Samples per estimate for sources that produce a few times a second at
/// most. Estimates from windows this small are rough, and the dashboard shows
/// the window size beside every number.
pub const STATS_WINDOW_SLOW: u16 = 256;
/// Bytes per estimate on the conditioned output (about four minutes of blocks).
pub const STATS_WINDOW_OUTPUT: u16 = 8192;

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Estimate {
    /// Samples the estimate was taken over.
    pub n: u32,
    /// Shannon entropy per sample, 1/256 bit.
    pub shannon_q8: u16,
    /// Most-common-value min-entropy per sample, 1/256 bit.
    pub min_q8: u16,
    /// Distinct values seen in the window.
    pub distinct: u16,
}

/// Running totals stop growing here, well inside the fixed-point range, and
/// the estimate simply holds. About 25 days of a 1 kHz source.
pub const CUMULATIVE_LIMIT: u32 = 1 << 31;

#[derive(Copy, Clone, Debug)]
pub struct Stats {
    hist: [u16; 256],
    n: u16,
    window: u16,
    /// Last completed window, if any.
    pub last: Option<Estimate>,
    /// Windows completed since boot.
    pub windows: u32,
    /// Every completed window since the last measurement reset, merged.
    /// Short windows cap the min-entropy a perfect source can show (see the
    /// table above); the running total is what converges on the real value.
    cum: [u32; 256],
    cum_n: u32,
    /// Estimate over the running total, refreshed as each window completes.
    pub total: Option<Estimate>,
}

impl Stats {
    pub const fn new(window: u16) -> Self {
        Stats {
            hist: [0; 256],
            n: 0,
            window,
            last: None,
            windows: 0,
            cum: [0; 256],
            cum_n: 0,
            total: None,
        }
    }

    pub fn push(&mut self, sample: u8) {
        self.hist[sample as usize] += 1;
        self.n += 1;
        if self.n >= self.window {
            self.last = Some(estimate(&self.hist, self.n as u32));
            self.windows = self.windows.wrapping_add(1);
            if self.cum_n <= CUMULATIVE_LIMIT - self.n as u32 {
                for (c, h) in self.cum.iter_mut().zip(self.hist.iter()) {
                    *c += *h as u32;
                }
                self.cum_n += self.n as u32;
                self.total = Some(estimate(&self.cum, self.cum_n));
            }
            self.hist = [0; 256];
            self.n = 0;
        }
    }

    /// Start the running total over. The current window is left alone.
    pub fn reset_total(&mut self) {
        self.cum = [0; 256];
        self.cum_n = 0;
        self.total = None;
    }

    /// Samples collected toward the window in progress.
    pub fn progress(&self) -> u16 {
        self.n
    }

    pub fn window(&self) -> u16 {
        self.window
    }
}

fn isqrt_u128(v: u128) -> u128 {
    if v < 2 {
        return v;
    }
    // Newton's method from an over-estimate converges monotonically down.
    let mut x = 1u128 << ((128 - v.leading_zeros() + 1) / 2);
    loop {
        let y = (x + v / x) / 2;
        if y >= x {
            return x;
        }
        x = y;
    }
}

/// Shannon and MCV min-entropy of a histogram of `n` samples.
pub fn estimate<T: Copy + Into<u32>>(hist: &[T; 256], n: u32) -> Estimate {
    if n == 0 {
        return Estimate {
            n: 0,
            shannon_q8: 0,
            min_q8: 0,
            distinct: 0,
        };
    }
    let total = n;
    let mut weighted: u64 = 0;
    let mut max = 0u32;
    let mut distinct = 0u16;
    for &c in hist.iter() {
        let c: u32 = c.into();
        if c == 0 {
            continue;
        }
        distinct += 1;
        max = max.max(c);
        weighted += c as u64 * neg_log2_ratio_q8(c, total) as u64;
    }
    let shannon_q8 = (weighted / total as u64).min(8 * 256) as u16;

    // MCV with the 99% upper confidence bound, in units of S = 2^30.
    const S: u128 = 1 << 30;
    let min_q8 = if total < 2 {
        0
    } else {
        let (m, t) = (max as u128, total as u128);
        let p_hat = m * S / t;
        let var = m * (t - m) * S * S / (t * t * (t - 1));
        let p_upper = (p_hat + isqrt_u128(var) * 2576 / 1000).min(S);
        if p_upper >= S {
            0
        } else {
            neg_log2_ratio_q8(p_upper as u32, S as u32).min(8 * 256) as u16
        }
    };

    Estimate {
        n,
        shannon_q8,
        min_q8,
        distinct,
    }
}

// ---------------------------------------------------------------------------
// Measurement: the conditioned output
// ---------------------------------------------------------------------------
//
// The same questions asked of what actually leaves the node. The output is a
// SHA3 hash, so it should look like full entropy (8 bits per byte) no matter
// how weak the inputs were; that is exactly why output statistics can never
// stand in for source assessment. What they DO catch is a conditioner or
// release-path fault: a stuck buffer, a repeated block, a byte-order bug.
//
// Only aggregate figures are kept. No released byte is stored.

#[derive(Copy, Clone, Debug)]
pub struct OutputStats {
    pub stats: Stats,
    pub rct: Rct,
    pub apt: Apt,
    pub markov: Markov,
    pub bytes: u64,
}

impl OutputStats {
    pub fn new() -> Self {
        // Health tests set as for a full-entropy source.
        let (rct_c, apt_c) = cutoffs_for(h_fixed(8, 0));
        OutputStats {
            stats: Stats::new(STATS_WINDOW_OUTPUT),
            rct: Rct::new(rct_c),
            apt: Apt::new(apt_c, APT_WINDOW),
            markov: Markov::new(crate::config::MARKOV_WINDOW_BITS, 0),
            bytes: 0,
        }
    }

    /// Start the measurements over (health-test failure counts included).
    pub fn reset(&mut self) {
        *self = OutputStats::new();
    }

    pub fn push(&mut self, block: &[u8]) {
        for &b in block {
            self.stats.push(b);
            self.rct.push(b);
            self.apt.push(b);
            self.markov.push(b);
        }
        self.bytes = self.bytes.wrapping_add(block.len() as u64);
    }
}

// ---------------------------------------------------------------------------
// Raw capture tap
// ---------------------------------------------------------------------------
//
// For the full NIST SP 800-90B assessment the raw samples of one source have
// to leave the device. The tap copies one chosen source's samples, in order,
// into a small buffer that the firmware drains to USB. While the tap is open
// the harvester refuses to release anything, because samples that have been
// printed are no longer secret.

pub const TAP_LEN: usize = 64;

#[derive(Copy, Clone, Debug)]
pub struct Tap {
    pub source: Option<SourceId>,
    pub buf: [u8; TAP_LEN],
    pub len: usize,
    /// Samples lost because the buffer was full. Any loss means the capture
    /// has gaps and must not be fed to the NIST tool.
    pub overflow: u32,
}

impl Tap {
    pub const fn new() -> Self {
        Tap {
            source: None,
            buf: [0; TAP_LEN],
            len: 0,
            overflow: 0,
        }
    }

    fn push(&mut self, id: SourceId, sample: u8) {
        if self.source != Some(id) {
            return;
        }
        if self.len < TAP_LEN {
            self.buf[self.len] = sample;
            self.len += 1;
        } else {
            self.overflow = self.overflow.saturating_add(1);
        }
    }
}

// ---------------------------------------------------------------------------
// Conditioner interface
// ---------------------------------------------------------------------------
//
// Kept abstract so the accounting above can be exercised on the host without
// dragging in SHA3 or the HAL. The device supplies the real
// implementation; the harness supplies a counting stub.

pub trait Absorb {
    fn absorb(&mut self, data: &[u8]);
    fn squeeze(&mut self, out: &mut [u8]);
}

// ---------------------------------------------------------------------------
// The node's source table
// ---------------------------------------------------------------------------

pub struct Harvester {
    pub sources: [SourceHealth; SOURCE_COUNT],
    pub budget: Budget,
    /// Entropy estimates per source, by `SourceId` index.
    pub stats: [Stats; SOURCE_COUNT],
    /// Estimates and health tests on the released output.
    pub output: OutputStats,
    pub tap: Tap,
    /// Each source's share of the credit sitting in the budget right now, in
    /// 1/256-bit units. Always sums to the budget's accrued credit: a sample
    /// arriving at a full budget adds to neither.
    pooled: [u32; SOURCE_COUNT],
    /// Credit from each source that was spent on released blocks since the
    /// last measurement reset, in 1/256-bit units: exactly who paid for the
    /// output. Credit thrown away by a health failure, an assessment change or
    /// a DUMP never reaches this.
    pub funded: [u64; SOURCE_COUNT],
}

impl Harvester {
    /// Build with deliberately low provisional assessments.
    ///
    /// Every `h` here is a PLACEHOLDER pending the Phase 0 bench
    /// characterization. They are deliberately capped at 0.5 bit/sample.
    /// Raising one without a
    /// measurement to back it is how a node starts lying about its keys.
    pub fn new(target_bits: u32) -> Self {
        use SourceId::*;
        let s = |id, h, credited| SourceHealth::new(id, h, credited);
        Harvester {
            sources: [
                s(AccelX, h_fixed(0, 128), true),
                s(AccelY, h_fixed(0, 128), true),
                s(AccelZ, h_fixed(0, 128), true),
                s(GyroX, h_fixed(0, 128), true),
                s(GyroY, h_fixed(0, 128), true),
                s(GyroZ, h_fixed(0, 128), true),
                s(MpuTemp, h_fixed(0, 128), true),
                s(ClockBeat, h_fixed(0, 128), true),
                s(MotionTiming, h_fixed(0, 0), false),
                s(BusTiming, h_fixed(0, 0), false),
                s(MpuFrame, h_fixed(0, 0), false),
                s(HwRng, h_fixed(0, 128), true),
                s(WifiRssi, h_fixed(0, 0), false),
                s(NetworkTiming, h_fixed(0, 0), false),
                s(UsbTiming, h_fixed(0, 0), false),
                // Creditable, but unassessed until measured: typing in an
                // assessment above zero makes it count.
                s(AdcNoise, h_fixed(0, 0), true),
            ],
            budget: Budget::new(target_bits),
            stats: SourceId::ALL.map(|id| {
                Stats::new(match id {
                    MotionTiming | WifiRssi | NetworkTiming | UsbTiming => STATS_WINDOW_SLOW,
                    _ => STATS_WINDOW_FAST,
                })
            }),
            output: OutputStats::new(),
            tap: Tap::new(),
            pooled: [0; SOURCE_COUNT],
            funded: [0; SOURCE_COUNT],
        }
    }

    /// Throw away every bit of unspent credit, and the record of who put it
    /// there. The only way unspent credit is ever discarded.
    pub fn discard_credit(&mut self) {
        self.budget.clear();
        self.pooled = [0; SOURCE_COUNT];
    }

    /// Feed one raw sample from one source. Mixes unconditionally, credits
    /// conditionally.
    pub fn push<A: Absorb>(&mut self, id: SourceId, sample: u8, sink: &mut A) {
        let source = &mut self.sources[id.index()];
        let was_failed = source.verdict == Verdict::Failed;
        let credit = source.push(sample);
        if source.credited && !was_failed && source.verdict == Verdict::Failed {
            // A continuous-test failure invalidates the entire not-yet-spent
            // assessment, not only this sample's contribution.
            self.discard_credit();
        }
        self.stats[id.index()].push(sample);
        self.tap.push(id, sample);
        // Domain-separate samples by source. This avoids making two different
        // source/interleaving histories hash as the same byte string.
        sink.absorb(&[0xA5, id as u8, sample]);
        let accepted = self.budget.add(credit);
        self.pooled[id.index()] += accepted;
    }

    /// Restart every running total, sources and output. Health state and the
    /// release budget are untouched: this only concerns measurement.
    pub fn reset_measurements(&mut self) {
        for s in self.stats.iter_mut() {
            s.reset_total();
        }
        self.output.reset();
        self.funded = [0; SOURCE_COUNT];
    }

    /// Number of credited sources currently in a passing state.
    pub fn live_credited(&self) -> usize {
        self.sources
            .iter()
            .filter(|s| s.credited && s.verdict.credits())
            .count()
    }

    /// Any credited source in a latched failure.
    pub fn any_failed(&self) -> bool {
        self.sources
            .iter()
            .any(|s| s.credited && s.verdict == Verdict::Failed)
    }

    /// Release gate. Key material leaves only when the budget is met AND at
    /// least `min_sources` independent credited sources are alive.
    ///
    /// The source-count floor matters: without it, one very noisy axis could
    /// fund an entire key on its own while the other five sit dead, and the
    /// budget alone would be perfectly happy about that.
    pub fn try_release<A: Absorb>(
        &mut self,
        min_sources: usize,
        sink: &mut A,
        out: &mut [u8],
    ) -> bool {
        // Nothing leaves while raw samples are being printed.
        if self.tap.source.is_some() {
            return false;
        }
        if self.live_credited() < min_sources {
            return false;
        }
        let accrued = self.budget.accrued;
        let target = self.budget.target;
        if !self.budget.consume() {
            return false;
        }
        // A zero target costs nothing and has nobody to charge.
        if target > 0 {
            self.charge(accrued, target);
        }
        sink.squeeze(out);
        self.output.push(out);
        true
    }

    /// Record who paid for the block just released.
    fn charge(&mut self, accrued: u32, target: u32) {
        // Charge the block to the sources in proportion to what each has in
        // the pool, so every release is paid for by exactly `target` units.
        // What is left carries into the next block, as the budget's does.
        let mut spent = [0u32; SOURCE_COUNT];
        let mut charged = 0u32;
        for (s, &p) in spent.iter_mut().zip(self.pooled.iter()) {
            *s = (p as u64 * target as u64 / accrued as u64) as u32;
            charged += *s;
        }
        // Rounding down leaves at most one unit per source uncharged. Hand it
        // out starting at a different source each release so no one source
        // is consistently billed the odd units.
        let mut rest = target - charged;
        let start = self.budget.releases as usize % SOURCE_COUNT;
        for k in 0..SOURCE_COUNT {
            let i = (start + k) % SOURCE_COUNT;
            let take = rest.min(self.pooled[i] - spent[i]);
            spent[i] += take;
            rest -= take;
        }
        for i in 0..SOURCE_COUNT {
            self.pooled[i] -= spent[i];
            self.funded[i] = self.funded[i].saturating_add(spent[i] as u64);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn markov_rejects_constant_and_alternating_streams() {
        let mut constant = Markov::new(4096, 32);
        let mut constant_failed = false;
        for _ in 0..512 {
            constant_failed |= constant.push(0x00);
        }
        assert!(constant_failed);
        assert_eq!(constant.last_h_q8, 0);

        let mut alternating = Markov::new(4096, 32);
        let mut alternating_failed = false;
        for _ in 0..512 {
            alternating_failed |= alternating.push(0x55);
        }
        assert!(alternating_failed);
        assert!(alternating.last_h_q8 < 32);
    }

    #[test]
    fn markov_accepts_balanced_pseudorandom_stream() {
        let mut markov = Markov::new(4096, 64);
        let mut x = 0x1234_5678u32;
        let mut failed = false;
        for _ in 0..512 {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            failed |= markov.push(x as u8);
        }
        assert!(!failed);
        assert!(markov.last_h_q8 > 200);
    }

    #[test]
    fn source_failure_is_latched_and_resettable() {
        let mut source = SourceHealth::new(SourceId::AccelX, h_fixed(0, 128), true).with_warmup(1);
        for _ in 0..64 {
            source.push(7);
        }
        assert_eq!(source.verdict, Verdict::Failed);
        source.reset();
        assert_eq!(source.verdict, Verdict::Warming);
        assert_eq!(source.rct.failures, 0);
        assert_eq!(source.markov.failures, 0);
    }

    fn reference(hist: &[u16; 256], n: u32) -> (f64, f64) {
        let n = n as f64;
        let mut shannon = 0.0;
        let mut max = 0.0f64;
        for &c in hist.iter() {
            if c > 0 {
                let p = c as f64 / n;
                shannon -= p * p.log2();
                max = max.max(c as f64);
            }
        }
        let p = max / n;
        let pu = (p + 2.576 * (p * (1.0 - p) / (n - 1.0)).sqrt()).min(1.0);
        (shannon, -pu.log2())
    }

    fn fill(mut f: impl FnMut(u32) -> u8, n: u16) -> [u16; 256] {
        let mut h = [0u16; 256];
        for i in 0..n as u32 {
            h[f(i) as usize] += 1;
        }
        h
    }

    #[test]
    fn estimates_match_a_floating_point_reference() {
        let mut x = 0x9E37_79B9u32;
        let cases: [[u16; 256]; 5] = [
            fill(|_| { x ^= x << 13; x ^= x >> 17; x ^= x << 5; x as u8 }, 4096),
            fill(|i| (i % 2) as u8, 4096),
            fill(|i| (i % 16) as u8, 4096),
            fill(|i| if i % 10 == 0 { 1 } else { 0 }, 4096),
            fill(|i| (i as u8) & 0x3F | if i % 3 == 0 { 0x40 } else { 0 }, 4096),
        ];
        for h in cases.iter() {
            let e = estimate(h, 4096u32);
            let (sh, mn) = reference(h, 4096);
            let (esh, emn) = (e.shannon_q8 as f64 / 256.0, e.min_q8 as f64 / 256.0);
            assert!((esh - sh).abs() < 0.02, "shannon {esh} vs {sh}");
            assert!((emn - mn).abs() < 0.02, "min {emn} vs {mn}");
            assert!(e.min_q8 <= e.shannon_q8 + 1, "min-entropy above Shannon");
        }
        // A constant source has no entropy by either measure.
        let e = estimate(&fill(|_| 42, 4096), 4096u32);
        assert_eq!((e.shannon_q8, e.min_q8, e.distinct), (0, 0, 1));
    }

    #[test]
    fn running_total_converges_on_a_perfect_source() {
        // A good generator should read about 7.88 min-entropy after roughly a
        // million samples, where one 4096-sample window can never exceed ~6.6.
        let mut s = Stats::new(4096);
        let mut x = 0x2545_F491u32;
        for _ in 0..(256 * 4096) {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            s.push((x >> 24) as u8);
        }
        let window = s.last.unwrap();
        let total = s.total.unwrap();
        assert_eq!(total.n, 256 * 4096);
        assert!(window.min_q8 < 7 * 256, "window {}", window.min_q8);
        assert!(total.min_q8 >= (7.8 * 256.0) as u16, "total {}", total.min_q8);
        assert!(total.shannon_q8 >= (7.99 * 256.0) as u16, "shannon {}", total.shannon_q8);
        s.reset_total();
        assert!(s.total.is_none());
    }

    #[test]
    fn credit_follows_the_assessment_and_never_reaches_steerable_sources() {
        assert!(SourceHealth::new(SourceId::HwRng, 128, true).credited);
        assert!(!SourceHealth::new(SourceId::AdcNoise, 0, true).credited);
        assert!(SourceHealth::new(SourceId::AdcNoise, 256, true).credited);
        assert!(!SourceHealth::new(SourceId::NetworkTiming, 2048, true).credited);
        assert!(!SourceHealth::new(SourceId::WifiRssi, 2048, true).credited);
        let h = Harvester::new(256);
        assert!(h.sources[SourceId::HwRng.index()].credited);
        assert!(!h.sources[SourceId::AdcNoise.index()].credited);
        assert!(h.sources[SourceId::AccelX.index()].credited);
    }

    #[test]
    fn hardware_rng_alone_releases_when_the_floor_allows_it() {
        // No MPU at all: only hw_rng (and uncredited sources) produce samples.
        let mut h = Harvester::new(256);
        let mut sink = Counting(0);
        let mut x = 0x1234_5678u32;
        let mut out = [0u8; 32];
        for _ in 0..8192 {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            h.push(SourceId::HwRng, x as u8, &mut sink);
            h.push(SourceId::AdcNoise, (x >> 8) as u8, &mut sink);
        }
        assert_eq!(h.live_credited(), 1);
        // Only the credited source put anything in the pool: 0.5 bit per
        // sample for every sample after warm-up.
        let hw = SourceId::HwRng.index();
        assert!((8192 - DEFAULT_WARMUP + 1) * 128 > 512 * H_UNIT as u64);
        // Far more was offered than the conditioner can hold: the pool stops
        // at two releases' worth.
        let pooled = 512 * H_UNIT;
        assert_eq!(h.pooled[SourceId::AdcNoise.index()], 0);
        assert_eq!(h.pooled[hw], pooled);
        assert_eq!(h.pooled.iter().sum::<u32>(), h.budget.accrued);
        assert!(!h.try_release(4, &mut sink, &mut out), "default floor needs the MPU");
        assert_eq!(h.funded[hw], 0, "no release, nothing funded");
        assert!(h.try_release(1, &mut sink, &mut out), "floor of 1 releases from hw_rng");
        assert_eq!(h.output.bytes, 32);
        // The block cost exactly 256 bits, all of it paid by hw_rng, and the
        // remainder is still in the pool.
        assert_eq!(h.funded[hw], 256 * H_UNIT as u64);
        assert_eq!(h.pooled[hw], pooled - 256 * H_UNIT);
        assert_eq!(h.pooled.iter().sum::<u32>(), h.budget.accrued);
        h.discard_credit();
        assert_eq!(h.pooled[hw], 0);
        assert_eq!(h.budget.accrued, 0);
        assert_eq!(h.funded[hw], 256 * H_UNIT as u64, "spent credit stays spent");
        h.reset_measurements();
        assert_eq!(h.funded[hw], 0);
    }

    #[test]
    fn a_release_is_charged_to_sources_in_proportion() {
        let mut h = Harvester::new(256);
        let mut sink = Counting(0);
        let mut out = [0u8; 32];
        // Three quarters of the pool from one source, one quarter from another.
        h.pooled[SourceId::AccelX.index()] = 3 * 128 * H_UNIT;
        h.pooled[SourceId::HwRng.index()] = 128 * H_UNIT;
        h.budget.add(512 * H_UNIT);
        for s in h.sources.iter_mut() {
            s.verdict = Verdict::Healthy;
        }
        assert!(h.try_release(1, &mut sink, &mut out));
        assert_eq!(h.funded[SourceId::AccelX.index()], 192 * H_UNIT as u64);
        assert_eq!(h.funded[SourceId::HwRng.index()], 64 * H_UNIT as u64);
        assert_eq!(h.pooled.iter().sum::<u32>(), h.budget.accrued);
    }

    #[test]
    fn stats_publish_one_estimate_per_window() {
        let mut s = Stats::new(256);
        for i in 0..255u32 {
            s.push(i as u8);
        }
        assert!(s.last.is_none());
        assert_eq!(s.progress(), 255);
        s.push(255);
        let e = s.last.expect("window complete");
        assert_eq!((e.n, e.distinct, e.shannon_q8), (256, 256, 8 * 256));
        assert_eq!(s.progress(), 0);
    }

    struct Counting(u8);
    impl Absorb for Counting {
        fn absorb(&mut self, _: &[u8]) {}
        fn squeeze(&mut self, out: &mut [u8]) {
            for b in out.iter_mut() {
                self.0 = self.0.wrapping_add(1);
                *b = self.0;
            }
        }
    }

    #[test]
    fn open_tap_blocks_release_and_output_is_measured() {
        let mut h = Harvester::new(8);
        for s in h.sources.iter_mut() {
            *s = SourceHealth::new(s.id, s.h, s.credited).with_warmup(0);
        }
        let mut sink = Counting(0);
        let mut x = 7u32;
        for _ in 0..200 {
            for id in [SourceId::AccelX, SourceId::AccelY, SourceId::AccelZ, SourceId::GyroX] {
                x = x.wrapping_mul(1_103_515_245).wrapping_add(12_345);
                h.push(id, (x >> 16) as u8, &mut sink);
            }
        }
        let mut out = [0u8; 32];
        h.tap.source = Some(SourceId::AccelX);
        assert!(!h.try_release(4, &mut sink, &mut out), "released with the tap open");
        h.tap.source = None;
        assert!(h.try_release(4, &mut sink, &mut out));
        assert_eq!(h.output.bytes, 32);
    }

    #[test]
    fn tap_copies_only_its_source_and_counts_overflow() {
        let mut t = Tap::new();
        t.source = Some(SourceId::GyroZ);
        t.push(SourceId::GyroY, 1);
        for i in 0..(TAP_LEN as u8 + 3) {
            t.push(SourceId::GyroZ, i);
        }
        assert_eq!(t.len, TAP_LEN);
        assert_eq!(t.buf[0], 0);
        assert_eq!(t.overflow, 3);
    }
}
