// ============================================================================
//  persist.rs - settings that survive a power cycle
//  Jupiter Labs / CHIRASU Network
//
//  Pure `core` code, host-testable. The flash reads and writes themselves live
//  in main.rs; everything that decides WHAT is written and WHICH copy to trust
//  lives here.
//
//  POWER-LOSS SAFETY
//
//  This node runs on a battery inside a guitar. A save can be interrupted by a
//  dead cell, a yanked cable or a dropped instrument, and an interrupted
//  flash erase leaves that sector as garbage. So there are two slots, A and B,
//  one flash sector each:
//
//    - every record carries a sequence number and a CRC32
//    - a save always writes the slot NOT holding the newest valid record
//    - on boot, the valid record with the highest sequence number wins
//
//  If power dies mid-write, the slot being written fails its CRC and the other
//  slot still holds the previous good settings. The worst case is losing the
//  most recent change, never losing everything.
//
//  WHAT IS NOT HERE: released key material. Nothing conditioned ever touches
//  flash. The admin password is stored only as a salted SHA3-256 digest, and
//  the hashing happens device-side because sha3 is not a host dependency.
// ============================================================================

#![allow(dead_code)]

use crate::entropy::SOURCE_COUNT;
use crate::net::{Ipv4, TargetPin, WifiCredentials};

// ---------------------------------------------------------------------------
// Record layout
// ---------------------------------------------------------------------------
//
//   0   [4]  magic  "NOCT"
//   4   u16  version
//   6   u16  payload length
//   8   u32  sequence
//   12  ...  payload
//   ..  u32  CRC32 over every byte above it
//
// All integers little-endian. The record is padded to RECORD_LEN so the flash
// write is word-aligned, which the ESP ROM flash routines require.

pub const MAGIC: [u8; 4] = *b"NOCT";
/// Layout 2 added the ADC noise source (16 assessments instead of 15).
/// Layout 3 added the minimum number of live credited sources.
/// Layout 4 added the rotation trigger, and `mot_thr` went from 32 mg steps to
/// 8 mg steps (older values are multiplied by four on read, so the physical
/// threshold does not change).
/// Every older layout is still read, so an upgrade keeps every setting.
pub const VERSION: u16 = 4;
pub const HEADER_LEN: usize = 12;
pub const PAYLOAD_LEN: usize = payload_len(VERSION);
pub const RECORD_LEN: usize = 256;

/// Assessments stored by each layout this firmware can read.
const fn assessments_in(version: u16) -> Option<usize> {
    match version {
        1 => Some(15),
        2..=4 => Some(16),
        _ => None,
    }
}

/// Whether the layout carries the min_live byte (after the assessments).
const fn has_min_live(version: u16) -> bool {
    version >= 3
}

/// Whether the layout carries the rotation trigger (after min_live), and
/// stores `mot_thr` in 8 mg steps rather than 32 mg steps.
const fn has_gyro_thr(version: u16) -> bool {
    version >= 4
}

/// Everything but the assessments, min_live and gyro_thr is fixed at 165
/// bytes.
const fn payload_len(version: u16) -> usize {
    let assessments = match assessments_in(version) {
        Some(n) => n,
        None => 0,
    };
    165 + 2 * assessments
        + if has_min_live(version) { 1 } else { 0 }
        + if has_gyro_thr(version) { 1 } else { 0 }
}

const _: () = assert!(payload_len(1) == 195);
const _: () = assert!(payload_len(2) == 197);
const _: () = assert!(payload_len(3) == 198);
const _: () = assert!(payload_len(4) == 199);

/// Default for the release floor: independent credited sources that must be
/// live before a block is released.
pub const DEFAULT_MIN_LIVE: u8 = 4;

/// One flash sector per slot.
pub const SLOT_SIZE: u32 = 4096;
pub const SLOT_COUNT: usize = 2;

const _: () = assert!(HEADER_LEN + PAYLOAD_LEN + 4 <= RECORD_LEN);
const _: () = assert!(RECORD_LEN % 4 == 0);

// ---------------------------------------------------------------------------
// Settings
// ---------------------------------------------------------------------------

#[derive(Copy, Clone, PartialEq, Eq)]
pub struct Settings {
    pub wifi: WifiCredentials,
    pub strum_pin: TargetPin,
    pub entropy_pin: TargetPin,
    pub strum_port: u16,
    pub entropy_port: u16,
    pub udp_enabled: bool,
    /// Whether the unauthenticated UDP control port accepts commands at all.
    pub udp_control: bool,
    pub debounce_ms: u16,
    /// Acceleration trigger, 8 mg steps (1 to 255).
    pub mot_thr: u8,
    pub accel_hpf: u8,
    /// Rotation trigger, degrees per second. 0 is off.
    pub gyro_thr: u8,
    /// Credited sources that must be live for a release (1 to SOURCE_COUNT).
    pub min_live: u8,
    /// Assessed min-entropy per source, 1/256-bit units. These are the Phase 0
    /// results, and losing them on a reboot is the single most expensive thing
    /// this module prevents.
    pub h: [u16; SOURCE_COUNT],
    pub admin_salt: [u8; 16],
    /// SHA3-256 of the admin password. All zeroes means "use the compiled
    /// default", which the dashboard flags loudly.
    pub admin_hash: [u8; 32],
}

impl Settings {
    pub fn admin_is_default(&self) -> bool {
        self.admin_hash.iter().all(|b| *b == 0)
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum DecodeError {
    TooShort,
    BadMagic,
    /// A record written by a different firmware layout. Ignored rather than
    /// guessed at, so an upgrade can never misread old bytes as new fields.
    BadVersion(u16),
    BadLength,
    BadCrc,
    /// CRC-valid but semantically impossible. Only reachable across a
    /// firmware change, since every write is validated first.
    BadField(&'static str),
    /// Erased flash, 0xFF throughout. Distinguished so the dashboard can say
    /// "never saved" rather than "corrupt".
    Blank,
}

// ---------------------------------------------------------------------------
// CRC-32 (IEEE 802.3, reflected, poly 0xEDB88320)
// ---------------------------------------------------------------------------

pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

struct Writer<'a> {
    buf: &'a mut [u8],
    at: usize,
}

impl<'a> Writer<'a> {
    fn u8(&mut self, v: u8) {
        self.buf[self.at] = v;
        self.at += 1;
    }
    fn u16(&mut self, v: u16) {
        self.buf[self.at..self.at + 2].copy_from_slice(&v.to_le_bytes());
        self.at += 2;
    }
    fn u32(&mut self, v: u32) {
        self.buf[self.at..self.at + 4].copy_from_slice(&v.to_le_bytes());
        self.at += 4;
    }
    fn bytes(&mut self, v: &[u8]) {
        self.buf[self.at..self.at + v.len()].copy_from_slice(v);
        self.at += v.len();
    }
    fn fixed(&mut self, v: &[u8], width: usize) {
        let n = v.len().min(width);
        self.buf[self.at..self.at + n].copy_from_slice(&v[..n]);
        for b in &mut self.buf[self.at + n..self.at + width] {
            *b = 0;
        }
        self.at += width;
    }
    fn pin(&mut self, p: TargetPin) {
        match p {
            TargetPin::Auto => {
                self.u8(0);
                self.bytes(&[0; 4]);
            }
            TargetPin::Pinned(ip) => {
                self.u8(1);
                self.bytes(&ip.0);
            }
        }
    }
}

struct Reader<'a> {
    buf: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn u8(&mut self) -> u8 {
        let v = self.buf[self.at];
        self.at += 1;
        v
    }
    fn u16(&mut self) -> u16 {
        let v = u16::from_le_bytes([self.buf[self.at], self.buf[self.at + 1]]);
        self.at += 2;
        v
    }
    fn u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        b.copy_from_slice(&self.buf[self.at..self.at + 4]);
        self.at += 4;
        u32::from_le_bytes(b)
    }
    fn take(&mut self, n: usize) -> &'a [u8] {
        let v = &self.buf[self.at..self.at + n];
        self.at += n;
        v
    }
    fn pin(&mut self) -> Result<TargetPin, DecodeError> {
        let tag = self.u8();
        let mut ip = [0u8; 4];
        ip.copy_from_slice(self.take(4));
        match tag {
            0 => Ok(TargetPin::Auto),
            1 => Ok(TargetPin::Pinned(Ipv4(ip))),
            _ => Err(DecodeError::BadField("target_tag")),
        }
    }
}

/// Serialize `settings` with sequence number `seq` into a full, padded record.
pub fn encode(settings: &Settings, seq: u32, out: &mut [u8; RECORD_LEN]) {
    encode_layout(settings, seq, VERSION, out);
}

/// Encode in a given layout. Only the current layout is ever written; older
/// ones exist here so the migration path can be tested.
fn encode_layout(settings: &Settings, seq: u32, version: u16, out: &mut [u8; RECORD_LEN]) {
    let count = assessments_in(version).unwrap_or(SOURCE_COUNT).min(SOURCE_COUNT);
    let payload = payload_len(version);
    out.fill(0xFF);
    let mut w = Writer { buf: out, at: 0 };
    w.bytes(&MAGIC);
    w.u16(version);
    w.u16(payload as u16);
    w.u32(seq);

    let ssid = settings.wifi.ssid().as_bytes();
    let pass = settings.wifi.password().as_bytes();
    w.u8(ssid.len() as u8);
    w.fixed(ssid, 32);
    w.u8(pass.len() as u8);
    w.fixed(pass, 64);
    w.pin(settings.strum_pin);
    w.pin(settings.entropy_pin);
    w.u16(settings.strum_port);
    w.u16(settings.entropy_port);
    w.u8((settings.udp_enabled as u8) | ((settings.udp_control as u8) << 1));
    w.u16(settings.debounce_ms);
    // Older layouts held the threshold in 32 mg steps. Only the tests write
    // them, to prove the migration.
    w.u8(if has_gyro_thr(version) { settings.mot_thr } else { (settings.mot_thr / 4).max(1) });
    w.u8(settings.accel_hpf);
    for h in settings.h.iter().take(count) {
        w.u16(*h);
    }
    if has_min_live(version) {
        w.u8(settings.min_live);
    }
    if has_gyro_thr(version) {
        w.u8(settings.gyro_thr);
    }
    w.bytes(&settings.admin_salt);
    w.bytes(&settings.admin_hash);

    debug_assert_eq!(w.at, HEADER_LEN + payload);
    let end = w.at;
    let crc = crc32(&out[..end]);
    out[end..end + 4].copy_from_slice(&crc.to_le_bytes());
}

/// Parse and fully validate a record. Returns the settings and the sequence
/// number, or why the record cannot be trusted.
pub fn decode(raw: &[u8]) -> Result<(Settings, u32), DecodeError> {
    if raw.len() < HEADER_LEN + 4 {
        return Err(DecodeError::TooShort);
    }
    if raw[..HEADER_LEN].iter().all(|b| *b == 0xFF) {
        return Err(DecodeError::Blank);
    }
    if raw[..4] != MAGIC {
        return Err(DecodeError::BadMagic);
    }

    let mut r = Reader { buf: raw, at: 4 };
    let version = r.u16();
    let count = assessments_in(version).ok_or(DecodeError::BadVersion(version))?;
    let payload = payload_len(version);
    if r.u16() as usize != payload {
        return Err(DecodeError::BadLength);
    }
    if raw.len() < HEADER_LEN + payload + 4 {
        return Err(DecodeError::TooShort);
    }
    let seq = r.u32();

    let end = HEADER_LEN + payload;
    let mut stored = [0u8; 4];
    stored.copy_from_slice(&raw[end..end + 4]);
    if crc32(&raw[..end]) != u32::from_le_bytes(stored) {
        return Err(DecodeError::BadCrc);
    }

    let ssid_len = r.u8() as usize;
    let ssid_raw = r.take(32);
    let pass_len = r.u8() as usize;
    let pass_raw = r.take(64);
    if ssid_len > 32 || pass_len > 64 {
        return Err(DecodeError::BadField("wifi_len"));
    }
    let ssid = core::str::from_utf8(&ssid_raw[..ssid_len])
        .map_err(|_| DecodeError::BadField("wifi_utf8"))?;
    let pass = core::str::from_utf8(&pass_raw[..pass_len])
        .map_err(|_| DecodeError::BadField("wifi_utf8"))?;
    // Re-run the same validation the control plane applies, so a stored
    // record can never smuggle in credentials the parser would refuse.
    let wifi = WifiCredentials::new(ssid, pass).map_err(DecodeError::BadField)?;

    let strum_pin = r.pin()?;
    let entropy_pin = r.pin()?;
    let strum_port = r.u16();
    let entropy_port = r.u16();
    let flags = r.u8();
    let debounce_ms = r.u16();
    let mot_thr = r.u8();
    let accel_hpf = r.u8();
    // Sources added after the record was written start unassessed (0),
    // which is what the compiled defaults give every uncredited source.
    let mut h = [0u16; SOURCE_COUNT];
    for slot in h.iter_mut().take(count) {
        *slot = r.u16();
    }
    // Layouts 1 and 2 could not credit the hardware RNG or the ADC noise, so
    // whatever they stored for those two had no effect and was no decision of
    // the owner's. Both take today's defaults rather than turning an old,
    // inert number into a real claim.
    if version < 3 {
        h[crate::entropy::SourceId::HwRng.index()] = crate::entropy::h_fixed(0, 128);
        h[crate::entropy::SourceId::AdcNoise.index()] = 0;
    }
    let min_live = if has_min_live(version) { r.u8() } else { DEFAULT_MIN_LIVE };
    let gyro_thr = if has_gyro_thr(version) { r.u8() } else { crate::mpu::DEFAULT_GYRO_THR };
    // Same physical threshold in the finer units. 32 mg * 64 and above is
    // already past anything a strap can do, so the top end simply clamps.
    let mot_thr = if has_gyro_thr(version) { mot_thr } else { (mot_thr as u16 * 4).min(255) as u8 };
    let mut admin_salt = [0u8; 16];
    admin_salt.copy_from_slice(r.take(16));
    let mut admin_hash = [0u8; 32];
    admin_hash.copy_from_slice(r.take(32));

    let settings = Settings {
        wifi,
        strum_pin,
        entropy_pin,
        strum_port,
        entropy_port,
        udp_enabled: flags & 1 != 0,
        udp_control: flags & 2 != 0,
        debounce_ms,
        mot_thr,
        accel_hpf,
        gyro_thr,
        min_live,
        h,
        admin_salt,
        admin_hash,
    };
    validate(&settings).map_err(DecodeError::BadField)?;
    Ok((settings, seq))
}

/// Field-level sanity. Called before every write and after every read.
pub fn validate(s: &Settings) -> Result<(), &'static str> {
    if s.strum_port == 0 || s.entropy_port == 0 {
        return Err("port_zero");
    }
    if !data_port_allowed(s.strum_port) || !data_port_allowed(s.entropy_port) {
        return Err("port_reserved");
    }
    if s.strum_port == s.entropy_port {
        return Err("ports_equal");
    }
    if s.debounce_ms > MAX_DEBOUNCE_MS {
        return Err("debounce_range");
    }
    if s.mot_thr == 0 {
        return Err("mot_thr_zero");
    }
    if !valid_hpf(s.accel_hpf) {
        return Err("hpf_range");
    }
    if s.min_live == 0 || s.min_live as usize > SOURCE_COUNT {
        return Err("min_live_range");
    }
    // A byte cannot carry more than 8 bits of min-entropy. Accepting more from
    // flash would silently inflate the credit budget on every boot.
    if s.h.iter().any(|h| *h > 8 * 256) {
        return Err("h_range");
    }
    Ok(())
}

pub const MAX_DEBOUNCE_MS: u16 = 10_000;

/// Ports this node itself listens on. A data socket bound to one of these
/// would receive that service's packets first and silently take it over, for
/// example strum on 5013 would swallow every control command. Saved, that
/// would survive a reboot.
pub const RESERVED_PORTS: [u16; 5] = [53, 67, 68, 80, 5013];

pub fn data_port_allowed(port: u16) -> bool {
    port != 0 && !RESERVED_PORTS.contains(&port)
}

/// Motion high-pass settings: 0 off, 1 to 4 the corners 5, 2.5, 1.25 and
/// 0.63 Hz. The MPU-6050's old "hold" setting (7) is not offered: with a
/// frozen baseline any tilt reads as motion forever and floods the relay.
pub fn valid_hpf(v: u8) -> bool {
    matches!(v, 0..=4)
}

// ---------------------------------------------------------------------------
// Slot selection
// ---------------------------------------------------------------------------

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Loaded {
    /// A valid record was found in `slot`.
    Found { slot: usize, seq: u32 },
    /// Both slots blank: this node has never saved.
    Blank,
    /// Something is in flash but nothing validates.
    Corrupt,
}

/// Choose which of the two decoded slots to trust.
///
/// Highest sequence number among the VALID records wins. An invalid slot is
/// never preferred over a valid one regardless of what its header claims.
pub fn choose(results: [Result<u32, DecodeError>; SLOT_COUNT]) -> Loaded {
    let mut best: Option<(usize, u32)> = None;
    for (slot, r) in results.iter().enumerate() {
        if let Ok(seq) = r {
            match best {
                Some((_, b)) if b >= *seq => {}
                _ => best = Some((slot, *seq)),
            }
        }
    }
    match best {
        Some((slot, seq)) => Loaded::Found { slot, seq },
        None if results.iter().all(|r| matches!(r, Err(DecodeError::Blank))) => Loaded::Blank,
        None => Loaded::Corrupt,
    }
}

/// Where the next save goes and what sequence number it carries.
///
/// Always the slot that is NOT currently holding the newest valid record, so
/// the last good copy survives until the new one is completely written.
pub fn next_write(current: Loaded) -> (usize, u32) {
    match current {
        Loaded::Found { slot, seq } => ((slot + 1) % SLOT_COUNT, seq.wrapping_add(1)),
        Loaded::Blank | Loaded::Corrupt => (0, 1),
    }
}

// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entropy::h_fixed;

    fn sample() -> Settings {
        Settings {
            wifi: WifiCredentials::new("My Phone Hotspot", "correct horse battery").unwrap(),
            strum_pin: TargetPin::Auto,
            entropy_pin: TargetPin::Pinned(Ipv4([10, 153, 103, 30])),
            strum_port: 5008,
            entropy_port: 5059,
            udp_enabled: true,
            udp_control: false,
            debounce_ms: 60,
            mot_thr: 8,
            accel_hpf: 4,
            gyro_thr: 12,
            min_live: 3,
            h: [h_fixed(0, 128); SOURCE_COUNT],
            admin_salt: [7; 16],
            admin_hash: [9; 32],
        }
    }

    #[test]
    fn crc32_matches_the_standard_check_value() {
        // The canonical CRC-32 check value for the ASCII string "123456789".
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32(b""), 0);
    }

    #[test]
    fn round_trip_preserves_every_field() {
        let mut s = sample();
        s.h[0] = h_fixed(3, 128);
        s.h[7] = h_fixed(6, 0);
        let mut rec = [0u8; RECORD_LEN];
        encode(&s, 42, &mut rec);
        let (back, seq) = decode(&rec).expect("valid record");
        assert_eq!(seq, 42);
        assert!(back == s, "decoded settings differ from what was written");
        assert_eq!(back.wifi.ssid(), "My Phone Hotspot");
        assert_eq!(back.wifi.password(), "correct horse battery");
        assert!(!back.udp_control && back.udp_enabled);
    }

    #[test]
    fn any_single_bit_flip_is_rejected() {
        let mut rec = [0u8; RECORD_LEN];
        encode(&sample(), 7, &mut rec);
        let covered = HEADER_LEN + PAYLOAD_LEN + 4;
        for byte in 0..covered {
            for bit in 0..8 {
                let mut bad = rec;
                bad[byte] ^= 1 << bit;
                assert!(
                    decode(&bad).is_err(),
                    "flip at byte {byte} bit {bit} was accepted"
                );
            }
        }
    }

    #[test]
    fn erased_flash_reads_as_blank_not_corrupt() {
        assert_eq!(decode(&[0xFF; RECORD_LEN]).err(), Some(DecodeError::Blank));
        assert_eq!(
            choose([Err(DecodeError::Blank), Err(DecodeError::Blank)]),
            Loaded::Blank
        );
    }

    #[test]
    fn other_firmware_versions_are_ignored_not_misread() {
        let mut rec = [0u8; RECORD_LEN];
        encode(&sample(), 1, &mut rec);
        rec[4] = 99; // a layout this firmware does not know
        assert_eq!(decode(&rec).err(), Some(DecodeError::BadVersion(99)));
    }

    #[test]
    fn newest_valid_slot_wins_and_invalid_never_does() {
        assert_eq!(choose([Ok(4), Ok(5)]), Loaded::Found { slot: 1, seq: 5 });
        assert_eq!(choose([Ok(9), Ok(5)]), Loaded::Found { slot: 0, seq: 9 });
        // A torn write in slot 1 must not beat the good copy in slot 0.
        assert_eq!(
            choose([Ok(3), Err(DecodeError::BadCrc)]),
            Loaded::Found { slot: 0, seq: 3 }
        );
        assert_eq!(
            choose([Err(DecodeError::BadCrc), Err(DecodeError::Blank)]),
            Loaded::Corrupt
        );
    }

    #[test]
    fn saves_alternate_slots_so_the_last_good_copy_survives() {
        let mut current = Loaded::Blank;
        let mut slots_written = [0u32; SLOT_COUNT];
        for _ in 0..6 {
            let (slot, seq) = next_write(current);
            if let Loaded::Found { slot: live, .. } = current {
                assert_ne!(slot, live, "a save overwrote the live copy");
            }
            slots_written[slot] += 1;
            current = Loaded::Found { slot, seq };
        }
        assert_eq!(slots_written, [3, 3]);
        assert_eq!(current, Loaded::Found { slot: 1, seq: 6 });
    }

    #[test]
    fn simulated_power_loss_mid_save_keeps_previous_settings() {
        let mut flash = [[0xFFu8; RECORD_LEN]; SLOT_COUNT];
        let mut first = sample();
        first.debounce_ms = 60;
        encode(&first, 1, &mut flash[0]);

        // Second save targets slot 1, but the cell dies half way through.
        let (slot, seq) = next_write(choose([
            decode(&flash[0]).map(|x| x.1),
            decode(&flash[1]).map(|x| x.1),
        ]));
        assert_eq!(slot, 1);
        let mut second = sample();
        second.debounce_ms = 200;
        let mut rec = [0u8; RECORD_LEN];
        encode(&second, seq, &mut rec);
        flash[1][..RECORD_LEN / 2].copy_from_slice(&rec[..RECORD_LEN / 2]);

        let pick = choose([
            decode(&flash[0]).map(|x| x.1),
            decode(&flash[1]).map(|x| x.1),
        ]);
        assert_eq!(pick, Loaded::Found { slot: 0, seq: 1 });
        let (kept, _) = decode(&flash[0]).unwrap();
        assert_eq!(kept.debounce_ms, 60);
    }

    #[test]
    fn impossible_values_are_refused_on_both_sides() {
        let mut s = sample();
        s.h[3] = 8 * 256 + 1;
        assert_eq!(validate(&s), Err("h_range"));
        let mut s = sample();
        s.accel_hpf = 5;
        assert_eq!(validate(&s), Err("hpf_range"));
        let mut s = sample();
        s.strum_port = 0;
        assert_eq!(validate(&s), Err("port_zero"));
        let mut s = sample();
        s.strum_port = 5013;
        assert_eq!(validate(&s), Err("port_reserved"));
        let mut s = sample();
        s.entropy_port = 80;
        assert_eq!(validate(&s), Err("port_reserved"));
        let mut s = sample();
        s.entropy_port = s.strum_port;
        assert_eq!(validate(&s), Err("ports_equal"));
        let mut s = sample();
        s.mot_thr = 0;
        assert_eq!(validate(&s), Err("mot_thr_zero"));
        let mut s = sample();
        s.min_live = 0;
        assert_eq!(validate(&s), Err("min_live_range"));
        let mut s = sample();
        s.min_live = SOURCE_COUNT as u8 + 1;
        assert_eq!(validate(&s), Err("min_live_range"));
    }

    #[test]
    fn layout_1_records_are_migrated_not_lost() {
        let s = sample();
        let mut rec = [0u8; RECORD_LEN];
        encode_layout(&s, 41, 1, &mut rec);
        let (got, seq) = decode(&rec).expect("layout 1 still reads");
        assert_eq!(seq, 41);
        assert!(got.wifi == s.wifi && got.strum_port == s.strum_port && got.admin_hash == s.admin_hash);
        let rng = crate::entropy::SourceId::HwRng.index();
        for i in 0..15 {
            if i != rng {
                assert_eq!(got.h[i], s.h[i]);
            }
        }
        assert_eq!(got.h[rng], h_fixed(0, 128), "hw_rng takes today's default");
        assert_eq!(got.h[15], 0, "new source starts unassessed");
        assert_eq!(got.min_live, DEFAULT_MIN_LIVE, "layouts before 3 get the default floor");
        assert_eq!(got.mot_thr, s.mot_thr, "32 mg steps become the same threshold in 8 mg steps");
        assert_eq!(got.gyro_thr, crate::mpu::DEFAULT_GYRO_THR, "layouts before 4 get the default rotation trigger");

        // A layout 2 record may hold inert values for hw_rng and adc_noise
        // (they could not be credited then). Neither becomes a real claim.
        let mut old = s;
        old.h[crate::entropy::SourceId::HwRng.index()] = 8 * 256;
        old.h[crate::entropy::SourceId::AdcNoise.index()] = 8 * 256;
        let mut rec2 = [0u8; RECORD_LEN];
        encode_layout(&old, 7, 2, &mut rec2);
        let (got2, _) = decode(&rec2).expect("layout 2 still reads");
        assert_eq!(got2.h[crate::entropy::SourceId::HwRng.index()], h_fixed(0, 128));
        assert_eq!(got2.h[crate::entropy::SourceId::AdcNoise.index()], 0);
        assert_eq!(got2.h[0], old.h[0]);
        // And the next save is written in the current layout.
        let mut rec = [0u8; RECORD_LEN];
        encode(&got, seq + 1, &mut rec);
        assert_eq!(u16::from_le_bytes([rec[4], rec[5]]), VERSION);
        assert_eq!(decode(&rec).unwrap().0.h, got.h);
    }

    #[test]
    fn layout_3_records_keep_the_same_motion_threshold() {
        // What a node saved before this firmware holds: mot_thr=2 in 32 mg
        // steps, which is 64 mg.
        let mut s = sample();
        s.mot_thr = 8;
        let mut rec = [0u8; RECORD_LEN];
        encode_layout(&s, 5, 3, &mut rec);
        assert_eq!(u16::from_le_bytes([rec[4], rec[5]]), 3);
        let (got, _) = decode(&rec).expect("layout 3 still reads");
        assert_eq!(got.mot_thr, 8, "64 mg either way");
        assert_eq!(got.gyro_thr, crate::mpu::DEFAULT_GYRO_THR);
        assert_eq!(got.min_live, s.min_live);
        assert_eq!(got.h, s.h);
        assert!(got.admin_hash == s.admin_hash && got.wifi == s.wifi);
    }

    #[test]
    fn default_admin_is_detectable() {
        let mut s = sample();
        assert!(!s.admin_is_default());
        s.admin_hash = [0; 32];
        assert!(s.admin_is_default());
    }
}
