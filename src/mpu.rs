// ============================================================================
//  mpu.rs - MPU-6050 driver, configured for noise rather than for accuracy
//  Jupiter Labs / CHIRASU Network
//
//  Board-independent. The driver is generic over a minimal async I2C trait
//  declared here, so the same code runs on an ESP32-S3 or an ESP32-C6 and the
//  pure logic (register encoding, frame parsing, sample extraction) is
//  host-testable with a mock bus and no HAL in sight.
//
//  EVERY TUTORIAL CONFIGURES THIS PART BACKWARDS FOR OUR PURPOSE.
//  The usual advice is: enable the DLPF, clock from the gyro PLL, pick a
//  comfortable full scale. All three of those suppress exactly what we are
//  trying to harvest. Here:
//
//    DLPF OFF       - the digital low-pass filter is an averaging filter, and
//                     averaging is the enemy of an LSB noise floor.
//    +/-2g, +/-250dps - most sensitive scale, so one LSB is the smallest
//                     physical quantity, so thermal noise spans the most bits.
//    INTERNAL RC    - the 8 MHz RC oscillator drifts badly against the MCU's
//                     crystal. That drift is a SECOND, independent source:
//                     timestamp the data-ready edge and you are measuring a
//                     beat between two unrelated oscillators.
// ============================================================================

#![allow(dead_code)]

// ---------------------------------------------------------------------------
// Minimal async I2C bus
// ---------------------------------------------------------------------------
//
// Declared locally so this file has zero dependencies. In firmware, implement
// it for the HAL's I2C in one short impl block; in the harness, implement it
// for a register-file mock.

pub trait I2cBus {
    type Error;
    fn write(
        &mut self,
        addr: u8,
        bytes: &[u8],
    ) -> impl core::future::Future<Output = Result<(), Self::Error>>;
    fn write_read(
        &mut self,
        addr: u8,
        write: &[u8],
        read: &mut [u8],
    ) -> impl core::future::Future<Output = Result<(), Self::Error>>;
}

// ---------------------------------------------------------------------------
// Addresses and registers
// ---------------------------------------------------------------------------

/// AD0 low. Tie AD0 high for 0x69 if you ever put two on one bus.
pub const ADDR_AD0_LOW: u8 = 0x68;
pub const ADDR_AD0_HIGH: u8 = 0x69;

pub mod reg {
    pub const SMPLRT_DIV: u8 = 0x19;
    pub const CONFIG: u8 = 0x1A;
    pub const GYRO_CONFIG: u8 = 0x1B;
    pub const ACCEL_CONFIG: u8 = 0x1C;
    /// MPU-6500 family only: accelerometer low-pass. Does not exist on a
    /// genuine MPU-6050 and is never touched there.
    pub const ACCEL_CONFIG2: u8 = 0x1D;
    pub const FIFO_EN: u8 = 0x23;
    pub const INT_PIN_CFG: u8 = 0x37;
    pub const INT_ENABLE: u8 = 0x38;
    pub const INT_STATUS: u8 = 0x3A;
    pub const ACCEL_XOUT_H: u8 = 0x3B;
    pub const TEMP_OUT_H: u8 = 0x41;
    pub const GYRO_XOUT_H: u8 = 0x43;
    pub const SIGNAL_PATH_RESET: u8 = 0x68;
    pub const USER_CTRL: u8 = 0x6A;
    pub const PWR_MGMT_1: u8 = 0x6B;
    pub const PWR_MGMT_2: u8 = 0x6C;
    pub const FIFO_COUNT_H: u8 = 0x72;
    pub const FIFO_R_W: u8 = 0x74;
    pub const WHO_AM_I: u8 = 0x75;
}

/// A genuine MPU-6050 reports 0x68 here. WHO_AM_I returns bits 6:1 of the I2C
/// address, so it reads 0x68 whichever way AD0 is strapped.
pub const WHO_AM_I_MPU6050: u8 = 0x68;

/// Which die is actually on the GY-521.
///
/// GY-521 boards are a lottery: many ship an MPU-6500-family die instead of an
/// MPU-6050. For everything this driver uses (power, clock, gyro and accel
/// range, sample-rate divider, data-ready interrupt, the 14-byte data burst)
/// the register map is the same. The one difference that matters is the
/// sample rate: on the 6500 family the divider is ignored with the gyro filter
/// fully off, so that family runs its widest divided filter setting instead.
/// See `configure`.
///
/// Motion detection does not use the chip's own motion registers at all (they
/// are undocumented in the current MPU-6050 register map and differ on every
/// clone), so both families detect motion identically. See `MotionDetector`.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Chip {
    Mpu6050,
    /// MPU-6500, MPU-9250/9255, ICM-206xx and the common clone IDs.
    Mpu6500Family(u8),
}

impl Chip {
    pub fn identify(who_am_i: u8) -> Option<Chip> {
        match who_am_i {
            WHO_AM_I_MPU6050 => Some(Chip::Mpu6050),
            // 0x70 MPU-6500, 0x71 MPU-9250, 0x72 and 0x74 clone/6515 dies,
            // 0x73 MPU-9255, 0x98 ICM-20689 and clones, 0x12 ICM-20602,
            // 0x19 MPU-6886.
            0x70 | 0x71 | 0x72 | 0x73 | 0x74 | 0x98 | 0x12 | 0x19 => {
                Some(Chip::Mpu6500Family(who_am_i))
            }
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Chip::Mpu6050 => "MPU-6050",
            Chip::Mpu6500Family(0x70) => "MPU-6500",
            Chip::Mpu6500Family(0x71) => "MPU-9250",
            Chip::Mpu6500Family(0x73) => "MPU-9255",
            Chip::Mpu6500Family(0x98) => "ICM-20689",
            Chip::Mpu6500Family(0x12) => "ICM-20602",
            Chip::Mpu6500Family(0x19) => "MPU-6886",
            Chip::Mpu6500Family(_) => "MPU-6500 clone",
        }
    }
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum AccelRange {
    G2 = 0,
    G4 = 1,
    G8 = 2,
    G16 = 3,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum GyroRange {
    Dps250 = 0,
    Dps500 = 1,
    Dps1000 = 2,
    Dps2000 = 3,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum ClockSource {
    /// Internal 8 MHz RC. Noisy and drifty against the MCU crystal, which is
    /// precisely why it is the default here.
    InternalRc = 0,
    PllGyroX = 1,
    PllGyroY = 2,
    PllGyroZ = 3,
}

#[derive(Copy, Clone, Debug)]
pub struct Config {
    pub accel: AccelRange,
    pub gyro: GyroRange,
    pub clock: ClockSource,
    /// DLPF_CFG. 0 disables the filter and puts the gyro output rate at 8 kHz.
    /// Leave it at 0. Any other value averages away the noise floor.
    pub dlpf: u8,
    /// SMPLRT_DIV. Sample rate = gyro_rate / (1 + SMPLRT_DIV).
    pub smplrt_div: u8,
    /// High-pass corner of the firmware motion detector (`MotionDetector`),
    /// using the same numbering the MPU-6050's own filter used:
    ///
    ///   0 = off (no motion events)
    ///   1 = 5 Hz      2 = 2.5 Hz     3 = 1.25 Hz
    ///   4 = 0.63 Hz
    ///
    /// 0.63 Hz is the default on purpose. A 5 Hz corner passes strum
    /// transients and attenuates the slower whole-body movement (leaning,
    /// walking, headbangs carried through the strap) that this node exists to
    /// capture. 0.63 Hz strips gravity and keeps the rest.
    ///
    /// Nothing here touches the raw samples that feed the entropy sources.
    pub accel_hpf: u8,
    /// Acceleration trigger, in 8 mg steps against the smoothed, high-passed
    /// signal (`MOTION_MG_PER_STEP`).
    pub mot_thr: u8,
    /// Rotation trigger, in whole degrees per second against the smoothed,
    /// bias-removed gyro. 0 turns the rotation trigger off.
    pub gyro_thr: u8,
}

/// Default rotation trigger, degrees per second. Also what a settings record
/// written before the rotation trigger existed gets.
pub const DEFAULT_GYRO_THR: u8 = 8;

impl Default for Config {
    /// The harvest configuration: filter off, most sensitive scale, internal
    /// RC clock, 1 kHz sampling.
    fn default() -> Self {
        Config {
            accel: AccelRange::G2,
            gyro: GyroRange::Dps250,
            clock: ClockSource::InternalRc,
            dlpf: 0,
            // With DLPF off the gyro output rate is 8 kHz, so a divider of 7
            // yields 1 kHz.
            //
            // DO NOT RAISE THIS RATE WITHOUT READING THE NEXT PARAGRAPH.
            //
            // The accelerometer output rate is fixed at 1 kHz REGARDLESS of
            // SMPLRT_DIV. Sample at 8 kHz and every accel reading repeats
            // eight times, which is not a bug in the part, it is the part
            // working as documented. Those repeats are indistinguishable from
            // a dead axis: repeated readings eventually trip RCT, so an 8 kHz
            // sample rate would fail the health tests
            // immediately and look like broken hardware.
            //
            // 1 kHz is the fastest rate at which all six axes are genuinely
            // fresh on every read.
            smplrt_div: 7,
            accel_hpf: 4,
            // 64 mg of movement on any axis, gravity already removed by the
            // high-pass. The strum and body-movement detector on a node with
            // no piezo. Tunable live with `SET mot_thr=`.
            mot_thr: 8,
            // 8 degrees per second of rotation on any axis: a deliberate lean
            // or twist of the neck, well clear of a guitar hanging still on a
            // strap. Tunable live with `SET gyro_thr=`.
            gyro_thr: DEFAULT_GYRO_THR,
        }
    }
}

impl Config {
    pub fn sample_rate_hz(&self) -> u32 {
        // Gyro output rate is 8 kHz when the DLPF is disabled (DLPF_CFG 0 or
        // 7), and 1 kHz for every other setting.
        let base: u32 = if self.dlpf == 0 || self.dlpf == 7 {
            8_000
        } else {
            1_000
        };
        base / (1 + self.smplrt_div as u32)
    }

    /// True when the configured rate would outrun the accelerometer's fixed
    /// 1 kHz update and manufacture duplicate samples.
    pub fn outruns_accel(&self) -> bool {
        self.sample_rate_hz() > 1_000
    }

    pub fn gyro_config_byte(&self) -> u8 {
        (self.gyro as u8) << 3
    }

    pub fn accel_config_byte(&self) -> u8 {
        // Range bits only. Bits [2:0] were the MPU-6050's motion high-pass,
        // which is reserved on the 6500 family; motion is detected in firmware
        // now, so they stay 0 on every chip.
        (self.accel as u8) << 3
    }

    pub fn config_byte(&self) -> u8 {
        self.dlpf & 0x07
    }

    pub fn pwr_mgmt_1_byte(&self) -> u8 {
        // SLEEP cleared, TEMP_DIS cleared (the temperature channel is one of
        // our sources), CLKSEL from config.
        self.clock as u8
    }

    /// LSB per g for the configured accelerometer range.
    pub fn accel_lsb_per_g(&self) -> u16 {
        match self.accel {
            AccelRange::G2 => 16384,
            AccelRange::G4 => 8192,
            AccelRange::G8 => 4096,
            AccelRange::G16 => 2048,
        }
    }

    /// Gyro counts per 0.1 degree per second, i.e. the datasheet's LSB per
    /// deg/s times ten (131, 65.5, 32.8, 16.4).
    pub fn gyro_lsb_per_dps_x10(&self) -> u16 {
        match self.gyro {
            GyroRange::Dps250 => 1310,
            GyroRange::Dps500 => 655,
            GyroRange::Dps1000 => 328,
            GyroRange::Dps2000 => 164,
        }
    }

    /// Micro-g represented by one accelerometer count.
    pub fn accel_ug_per_count(&self) -> u32 {
        1_000_000 / self.accel_lsb_per_g() as u32
    }
}

// ---------------------------------------------------------------------------
// A sample frame
// ---------------------------------------------------------------------------

pub const FRAME_LEN: usize = 14;

#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub struct Frame {
    pub accel: [i16; 3],
    pub temp: i16,
    pub gyro: [i16; 3],
}

impl Frame {
    /// Parse the 14-byte burst starting at ACCEL_XOUT_H. All fields are
    /// big-endian signed 16-bit, in the order accel XYZ, temp, gyro XYZ.
    pub fn parse(raw: &[u8; FRAME_LEN]) -> Self {
        let be = |hi: u8, lo: u8| i16::from_be_bytes([hi, lo]);
        Frame {
            accel: [be(raw[0], raw[1]), be(raw[2], raw[3]), be(raw[4], raw[5])],
            temp: be(raw[6], raw[7]),
            gyro: [
                be(raw[8], raw[9]),
                be(raw[10], raw[11]),
                be(raw[12], raw[13]),
            ],
        }
    }

    /// Die temperature in hundredths of a degree C.
    ///
    /// Datasheet: T_C = TEMP_OUT / 340 + 36.53. Kept in fixed point so no
    /// float touches the sampling path.
    pub fn temp_centi_c(&self) -> i32 {
        (self.temp as i32) * 100 / 340 + 3653
    }

    /// The entropy-bearing byte of each channel, in a fixed order matching
    /// SourceId: accel XYZ, gyro XYZ, temp.
    ///
    /// The low 8 bits are the noise-bearing part. At +/-2g one count is about
    /// 61 ug, so 8 bits spans roughly 15.6 mg, which the part's own noise
    /// floor crosses continuously even on a guitar stand. The high byte is
    /// gross orientation: highly structured, and deliberately not used as a
    /// health-test sample.
    pub fn entropy_samples(&self) -> [u8; 7] {
        [
            self.accel[0] as u8,
            self.accel[1] as u8,
            self.accel[2] as u8,
            self.gyro[0] as u8,
            self.gyro[1] as u8,
            self.gyro[2] as u8,
            self.temp as u8,
        ]
    }

    /// True when every channel reads zero, which is what a bus that returns
    /// nothing looks like. A real part sitting on a bench never produces this:
    /// gravity alone puts roughly 16384 counts on one accelerometer axis.
    pub fn is_all_zero(&self) -> bool {
        self.accel == [0, 0, 0] && self.gyro == [0, 0, 0] && self.temp == 0
    }

    /// The same failure with the bus stuck high instead of low.
    pub fn is_all_ones(&self) -> bool {
        self.accel == [-1, -1, -1] && self.gyro == [-1, -1, -1] && self.temp == -1
    }

    /// A frame worth trusting at all. Catches the two bus failures above
    /// before their samples ever reach the health tests, so a snapped SDA line
    /// is reported as a bus fault rather than as seven simultaneously dead
    /// noise sources.
    pub fn plausible(&self) -> bool {
        !self.is_all_zero() && !self.is_all_ones()
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Error<E> {
    Bus(E),
    /// WHO_AM_I returned something other than 0x68. Carries what it did say,
    /// because that byte identifies which part you actually soldered on.
    WrongDevice(u8),
    /// The device answered but the configuration did not read back. Usually a
    /// clone that silently ignores writes to registers it does not implement.
    ConfigReadback {
        reg: u8,
        wrote: u8,
        read: u8,
    },
}

// ---------------------------------------------------------------------------
// Driver
// ---------------------------------------------------------------------------

pub struct Mpu6050<I> {
    bus: I,
    addr: u8,
    cfg: Config,
}

impl<I: I2cBus> Mpu6050<I> {
    pub fn new(bus: I, addr: u8, cfg: Config) -> Self {
        Mpu6050 { bus, addr, cfg }
    }

    pub fn config(&self) -> &Config {
        &self.cfg
    }

    /// Select the physical I2C address before probing. This permits firmware
    /// to support both AD0 straps without rebuilding.
    pub fn set_address(&mut self, addr: u8) {
        self.addr = addr;
    }

    async fn write_reg(&mut self, r: u8, v: u8) -> Result<(), Error<I::Error>> {
        self.bus.write(self.addr, &[r, v]).await.map_err(Error::Bus)
    }

    async fn read_reg(&mut self, r: u8) -> Result<u8, Error<I::Error>> {
        let mut b = [0u8; 1];
        self.bus
            .write_read(self.addr, &[r], &mut b)
            .await
            .map_err(Error::Bus)?;
        Ok(b[0])
    }

    /// Write a register and read it back, failing if it did not take.
    ///
    /// Worth the extra transaction at init: clone dies accept writes to
    /// registers they do not implement and return 0, which would leave the
    /// DLPF on and the noise floor filtered away with nothing to indicate it.
    async fn write_verify(&mut self, r: u8, v: u8) -> Result<(), Error<I::Error>> {
        self.write_reg(r, v).await?;
        let got = self.read_reg(r).await?;
        if got != v {
            return Err(Error::ConfigReadback {
                reg: r,
                wrote: v,
                read: got,
            });
        }
        Ok(())
    }

    pub async fn who_am_i(&mut self) -> Result<u8, Error<I::Error>> {
        self.read_reg(reg::WHO_AM_I).await
    }

    /// Full init. Order matters: reset, wake with the chosen clock, then
    /// configure, then verify.
    ///
    /// The caller must delay ~100 ms after `reset_only` before `configure`;
    /// this driver holds no timer so the wait belongs to the async runtime.
    pub async fn reset_only(&mut self) -> Result<(), Error<I::Error>> {
        // DEVICE_RESET. Not verified: the register clears itself as the reset
        // completes, so a readback races the part.
        self.write_reg(reg::PWR_MGMT_1, 0x80).await
    }

    /// Configure for harvesting. Returns which die answered.
    ///
    /// Every register written here is documented for both chip families and
    /// is read back; a mismatch is reported with the register, the value
    /// written and the value read, so a bad part or a bad wire is named
    /// instead of guessed at.
    pub async fn configure(&mut self) -> Result<Chip, Error<I::Error>> {
        let id = self.who_am_i().await?;
        let chip = Chip::identify(id).ok_or(Error::WrongDevice(id))?;

        // Wake and select the clock in one write. SLEEP must clear before any
        // other register will hold a value. CLKSEL 0 is the internal
        // oscillator on both families (8 MHz RC on the 6050, 20 MHz on the
        // 6500 family); either way it is unrelated to the ESP32's crystal,
        // which is what the clock-beat source measures.
        self.write_verify(reg::PWR_MGMT_1, self.cfg.pwr_mgmt_1_byte())
            .await?;
        // All axes on, no standby.
        self.write_verify(reg::PWR_MGMT_2, 0x00).await?;

        match chip {
            Chip::Mpu6050 => {
                // Filter off, 8 kHz gyro rate divided by 8: 1 kHz, the
                // accelerometer's own fixed rate.
                self.write_verify(reg::CONFIG, self.cfg.config_byte())
                    .await?;
                self.write_verify(reg::SMPLRT_DIV, self.cfg.smplrt_div)
                    .await?;
            }
            Chip::Mpu6500Family(_) => {
                // With the gyro filter fully off this family ignores the
                // divider and runs at 8 kHz, which would repeat every accel
                // sample eight times and trip RCT. DLPF_CFG 1 is the widest
                // setting that honours the divider: 1 kHz internal rate,
                // divider 0, 1 kHz out, gyro bandwidth 184 Hz.
                self.write_verify(reg::CONFIG, 0x01).await?;
                self.write_verify(reg::SMPLRT_DIV, 0x00).await?;
                // Accelerometer at its widest divided bandwidth (460 Hz).
                self.write_verify(reg::ACCEL_CONFIG2, 0x00).await?;
            }
        }
        self.write_verify(reg::GYRO_CONFIG, self.cfg.gyro_config_byte())
            .await?;
        self.write_verify(reg::ACCEL_CONFIG, self.cfg.accel_config_byte())
            .await?;

        // INT pin: push-pull, active high, 50 us pulse, cleared by reading
        // INT_STATUS. A latched pin would need an extra transaction per
        // sample, which is bandwidth we would rather spend on frames.
        self.write_verify(reg::INT_PIN_CFG, 0x00).await?;
        // Data-ready only. Motion is detected in firmware from the samples.
        self.write_verify(reg::INT_ENABLE, 0x01).await?;

        Ok(chip)
    }

    /// Read one 14-byte frame in a single burst from ACCEL_XOUT_H.
    ///
    /// One transaction, not seven: the part latches all output registers for
    /// the duration of a burst read, so a burst is internally consistent while
    /// separate reads can straddle an update and mix two moments together.
    pub async fn read_frame(&mut self) -> Result<Frame, Error<I::Error>> {
        let mut raw = [0u8; FRAME_LEN];
        self.bus
            .write_read(self.addr, &[reg::ACCEL_XOUT_H], &mut raw)
            .await
            .map_err(Error::Bus)?;
        Ok(Frame::parse(&raw))
    }

    pub async fn int_status(&mut self) -> Result<u8, Error<I::Error>> {
        self.read_reg(reg::INT_STATUS).await
    }

    /// INT_STATUS and the full frame in ONE 15-byte burst from 0x3A, the
    /// register directly before ACCEL_XOUT_H.
    ///
    /// Reading INT_STATUS clears DATA_RDY. Doing that in the same burst as the
    /// data means the flag and the data always describe the same sample: a
    /// sample that lands mid-read leaves DATA_RDY set for the next read and is
    /// never delivered twice. It also halves the bus transactions per frame.
    pub async fn read_status_and_frame(&mut self) -> Result<(u8, Frame), Error<I::Error>> {
        let mut raw = [0u8; 1 + FRAME_LEN];
        self.bus
            .write_read(self.addr, &[reg::INT_STATUS], &mut raw)
            .await
            .map_err(Error::Bus)?;
        let mut frame = [0u8; FRAME_LEN];
        frame.copy_from_slice(&raw[1..]);
        Ok((raw[0], Frame::parse(&frame)))
    }

    pub fn bus_mut(&mut self) -> &mut I {
        &mut self.bus
    }
}

/// INT_STATUS bit 0: a fresh sample is available.
pub const INT_DATA_RDY: u8 = 0x01;

// ---------------------------------------------------------------------------
// Motion detector
// ---------------------------------------------------------------------------
//
// Runs on every frame the sampler already reads at 1 kHz, on two sensors:
//
//   accel XYZ ─► median of 3 ─► average of 8 ─► minus slow resting value ─► largest |axis| mg ─┐
//   gyro  XYZ ─► median of 3 ─► average of 8 ─► minus slow resting value ─► largest |axis| °/s ─┤
//                                                  (corner set by hpf)                          │
//                            either one over its threshold for 2 frames in a row ─► motion ◄────┘
//
// The median throws away a single corrupted frame; the average cuts the
// sensor's own noise by about three times, which is what lets the thresholds
// go down to a few mg and a few degrees per second without firing on a guitar
// sitting still. The resting value removes gravity from the accelerometer and
// the zero-rate offset from the gyro (up to 20 °/s on a 6050, and it drifts
// with temperature).
//
// All of this is detection only. The entropy sources keep the raw samples,
// unsmoothed, exactly as before.
//
// Doing this in firmware rather than with the MPU's motion interrupt means:
// the thresholds are in exact units on every chip, the same code works on
// genuine parts and clones, and nothing depends on registers the current
// datasheet no longer documents.

/// Accelerometer threshold units, milligravity per step of `mot_thr`.
pub const MOTION_MG_PER_STEP: u32 = 8;

/// Consecutive over-threshold frames needed before a frame counts as motion.
pub const MOTION_CONFIRM_FRAMES: u8 = 2;

/// Frames averaged by the detection path. 8 at 1 kHz adds about 4 ms.
pub const MOTION_SMOOTH_FRAMES: usize = 8;

/// Frames after boot or a re-probe during which nothing counts and the
/// resting values track fast (a 1 kHz / (2 pi 8) = 20 Hz corner), so they
/// start from the sensor's real resting state rather than from whatever the
/// first frame said. That frame may be corrupted, and the gyro takes tens of
/// milliseconds to settle after the part wakes. 128 ms converges from any
/// starting error.
pub const MOTION_WARMUP_FRAMES: u16 = 128;
const WARMUP_SHIFT: u32 = 3;

fn median3(a: i16, b: i16, c: i16) -> i16 {
    a.max(b).min(a.min(b).max(c))
}

/// One three-axis sensor through the detection path.
#[derive(Copy, Clone, Debug, Default)]
struct Smoothed {
    /// The last three raw frames, oldest first, for the median.
    raw: [[i16; 3]; 3],
    /// The last `MOTION_SMOOTH_FRAMES` medians and their running sum.
    ring: [[i16; 3]; MOTION_SMOOTH_FRAMES],
    sum: [i32; 3],
    at: usize,
    /// Resting value per axis, counts scaled by 256.
    base: [i32; 3],
}

impl Smoothed {
    /// Start from a frame as if the sensor had been sitting there forever.
    fn prime(&mut self, v: [i16; 3]) {
        self.raw = [v; 3];
        self.ring = [v; MOTION_SMOOTH_FRAMES];
        for k in 0..3 {
            self.sum[k] = v[k] as i32 * MOTION_SMOOTH_FRAMES as i32;
            self.base[k] = (v[k] as i32) << 8;
        }
        self.at = 0;
    }

    /// Feed one frame. Returns the largest deviation from rest on any axis,
    /// in counts.
    fn push(&mut self, v: [i16; 3], shift: u32) -> u32 {
        self.raw = [self.raw[1], self.raw[2], v];
        let mut peak: i32 = 0;
        for k in 0..3 {
            let m = median3(self.raw[0][k], self.raw[1][k], self.raw[2][k]);
            self.sum[k] += m as i32 - self.ring[self.at][k] as i32;
            self.ring[self.at][k] = m;
            // Mean, scaled by 256 like the resting value. The sum is at most
            // 8 * 32768, so sum << 8 is at most 2^26, far inside an i32.
            let mean = (self.sum[k] << 8) / MOTION_SMOOTH_FRAMES as i32;
            let deviation = (mean - self.base[k]) >> 8;
            peak = peak.max(deviation.abs());
            self.base[k] += (mean - self.base[k]) >> shift;
        }
        self.at = (self.at + 1) % MOTION_SMOOTH_FRAMES;
        peak as u32
    }
}

/// What one frame looked like to the detector.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct MotionReading {
    /// Over a threshold long enough to count.
    pub hit: bool,
    /// Largest smoothed acceleration away from rest, mg.
    pub accel_mg: u32,
    /// Largest smoothed rotation away from rest, tenths of a degree/s.
    pub gyro_dps10: u32,
}

/// Unit conversions for the configured ranges, fixed for a session.
#[derive(Copy, Clone, Debug)]
pub struct MotionScale {
    pub accel_lsb_per_g: u16,
    pub gyro_lsb_per_dps_x10: u16,
}

impl MotionScale {
    pub fn of(cfg: &Config) -> Self {
        MotionScale {
            accel_lsb_per_g: cfg.accel_lsb_per_g(),
            gyro_lsb_per_dps_x10: cfg.gyro_lsb_per_dps_x10(),
        }
    }
}

#[derive(Copy, Clone, Debug, Default)]
pub struct MotionDetector {
    accel: Smoothed,
    gyro: Smoothed,
    primed: bool,
    /// Frames of warm-up left (`MOTION_WARMUP_FRAMES`).
    warm: u16,
    /// Consecutive frames over a threshold so far.
    over: u8,
}

impl MotionDetector {
    pub fn new() -> Self {
        Self::default()
    }

    /// Forget the resting values, so the next frame becomes the new baseline
    /// instead of registering as a jump. Called after the part is re-probed.
    pub fn reset(&mut self) {
        self.primed = false;
        self.over = 0;
    }

    /// Smoothing shift for an `hpf` setting at 1 kHz. The corner is
    /// fs / (2 pi 2^shift): 5 => 5 Hz, 6 => 2.5 Hz, 7 => 1.24 Hz, 8 => 0.62 Hz.
    /// Detection is off for 0, and the resting values keep tracking at
    /// 0.62 Hz so turning it back on does not start from a stale value.
    fn shift(hpf: u8) -> u32 {
        match hpf {
            1 => 5,
            2 => 6,
            3 => 7,
            _ => 8,
        }
    }

    /// Feed one frame and decide.
    ///
    /// `hpf` 0 turns detection off entirely. `mot_thr` is in 8 mg steps and
    /// `gyro_thr` in whole degrees per second; either at 0 switches that
    /// trigger off. The levels are reported whatever the thresholds.
    pub fn push(
        &mut self,
        accel: [i16; 3],
        gyro: [i16; 3],
        hpf: u8,
        mot_thr: u8,
        gyro_thr: u8,
        scale: MotionScale,
    ) -> MotionReading {
        if !self.primed {
            self.accel.prime(accel);
            self.gyro.prime(gyro);
            self.primed = true;
            self.warm = MOTION_WARMUP_FRAMES;
            self.over = 0;
            return MotionReading { hit: false, accel_mg: 0, gyro_dps10: 0 };
        }
        let warming = self.warm > 0;
        let shift = if warming {
            self.warm -= 1;
            WARMUP_SHIFT
        } else {
            Self::shift(hpf)
        };
        let accel_mg = self.accel.push(accel, shift) * 1000 / scale.accel_lsb_per_g.max(1) as u32;
        let gyro_dps10 = self.gyro.push(gyro, shift) * 100 / scale.gyro_lsb_per_dps_x10.max(1) as u32;

        let accel_over = mot_thr != 0 && accel_mg >= mot_thr as u32 * MOTION_MG_PER_STEP;
        let gyro_over = gyro_thr != 0 && gyro_dps10 >= gyro_thr as u32 * 10;
        if !warming && hpf != 0 && (accel_over || gyro_over) {
            self.over = self.over.saturating_add(1);
        } else {
            self.over = 0;
        }
        MotionReading {
            hit: self.over >= MOTION_CONFIRM_FRAMES,
            accel_mg,
            gyro_dps10,
        }
    }
}

// ---------------------------------------------------------------------------
// Clock beat
// ---------------------------------------------------------------------------
//
// The MPU runs off its internal 8 MHz RC oscillator; the MCU runs off a
// crystal. Neither knows about the other, so the interval between data-ready
// edges, measured in MCU cycles, wanders. That wander is a genuinely separate
// physical process from the MEMS noise on the axes, which matters: six
// accelerometer channels sharing one internal ADC may well be correlated with
// each other, but none of them is correlated with a crystal.

#[derive(Copy, Clone, Debug, Default)]
pub struct ClockBeat {
    last: u32,
    have_last: bool,
    pub last_delta: u32,
}

impl ClockBeat {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed the MCU cycle counter captured at a data-ready edge. Returns the
    /// entropy byte, or None for the first edge, which has no predecessor to
    /// difference against.
    pub fn push(&mut self, cycles: u32) -> Option<u8> {
        if !self.have_last {
            self.last = cycles;
            self.have_last = true;
            return None;
        }
        let delta = cycles.wrapping_sub(self.last);
        self.last = cycles;
        self.last_delta = delta;
        // The low byte of the interval. The high bits are the nominal period
        // and carry no information; the jitter lives at the bottom.
        Some(delta as u8)
    }

    pub fn reset(&mut self) {
        self.have_last = false;
        self.last_delta = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::future::Future;
    use core::pin::pin;
    use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

    /// Run a future that never actually waits (the mock bus is synchronous).
    fn block_on<F: Future>(f: F) -> F::Output {
        fn noop(_: *const ()) {}
        fn clone(p: *const ()) -> RawWaker {
            RawWaker::new(p, &VTABLE)
        }
        static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, noop, noop, noop);
        let waker = unsafe { Waker::from_raw(RawWaker::new(core::ptr::null(), &VTABLE)) };
        let mut cx = Context::from_waker(&waker);
        let mut f = pin!(f);
        loop {
            if let Poll::Ready(v) = f.as_mut().poll(&mut cx) {
                return v;
            }
        }
    }

    /// A register file behind one I2C address. `stuck` registers ignore
    /// writes, the way a clone ignores registers it does not implement.
    struct MockBus {
        addr: u8,
        regs: [u8; 128],
        stuck: &'static [u8],
        writes: [(u8, u8); 32],
        n_writes: usize,
    }

    impl MockBus {
        fn new(addr: u8, who_am_i: u8, stuck: &'static [u8]) -> Self {
            let mut regs = [0u8; 128];
            regs[reg::WHO_AM_I as usize] = who_am_i;
            regs[reg::PWR_MGMT_1 as usize] = 0x40; // SLEEP after reset
            MockBus { addr, regs, stuck, writes: [(0, 0); 32], n_writes: 0 }
        }
        fn wrote(&self, r: u8) -> Option<u8> {
            self.writes[..self.n_writes].iter().rev().find(|w| w.0 == r).map(|w| w.1)
        }
    }

    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    struct Nack;

    impl I2cBus for MockBus {
        type Error = Nack;
        async fn write(&mut self, addr: u8, bytes: &[u8]) -> Result<(), Nack> {
            if addr != self.addr {
                return Err(Nack);
            }
            let (r, v) = (bytes[0], bytes[1]);
            if self.n_writes < self.writes.len() {
                self.writes[self.n_writes] = (r, v);
                self.n_writes += 1;
            }
            if !self.stuck.contains(&r) {
                self.regs[r as usize] = v;
            }
            Ok(())
        }
        async fn write_read(&mut self, addr: u8, w: &[u8], out: &mut [u8]) -> Result<(), Nack> {
            if addr != self.addr {
                return Err(Nack);
            }
            for (i, o) in out.iter_mut().enumerate() {
                *o = self.regs[(w[0] as usize + i) % 128];
            }
            Ok(())
        }
    }

    #[test]
    fn genuine_mpu6050_gets_filter_off_and_divider_7() {
        let mut dev = Mpu6050::new(MockBus::new(0x68, 0x68, &[]), 0x68, Config::default());
        assert_eq!(block_on(dev.configure()), Ok(Chip::Mpu6050));
        let bus = dev.bus_mut();
        assert_eq!(bus.wrote(reg::CONFIG), Some(0x00));
        assert_eq!(bus.wrote(reg::SMPLRT_DIV), Some(7));
        assert_eq!(bus.wrote(reg::ACCEL_CONFIG), Some(0x00));
        assert_eq!(bus.wrote(reg::GYRO_CONFIG), Some(0x00));
        assert_eq!(bus.wrote(reg::INT_ENABLE), Some(0x01));
        assert_eq!(bus.wrote(reg::ACCEL_CONFIG2), None, "6500-only register touched");
        // No undocumented motion registers are touched on any chip.
        for r in [0x1F, 0x20, 0x69] {
            assert_eq!(bus.wrote(r), None, "wrote reg 0x{r:02x}");
        }
    }

    #[test]
    fn mpu6500_family_clone_is_accepted_and_runs_at_1khz() {
        for id in [0x70, 0x71, 0x72, 0x73, 0x98] {
            let mut dev = Mpu6050::new(MockBus::new(0x68, id, &[]), 0x68, Config::default());
            assert_eq!(block_on(dev.configure()), Ok(Chip::Mpu6500Family(id)));
            let bus = dev.bus_mut();
            assert_eq!(bus.wrote(reg::CONFIG), Some(0x01));
            assert_eq!(bus.wrote(reg::SMPLRT_DIV), Some(0x00));
            assert_eq!(bus.wrote(reg::ACCEL_CONFIG2), Some(0x00));
            assert_eq!(bus.wrote(reg::INT_ENABLE), Some(0x01));
        }
    }

    #[test]
    fn status_and_frame_come_from_one_burst() {
        let mut bus = MockBus::new(0x68, 0x68, &[]);
        bus.regs[reg::INT_STATUS as usize] = INT_DATA_RDY;
        for (i, r) in (reg::ACCEL_XOUT_H..reg::ACCEL_XOUT_H + FRAME_LEN as u8).enumerate() {
            bus.regs[r as usize] = i as u8 + 1;
        }
        let mut dev = Mpu6050::new(bus, 0x68, Config::default());
        let (status, frame) = block_on(dev.read_status_and_frame()).unwrap();
        assert_eq!(status, INT_DATA_RDY);
        assert_eq!(frame.accel[0], i16::from_be_bytes([1, 2]));
        assert_eq!(frame.gyro[2], i16::from_be_bytes([13, 14]));
        // 0x3A really is the register right before the data.
        assert_eq!(reg::INT_STATUS + 1, reg::ACCEL_XOUT_H);
    }

    #[test]
    fn failures_name_the_cause() {
        // Nothing at the address.
        let mut dev = Mpu6050::new(MockBus::new(0x69, 0x68, &[]), 0x68, Config::default());
        assert_eq!(block_on(dev.configure()), Err(Error::Bus(Nack)));
        // Something that is not an IMU of either family.
        let mut dev = Mpu6050::new(MockBus::new(0x68, 0x00, &[]), 0x68, Config::default());
        assert_eq!(block_on(dev.configure()), Err(Error::WrongDevice(0x00)));
        // A register that does not hold its value.
        let mut dev = Mpu6050::new(MockBus::new(0x68, 0x68, &[reg::PWR_MGMT_1]), 0x68, Config::default());
        assert_eq!(
            block_on(dev.configure()),
            Err(Error::ConfigReadback { reg: reg::PWR_MGMT_1, wrote: 0x00, read: 0x40 })
        );
    }

    const G: i16 = 16384; // counts per g at +/-2g
    const DPS: i16 = 131; // counts per degree/s at +/-250 dps
    const SCALE: MotionScale = MotionScale { accel_lsb_per_g: 16384, gyro_lsb_per_dps_x10: 1310 };
    const REST: [i16; 3] = [0, 0, G];
    /// A typical 6050 zero-rate offset: several degrees per second.
    const BIAS: [i16; 3] = [-600, 250, 90];

    fn settle(d: &mut MotionDetector, thr: u8, gthr: u8) {
        for _ in 0..3_000 {
            assert!(!d.push(REST, BIAS, 4, thr, gthr, SCALE).hit);
        }
    }

    #[test]
    fn median_of_three() {
        assert_eq!(median3(1, 2, 3), 2);
        assert_eq!(median3(3, 1, 2), 2);
        assert_eq!(median3(2, 3, 1), 2);
        assert_eq!(median3(-5, 9, -5), -5);
        assert_eq!(median3(i16::MIN, 0, i16::MAX), 0);
    }

    #[test]
    fn detector_ignores_stillness_gravity_and_gyro_offset() {
        let mut d = MotionDetector::new();
        // Resting with gravity on Z, a gyro offset, and noise worse than a
        // real 6050's at 1 kHz: +/-8 mg on every accel axis and +/-0.5 dps on
        // every gyro axis. The most sensitive settings (16 mg, 1 dps) still
        // never fire.
        let mut x: u32 = 12345;
        let mut n = || {
            x = x.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            ((x >> 16) % 1001) as i32 - 500
        };
        for _ in 0..20_000 {
            let a = [n() * 262 / 1000, n() * 262 / 1000, G as i32 + n() * 262 / 1000];
            let g = [BIAS[0] as i32 + n() * 131 / 1000, BIAS[1] as i32 + n() * 131 / 1000, BIAS[2] as i32 + n() * 131 / 1000];
            let r = d.push(
                [a[0] as i16, a[1] as i16, a[2] as i16],
                [g[0] as i16, g[1] as i16, g[2] as i16],
                4,
                2,
                1,
                SCALE,
            );
            assert!(!r.hit, "fired on noise: {r:?}");
        }
    }

    #[test]
    fn detector_fires_on_a_small_jolt_within_a_few_milliseconds() {
        let mut d = MotionDetector::new();
        settle(&mut d, 2, 0);
        // A 24 mg bump on X against a 16 mg threshold (mot_thr 2).
        let bump = [393, 0, G];
        let mut fired_at = None;
        for i in 0..20 {
            let r = d.push(bump, BIAS, 4, 2, 0, SCALE);
            if r.hit {
                fired_at = Some(i);
                break;
            }
        }
        let at = fired_at.expect("a 24 mg bump registers");
        assert!(at <= 10, "took {at} ms");
    }

    #[test]
    fn detector_fires_on_a_slow_rotation_the_accelerometer_misses() {
        // Rotating at 4 degrees/s for half a second tilts the guitar by two
        // degrees: about 35 mg of gravity shifting across, spread over 500 ms,
        // under the default 64 mg. The gyro sees 4 dps against a 3 dps
        // threshold at once.
        let mut d = MotionDetector::new();
        settle(&mut d, 8, 3);
        let mut accel_only = d;
        let mut gyro_fired = false;
        let mut accel_fired = false;
        for i in 0..500 {
            let angle = (i as f32 / 1000.0) * 4.0_f32.to_radians();
            let a = [(angle.sin() * G as f32) as i16, 0, (angle.cos() * G as f32) as i16];
            let g = [BIAS[0], BIAS[1] + 4 * DPS, BIAS[2]];
            gyro_fired |= d.push(a, g, 4, 8, 3, SCALE).hit;
            accel_fired |= accel_only.push(a, g, 4, 8, 0, SCALE).hit;
        }
        assert!(gyro_fired);
        assert!(!accel_fired);
    }

    #[test]
    fn detector_still_catches_strums_and_headbangs() {
        // 100 mg jolt at the default 64 mg.
        let mut d = MotionDetector::new();
        settle(&mut d, 8, 0);
        let mut fired = false;
        for _ in 0..10 {
            fired |= d.push([1638, 0, G], BIAS, 4, 8, 0, SCALE).hit;
        }
        assert!(fired);

        // A 90 degree tilt over 0.3 s (a headbang or swinging the neck).
        let mut d = MotionDetector::new();
        settle(&mut d, 8, 0);
        let mut fired = false;
        for i in 0..=300 {
            let t = i as f32 / 300.0 * core::f32::consts::FRAC_PI_2;
            let (s, c) = (t.sin(), t.cos());
            fired |= d.push([(s * G as f32) as i16, 0, (c * G as f32) as i16], BIAS, 4, 8, 0, SCALE).hit;
        }
        assert!(fired);
    }

    #[test]
    fn detector_reports_levels_in_real_units() {
        let mut d = MotionDetector::new();
        settle(&mut d, 8, 8);
        let mut r = d.push(REST, BIAS, 4, 8, 8, SCALE);
        for _ in 0..12 {
            // 50 mg on Y and 20 dps on Z, held long enough to fill the average.
            r = d.push([0, 819, G], [BIAS[0], BIAS[1], BIAS[2] + 20 * DPS], 4, 8, 8, SCALE);
        }
        // A few percent under the true 50 mg and 20.0 dps: the resting value
        // has already started following the step, which is the high-pass
        // doing its job.
        assert!((46..=50).contains(&r.accel_mg), "{r:?}");
        assert!((190..=200).contains(&r.gyro_dps10), "{r:?}");
    }

    #[test]
    fn detector_off_switches_glitches_and_reset() {
        let mut d = MotionDetector::new();
        settle(&mut d, 1, 1);
        let run = |mut d: MotionDetector, a: [i16; 3], g: [i16; 3], hpf: u8, thr: u8, gthr: u8| {
            (0..20).any(|_| d.push(a, g, hpf, thr, gthr, SCALE).hit)
        };
        let big_a = [8000, 0, G];
        let big_g = [BIAS[0] + 50 * DPS, BIAS[1], BIAS[2]];
        // hpf 0 turns everything off.
        assert!(!run(d, big_a, big_g, 0, 1, 1));
        // Each trigger has its own off switch.
        assert!(!run(d, REST, big_g, 4, 1, 0));
        assert!(!run(d, big_a, BIAS, 4, 0, 1));
        assert!(run(d, REST, big_g, 4, 1, 1));
        assert!(run(d, big_a, BIAS, 4, 1, 0));
        // A single corrupted frame between normal ones never counts, even at
        // the most sensitive settings: the median discards it.
        let mut g = d;
        assert!(!g.push([30000, -30000, G], [30000, -30000, 30000], 4, 1, 1, SCALE).hit);
        for _ in 0..20 {
            assert!(!g.push(REST, BIAS, 4, 1, 1, SCALE).hit);
        }
        // The first frame after a reset is the new baseline, not a jump.
        d.reset();
        for _ in 0..20 {
            assert!(!d.push(big_a, big_g, 4, 1, 1, SCALE).hit);
        }
    }

    #[test]
    fn a_bad_first_frame_after_a_reprobe_is_not_a_movement() {
        // The first frame after boot or a re-probe is corrupted (a flipped
        // sign on Z, a gyro spike), then the sensor reads normally. The
        // resting values must come from the normal frames, at the most
        // sensitive settings, with no false hit at all.
        let mut d = MotionDetector::new();
        assert!(!d.push([0, 0, -G], [2000, -2000, 2000], 4, 1, 1, SCALE).hit);
        for i in 0..5_000 {
            let r = d.push(REST, BIAS, 4, 1, 1, SCALE);
            assert!(!r.hit, "false hit at frame {i}: {r:?}");
        }
        // And it still works afterwards.
        assert!((0..20).any(|_| d.push([1638, 0, G], BIAS, 4, 8, 0, SCALE).hit));
    }

    #[test]
    fn nothing_counts_during_warm_up() {
        let mut d = MotionDetector::new();
        d.push(REST, BIAS, 4, 1, 1, SCALE);
        let jolt = [8000, 0, G];
        for _ in 0..MOTION_WARMUP_FRAMES {
            assert!(!d.push(jolt, BIAS, 4, 1, 1, SCALE).hit);
        }
    }

    #[test]
    fn gyro_scale_matches_the_datasheet() {
        let mut c = Config::default();
        assert_eq!(c.gyro_lsb_per_dps_x10(), 1310);
        c.gyro = GyroRange::Dps2000;
        assert_eq!(c.gyro_lsb_per_dps_x10(), 164);
    }
}
