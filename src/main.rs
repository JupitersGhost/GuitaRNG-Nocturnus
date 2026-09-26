// ============================================================================
//  main.rs - GuitaRNG MPU node
//  ESP32-S3 Super Mini + MPU-6050, Embassy / no_std
// ============================================================================

#![no_std]
#![no_main]

mod config;
mod entropy;
mod mpu;
mod net;
mod persist;
mod web;

use core::fmt::Write as _;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU8, Ordering};

use config as cfg;
use embassy_executor::Spawner;
use embassy_futures::select::{select, select4, Either, Either4};
use embassy_net::udp::{PacketMetadata, UdpSocket};
use embassy_net::{
    IpAddress, IpEndpoint, Ipv4Address, Ipv4Cidr, Runner, Stack, StackResources, StaticConfigV4,
};
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::channel::Channel;
use embassy_sync::mutex::Mutex;
use embassy_sync::signal::Signal;
use embassy_time::{with_timeout, Duration, Instant, Ticker, Timer};
use embedded_io_async::{Read, Write};
use esp_backtrace as _;
use esp_hal::rtc_cntl::{Rtc, RwdtStage, SocResetReason};
use esp_hal::usb::usb_serial_jtag::{UsbSerialJtagRx, UsbSerialJtagTx};
use esp_hal::Async;
use esp_radio::wifi::{
    ap::AccessPointConfig, sta::StationConfig, AuthenticationMethodConfig, Config as WifiConfig,
    ControllerConfig, Interface, WifiController,
};
use esp_storage::FlashStorage;
use sha3::{Digest, Sha3_256, Sha3_512};

use entropy::{Absorb, Harvester, SourceId, Verdict, SOURCE_COUNT};
use net::{Resolved, TargetPin};
use persist::{Loaded, Settings};

// Required by the ESP-IDF second-stage bootloader used by espflash v4. This
// places the application metadata at `.rodata_desc.appdesc` in the image.
esp_bootloader_esp_idf::esp_app_desc!();

macro_rules! mk_static {
    ($t:ty, $value:expr) => {{
        static CELL: static_cell::StaticCell<$t> = static_cell::StaticCell::new();
        CELL.uninit().write($value)
    }};
}

// ---------------------------------------------------------------------------
// SHA3-512 conditioner
// ---------------------------------------------------------------------------

const CONDITIONER_DOMAIN: &[u8] = b"GuitaRNG/nocturnus/SHA3-512/v1";

// The budget caps unspent credit at two releases' worth on the grounds that one
// SHA3-512 digest is 512 bits and its unreleased half is 256. That only holds
// while a release costs exactly one output block.
const _: () = assert!(cfg::TARGET_BITS == (cfg::KEY_BYTES * 8) as u32 && cfg::KEY_BYTES == 32);

/// SHA3-512 extraction with an unreleased chaining half.
///
/// Every release finalizes a clone of the current state. Bytes 0..32 are the
/// Spectra-compatible output. Bytes 32..64 are never transmitted and key the
/// next epoch by being absorbed, with a domain separator and epoch counter,
/// into a fresh SHA3-512 state. Replacing the old state gives backtracking
/// resistance while fresh raw entropy is still required for every release.
pub struct Sha3Sink {
    hasher: Sha3_512,
    absorbed: u64,
    releases: u32,
}

impl Sha3Sink {
    pub fn new() -> Self {
        let mut hasher = Sha3_512::new();
        hasher.update(CONDITIONER_DOMAIN);
        Sha3Sink {
            hasher,
            absorbed: 0,
            releases: 0,
        }
    }
}

impl Absorb for Sha3Sink {
    fn absorb(&mut self, data: &[u8]) {
        self.hasher.update(data);
        self.absorbed = self.absorbed.saturating_add(data.len() as u64);
    }

    fn squeeze(&mut self, out: &mut [u8]) {
        let digest = self.hasher.clone().finalize();
        let n = out.len().min(cfg::KEY_BYTES);
        out[..n].copy_from_slice(&digest[..n]);

        let mut next = Sha3_512::new();
        next.update(CONDITIONER_DOMAIN);
        next.update(b"/chain/");
        next.update(&digest[cfg::KEY_BYTES..64]);
        next.update(self.releases.to_le_bytes());
        self.hasher = next;
        self.releases = self.releases.wrapping_add(1);
        self.absorbed = 0;
    }
}

// ---------------------------------------------------------------------------
// Shared state and event queues
// ---------------------------------------------------------------------------

pub struct Shared {
    pub harvester: Harvester,
    pub strum_pin: TargetPin,
    pub entropy_pin: TargetPin,
    pub strum: Resolved,
    pub entropy: Resolved,
    pub strum_port: u16,
    pub entropy_port: u16,
    pub udp_enabled: bool,
    /// Whether the unauthenticated UDP control port accepts commands.
    pub udp_control: bool,
    pub targets_dirty: bool,
    pub bus_faults: u32,
    pub mpu_ready: bool,
    pub mpu_address: u8,
    /// Which die answered, once one has.
    pub mpu_chip: &'static str,
    /// Why the last probe failed, in words, for USB and the dashboard.
    pub mpu_error: net::Buf<512>,
    /// How the MPU is connected once found: pins, bus speed, INT mode.
    pub mpu_link: net::Buf<96>,
    /// The motion settings as ASKED FOR. The sampler applies them to the part
    /// between frames, and re-applies them after any re-probe.
    pub mot_thr: u8,
    pub gyro_thr: u8,
    pub accel_hpf: u8,
    /// Credited sources that must be live for a release.
    pub min_live: u8,
    pub wifi_connected: bool,
    pub wifi_credentials: net::WifiCredentials,
    pub sta_ip: Option<net::Ipv4>,
    pub sta_gw: Option<net::Ipv4>,
    pub admin_salt: [u8; 16],
    pub admin_hash: [u8; 32],
    pub reset_reason: &'static str,
}

static SHARED: Mutex<CriticalSectionRawMutex, Option<Shared>> = Mutex::new(None);

#[derive(Copy, Clone)]
struct KeyPacket {
    bytes: [u8; cfg::KEY_BYTES],
}

#[derive(Copy, Clone)]
struct AuxSample {
    source: SourceId,
    sample: u8,
}

#[derive(Copy, Clone)]
struct UsbText {
    bytes: [u8; 1024],
    len: usize,
}

impl UsbText {
    fn from_slice(data: &[u8]) -> Self {
        let mut result = UsbText {
            bytes: [0; 1024],
            len: data.len().min(1024),
        };
        result.bytes[..result.len].copy_from_slice(&data[..result.len]);
        result
    }

    fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

static NET_KEYS: Channel<CriticalSectionRawMutex, KeyPacket, 4> = Channel::new();
static USB_KEYS: Channel<CriticalSectionRawMutex, KeyPacket, 4> = Channel::new();
static STRUMS: Channel<CriticalSectionRawMutex, (), 8> = Channel::new();
static AUX_SAMPLES: Channel<CriticalSectionRawMutex, AuxSample, 32> = Channel::new();
static USB_TEXT: Channel<CriticalSectionRawMutex, UsbText, 4> = Channel::new();

/// Raw samples on their way to USB during a DUMP, in capture order.
#[derive(Copy, Clone)]
enum DumpChunk {
    Data {
        source: SourceId,
        len: u8,
        bytes: [u8; entropy::TAP_LEN],
    },
    Done {
        source: SourceId,
        captured: u32,
        /// Why it ended: "done", or what cut it short.
        reason: &'static str,
    },
}
static DUMP_CHUNKS: Channel<CriticalSectionRawMutex, DumpChunk, 32> = Channel::new();
/// Samples still to capture in the running DUMP; 0 when none is running.
static DUMP_LEFT: AtomicU32 = AtomicU32::new(0);
/// Samples delivered to USB in the running capture.
static DUMP_CAPTURED: AtomicU32 = AtomicU32::new(0);
/// Source being captured (its index), or DUMP_NONE. Read without the lock by
/// `capture_aux`, so a sample dropped before it reaches the tap is noticed.
const DUMP_NONE: u8 = 0xFF;
static DUMP_SOURCE: AtomicU8 = AtomicU8::new(DUMP_NONE);
/// A sample of the captured source was dropped on the way in.
static DUMP_GAP: AtomicBool = AtomicBool::new(false);

/// End a capture, whoever ends it. Must be called with the shared state
/// locked: the tap closes and the credit collected while samples were being
/// printed is discarded in the same step, before any release can run.
fn end_dump(sh: &mut Shared, reason: &'static str) {
    let Some(source) = sh.harvester.tap.source else {
        return;
    };
    sh.harvester.tap = entropy::Tap::new();
    sh.harvester.discard_credit();
    DUMP_SOURCE.store(DUMP_NONE, Ordering::Relaxed);
    DUMP_LEFT.store(0, Ordering::Relaxed);
    DUMP_GAP.store(false, Ordering::Relaxed);
    let done = DumpChunk::Done {
        source,
        captured: DUMP_CAPTURED.swap(0, Ordering::Relaxed),
        reason,
    };
    if DUMP_CHUNKS.try_send(done).is_err() {
        queue_usb(b"DUMP state=ended note=summary_dropped releases=resumed\r\n");
    }
}

type NoiseAdc = esp_hal::analog::adc::Adc<'static, esp_hal::peripherals::ADC1<'static>, esp_hal::Blocking>;
type NoisePin = esp_hal::analog::adc::AdcPin<
    esp_hal::peripherals::GPIO1<'static>,
    esp_hal::peripherals::ADC1<'static>,
>;
static WIFI_UPDATES: Channel<CriticalSectionRawMutex, net::WifiCredentials, 4> = Channel::new();

/// Minimum gap between motion events reaching the relay, milliseconds.
static DEBOUNCE_MS: AtomicU32 = AtomicU32::new(cfg::MOTION_DEBOUNCE_MS as u32);

/// Motion detector settings, read by the sampler on every frame, so a change
/// takes effect on the next millisecond with no bus traffic at all.
static MOT_THR: AtomicU8 = AtomicU8::new(8);
static GYRO_THR: AtomicU8 = AtomicU8::new(mpu::DEFAULT_GYRO_THR);
static MOTION_HPF: AtomicU8 = AtomicU8::new(4);

/// Largest movement seen in the last quarter second, mg. The dashboard shows
/// it next to the threshold so tuning is a matter of watching one number.
static MOTION_LEVEL_MG: AtomicU32 = AtomicU32::new(0);
/// The same for rotation, tenths of a degree per second.
static GYRO_LEVEL_DPS10: AtomicU32 = AtomicU32::new(0);

// Counters for the dashboard. Monotonic since boot; the page turns them into
// rates by differencing two polls.
static MOTION_RAW: AtomicU32 = AtomicU32::new(0);
static MOTION_EVENTS: AtomicU32 = AtomicU32::new(0);
static FRAMES: AtomicU32 = AtomicU32::new(0);
static SENT_ENTROPY: AtomicU32 = AtomicU32::new(0);
static SENT_STRUM: AtomicU32 = AtomicU32::new(0);
static SENT_HEARTBEAT: AtomicU32 = AtomicU32::new(0);
static SEND_ERRORS: AtomicU32 = AtomicU32::new(0);
/// Last RSSI in dBm, stored as the i8 bit pattern.
static RSSI: AtomicU8 = AtomicU8::new(0);

/// Set once the Wi-Fi controller is running. The hardware RNG is only a true
/// random source while the radio is on, so its samples are only taken then.
static RADIO_UP: AtomicBool = AtomicBool::new(false);

/// Advances on every pass of the sampler, including passes that time out and
/// passes spent probing for a missing MPU. The watchdog is fed only while this
/// moves.
static HARVEST_BEAT: AtomicU32 = AtomicU32::new(0);
static WDT_ARMED: AtomicBool = AtomicBool::new(false);

fn queue_usb(data: &[u8]) {
    let _ = USB_TEXT.try_send(UsbText::from_slice(data));
}

fn capture_aux(source: SourceId, sample: u8) {
    if AUX_SAMPLES.try_send(AuxSample { source, sample }).is_err()
        && DUMP_SOURCE.load(Ordering::Relaxed) == source as u8
    {
        // The capture would have a hole in it. Never hand that to NIST.
        DUMP_GAP.store(true, Ordering::Relaxed);
    }
}

fn timer_byte() -> u8 {
    esp_hal::time::Instant::now()
        .duration_since_epoch()
        .as_micros() as u8
}

fn verdict_char(v: Verdict) -> char {
    match v {
        Verdict::Warming => 'W',
        Verdict::Healthy => 'H',
        Verdict::Degraded => 'D',
        Verdict::Failed => 'F',
    }
}

// ---------------------------------------------------------------------------
// Entropy harvest
// ---------------------------------------------------------------------------

fn describe_mpu_error<const N: usize>(
    out: &mut net::Buf<N>,
    address: u8,
    stage: &str,
    e: mpu::Error<esp_hal::i2c::master::Error>,
) {
    let _ = match e {
        mpu::Error::Bus(bus) => write!(out, "0x{address:02x} {stage}: bus {bus:?}"),
        mpu::Error::WrongDevice(id) => write!(
            out,
            "0x{address:02x} answered WHO_AM_I=0x{id:02x}, not a known MPU"
        ),
        mpu::Error::ConfigReadback { reg, wrote, read } => write!(
            out,
            "0x{address:02x} register 0x{reg:02x} wrote 0x{wrote:02x} read back 0x{read:02x}"
        ),
    };
}

#[embassy_executor::task]
async fn harvest_task(
    mut dev: mpu::Mpu6050<HalI2c>,
    mut int_pin: esp_hal::gpio::Input<'static>,
    adc: NoiseAdc,
    adc_pin: NoisePin,
    wiring: net::Buf<320>,
    bus_pins: (u8, u8),
) {
    let mut common = Common {
        sink: Sha3Sink::new(),
        rng: esp_hal::rng::Rng::new(),
        adc,
        adc_pin,
        last_release: Instant::now(),
    };
    let mut beat = mpu::ClockBeat::new();
    let mut bus_faults: u32 = 0;
    // Sampling speed. Drops to 100 kHz for good if the bus proves unreliable
    // at the full rate (weak pull-ups, long wires): half the frames at 100 kHz
    // beats none at 400.
    let mut run_hz: u32 = cfg::I2C_FREQ_HZ;

    // None until the first reported movement, so the first movement after boot
    // always goes out instead of being swallowed by the debounce window.
    let mut last_motion: Option<Instant> = None;
    let mut detector = mpu::MotionDetector::new();
    let scale = mpu::MotionScale::of(dev.config());

    loop {
        // ---- find and configure the part --------------------------------
        // Probing runs at 100 kHz, which tolerates long jumpers and weak
        // pull-ups far better than 400 kHz; sampling switches up once the
        // part has answered.
        let _ = dev.bus_mut().apply_config(&i2c_config(100_000));

        // Last failure reported on USB, so a changed fault (a wire reseated
        // into a different problem) is reported again, but a repeat is not.
        let mut reported = net::Buf::<512>::new();
        let (detected_address, chip) = 'probe: loop {
            HARVEST_BEAT.fetch_add(1, Ordering::Relaxed);
            // What each address answered, so a failure names its cause.
            let mut why = net::Buf::<512>::new();
            for address in [mpu::ADDR_AD0_LOW, mpu::ADDR_AD0_HIGH] {
                dev.set_address(address);
                if !why.as_bytes().is_empty() {
                    let _ = why.write_str("; ");
                }
                if let Err(e) = dev.reset_only().await {
                    describe_mpu_error(&mut why, address, "no answer", e);
                    continue;
                }
                Timer::after(Duration::from_millis(100)).await;
                match dev.configure().await {
                    Ok(chip) => break 'probe (address, chip),
                    Err(e) => describe_mpu_error(&mut why, address, "setup failed", e),
                }
            }
            // Anything else on the bus? A device at another address means the
            // wires work and the part is not an MPU; nothing at all means no
            // device is electrically connected.
            let found = scan_bus(dev.bus_mut()).await;
            let _ = write!(why, "; bus scan: ");
            if found.2 {
                let _ = why.write_str("bus stuck or timing out (a line held low or shorted)");
            } else if found.1 == 0 {
                let _ = why.write_str("nothing answered");
            } else {
                let _ = why.write_str("found");
                for a in &found.0[..found.1.min(found.0.len())] {
                    let _ = write!(why, " 0x{a:02x}");
                }
            }
            let _ = write!(why, "; at boot: {}", wiring.as_str());

            {
                let mut guard = SHARED.lock().await;
                if let Some(sh) = guard.as_mut() {
                    sh.mpu_error = why;
                }
            }
            if why.as_bytes() != reported.as_bytes() {
                let mut line = net::Buf::<608>::new();
                let _ = write!(
                    line,
                    "WARN component=mpu reason=not_found detail=\"{}\" retrying_every=5s\r\n",
                    why.as_str()
                );
                queue_usb(line.as_bytes());
                reported = why;
            }

            // Until the MPU answers, keep every source that does not need it
            // running on the ESP32's own clock, so the hardware RNG, ADC,
            // radio and timing sources are measured and visible regardless.
            let mut tick = Ticker::every(Duration::from_millis(1));
            let until = Instant::now() + Duration::from_secs(5);
            while Instant::now() < until {
                tick.next().await;
                HARVEST_BEAT.fetch_add(1, Ordering::Relaxed);
                let released = {
                    let mut guard = SHARED.lock().await;
                    match guard.as_mut() {
                        Some(sh) => finish_frame(sh, &mut common),
                        None => None,
                    }
                };
                deliver(released);
            }
        };

        let _ = dev.bus_mut().apply_config(&i2c_config(run_hz));
        let set_link = |sh: &mut Shared, int_mode: &str| {
            sh.mpu_link.clear();
            let _ = write!(
                sh.mpu_link,
                "SDA=GPIO{} SCL=GPIO{}, {} kHz, INT {}",
                bus_pins.0,
                bus_pins.1,
                run_hz / 1000,
                int_mode
            );
        };
        {
            let mut guard = SHARED.lock().await;
            if let Some(sh) = guard.as_mut() {
                sh.mpu_ready = true;
                sh.mpu_address = detected_address;
                sh.mpu_chip = chip.name();
                sh.mpu_error.clear();
                set_link(sh, "on GPIO11");
            }
        }
        {
            let mut line = net::Buf::<96>::new();
            let _ = write!(
                line,
                "MPU state=ready chip={} address=0x{:02x} sda=GPIO{} scl=GPIO{} i2c_khz={}\r\n",
                chip.name(),
                detected_address,
                bus_pins.0,
                bus_pins.1,
                run_hz / 1000
            );
            queue_usb(line.as_bytes());
        }
        beat.reset();
        detector.reset();

        // ---- sample until the part goes quiet ----------------------------
        let mut level_window_max: u32 = 0;
        let mut gyro_window_max: u32 = 0;
        let mut level_window_frames: u32 = 0;
        let mut faults_in_a_row: u32 = 0;
        // Without a working INT wire the part is polled over I2C instead,
        // twice per sample period so no frame is missed.
        let mut polling = false;
        let mut empty_polls: u32 = 0;
        let mut poll_tick = Ticker::every(Duration::from_micros(500));
        loop {
            HARVEST_BEAT.fetch_add(1, Ordering::Relaxed);
            if faults_in_a_row >= 50 {
                if run_hz > 100_000 {
                    run_hz = 100_000;
                    queue_usb(b"WARN component=mpu reason=bus_errors_at_full_speed action=reprobe_at_100khz\r\n");
                }
                break;
            }

            // At 1 kHz a data-ready edge arrives every millisecond. A full
            // second of silence means either the INT wire is not connected, or
            // the part itself is gone (a loose connector, or a brownout that
            // reset its registers to sleep mode). Asking the part over I2C
            // tells the two apart: if it still answers, only INT is missing,
            // and sampling carries on by polling.
            if polling {
                poll_tick.next().await;
            } else if with_timeout(
                Duration::from_millis(cfg::MPU_STALL_MS),
                int_pin.wait_for_rising_edge(),
            )
            .await
            .is_err()
            {
                if dev.int_status().await.is_err() {
                    break;
                }
                polling = true;
                beat.reset();
                poll_tick = Ticker::every(Duration::from_micros(500));
                {
                    let mut guard = SHARED.lock().await;
                    if let Some(sh) = guard.as_mut() {
                        set_link(sh, "silent, polling over I2C (check the INT wire to GPIO11)");
                    }
                }
                queue_usb(b"WARN component=mpu reason=int_wire_silent mode=polling detail=\"no data-ready edges on GPIO11; sampling by polling, clock_beat paused\"\r\n");
                continue;
            }
            // Timestamp the edge before anything else touches the bus, so the
            // clock-beat and bus-timing samples are the same on every frame.
            let edge_us = esp_hal::time::Instant::now()
                .duration_since_epoch()
                .as_micros() as u32;
            let bus_start = edge_us;

            let (status, frame) = match dev.read_status_and_frame().await {
                Ok(r) => r,
                Err(_) => {
                    bus_faults = bus_faults.saturating_add(1);
                    faults_in_a_row += 1;
                    Timer::after(Duration::from_millis(10)).await;
                    continue;
                }
            };
            if status & mpu::INT_DATA_RDY == 0 {
                // While polling, a part that answers but never has data has
                // reset itself (a brownout puts it back to sleep): after a
                // second of that, go back and configure it again.
                if polling {
                    empty_polls += 1;
                    if empty_polls >= 2 * cfg::MPU_STALL_MS as u32 {
                        break;
                    }
                }
                continue;
            }
            empty_polls = 0;
            let bus_end = esp_hal::time::Instant::now()
                .duration_since_epoch()
                .as_micros() as u32;

            if !frame.plausible() {
                bus_faults = bus_faults.saturating_add(1);
                faults_in_a_row += 1;
                continue;
            }
            faults_in_a_row = 0;
            FRAMES.fetch_add(1, Ordering::Relaxed);

            // Motion: strums, headbangs, walking, swinging the neck. Every
            // frame over the threshold counts as a hit; debounce decides what
            // reaches the relay. Report the leading edge of a movement and
            // then hold off, rather than flooding the relay with events that
            // no longer mean anything individually.
            let reading = detector.push(
                frame.accel,
                frame.gyro,
                MOTION_HPF.load(Ordering::Relaxed),
                MOT_THR.load(Ordering::Relaxed),
                GYRO_THR.load(Ordering::Relaxed),
                scale,
            );
            let motion = reading.hit;
            level_window_max = level_window_max.max(reading.accel_mg);
            gyro_window_max = gyro_window_max.max(reading.gyro_dps10);
            level_window_frames += 1;
            if level_window_frames >= 250 {
                MOTION_LEVEL_MG.store(level_window_max, Ordering::Relaxed);
                GYRO_LEVEL_DPS10.store(gyro_window_max, Ordering::Relaxed);
                level_window_max = 0;
                gyro_window_max = 0;
                level_window_frames = 0;
            }
            if motion {
                MOTION_RAW.fetch_add(1, Ordering::Relaxed);
                let gap = Duration::from_millis(DEBOUNCE_MS.load(Ordering::Relaxed) as u64);
                let now = Instant::now();
                if last_motion.map_or(true, |t| now.duration_since(t) >= gap) {
                    last_motion = Some(now);
                    MOTION_EVENTS.fetch_add(1, Ordering::Relaxed);
                    let _ = STRUMS.try_send(());
                }
            }

            let released = {
                let mut guard = SHARED.lock().await;
                let Some(sh) = guard.as_mut() else {
                    continue;
                };
                sh.bus_faults = bus_faults;
                let sink = &mut common.sink;

                const ORDER: [SourceId; 7] = [
                    SourceId::AccelX,
                    SourceId::AccelY,
                    SourceId::AccelZ,
                    SourceId::GyroX,
                    SourceId::GyroY,
                    SourceId::GyroZ,
                    SourceId::MpuTemp,
                ];
                for (id, sample) in ORDER.iter().zip(frame.entropy_samples().iter()) {
                    sh.harvester.push(*id, *sample, sink);
                }

                // The clock beat is the MPU oscillator seen through INT edges.
                // A polled timestamp is the ESP32's own ticker, not that, so
                // nothing is pushed while polling.
                if !polling {
                    if let Some(sample) = beat.push(edge_us) {
                        sh.harvester.push(SourceId::ClockBeat, sample, sink);
                    }
                }
                sh.harvester
                    .push(SourceId::BusTiming, bus_end.wrapping_sub(bus_start) as u8, sink);
                if motion && !polling {
                    // Uncredited, and fed from every motion frame rather than
                    // the debounced events: the debounce is about what the
                    // relay sees, not about throwing away timing. Skipped while
                    // polling, where the timestamp is only the poll grid.
                    sh.harvester.push(SourceId::MotionTiming, edge_us as u8, sink);
                }

                // Gross orientation/motion is structured and correlated with
                // the low bytes, so it is mixed but never credited as an
                // independent source.
                let context = [
                    frame.accel[0].to_be_bytes()[0],
                    frame.accel[1].to_be_bytes()[0],
                    frame.accel[2].to_be_bytes()[0],
                    frame.gyro[0].to_be_bytes()[0],
                    frame.gyro[1].to_be_bytes()[0],
                    frame.gyro[2].to_be_bytes()[0],
                    frame.temp.to_be_bytes()[0],
                ];
                for sample in context {
                    sh.harvester.push(SourceId::MpuFrame, sample, sink);
                }

                finish_frame(sh, &mut common)
            };
            deliver(released);
        }

        // ---- the part went quiet -----------------------------------------
        MOTION_LEVEL_MG.store(0, Ordering::Relaxed);
        GYRO_LEVEL_DPS10.store(0, Ordering::Relaxed);
        {
            let mut guard = SHARED.lock().await;
            if let Some(sh) = guard.as_mut() {
                // Samples of an MPU source from before and after a re-probe
                // are not one stream, so such a capture ends here.
                if sh.harvester.tap.source.is_some_and(|id| id.needs_mpu()) {
                    end_dump(sh, "mpu_lost");
                }
                sh.mpu_ready = false;
                sh.mpu_link.clear();
                sh.mpu_error.clear();
                let _ = sh.mpu_error.write_str("lost contact with the MPU, re-probing");
            }
        }
        queue_usb(b"WARN component=mpu reason=lost_contact reprobing=1\r\n");
    }
}

/// Sampler state shared by the MPU-driven loop and the fallback clock.
struct Common {
    sink: Sha3Sink,
    rng: esp_hal::rng::Rng,
    adc: NoiseAdc,
    adc_pin: NoisePin,
    last_release: Instant,
}

/// The part of every sampling tick that does not involve the MPU: hardware
/// RNG, ADC noise, the radio/USB/network timing queue, raw capture draining,
/// and the release attempt. Runs with the shared state locked.
fn finish_frame(sh: &mut Shared, c: &mut Common) -> Option<KeyPacket> {
    let sink = &mut c.sink;

    // Espressif: true random only while the RF subsystem is on; otherwise
    // pseudo-random. So nothing is taken from it (and nothing credited)
    // until the radio is up.
    if RADIO_UP.load(Ordering::Relaxed) {
        let mut hw = [0u8; 8];
        c.rng.read(&mut hw);
        for sample in hw {
            sh.harvester.push(SourceId::HwRng, sample, sink);
        }
    }

    // One conversion on the unconnected ADC pin per tick; the low byte is
    // where the converter noise lives.
    let adc_raw = c.adc.read_blocking(&mut c.adc_pin);
    sh.harvester.push(SourceId::AdcNoise, adc_raw as u8, sink);

    while let Ok(aux) = AUX_SAMPLES.try_receive() {
        sh.harvester.push(aux.source, aux.sample, sink);
    }

    // Raw capture. Drain whatever the tap collected this tick, in order. The
    // stream is always contiguous: the first sample that cannot be delivered
    // ends the capture instead of leaving a gap.
    if let Some(source) = sh.harvester.tap.source {
        let left = DUMP_LEFT.load(Ordering::Relaxed);
        let take = (sh.harvester.tap.len as u32).min(left) as usize;
        let mut ended: Option<&'static str> = None;
        if sh.harvester.tap.overflow > 0 || DUMP_GAP.load(Ordering::Relaxed) {
            ended = Some("samples_lost_on_device");
        } else if take > 0 {
            let mut bytes = [0u8; entropy::TAP_LEN];
            bytes[..take].copy_from_slice(&sh.harvester.tap.buf[..take]);
            let chunk = DumpChunk::Data {
                source,
                len: take as u8,
                bytes,
            };
            if DUMP_CHUNKS.try_send(chunk).is_err() {
                ended = Some("usb_fell_behind");
            } else {
                DUMP_CAPTURED.fetch_add(take as u32, Ordering::Relaxed);
                DUMP_LEFT.store(left - take as u32, Ordering::Relaxed);
                if left - take as u32 == 0 {
                    ended = Some("done");
                }
            }
        }
        sh.harvester.tap.len = 0;
        if let Some(reason) = ended {
            end_dump(sh, reason);
        }
    }

    // Release. The floor of live credited sources is the owner's setting
    // (min_live); with the MPU missing only the hardware RNG, and ADC noise if
    // it has been assessed, can count toward it.
    if Instant::now().duration_since(c.last_release)
        >= Duration::from_millis(cfg::MIN_RELEASE_INTERVAL_MS)
    {
        let mut bytes = [0u8; cfg::KEY_BYTES];
        if sh
            .harvester
            .try_release(sh.min_live as usize, sink, &mut bytes)
        {
            c.last_release = Instant::now();
            return Some(KeyPacket { bytes });
        }
    }
    None
}

fn deliver(released: Option<KeyPacket>) {
    if let Some(packet) = released {
        // Neither consumer can stall sampling. A radio/host outage drops old
        // output; it never blocks or reuses conditioned material.
        let _ = NET_KEYS.try_send(packet);
        let _ = USB_KEYS.try_send(packet);
    }
}

fn i2c_config(hz: u32) -> esp_hal::i2c::master::Config {
    esp_hal::i2c::master::Config::default()
        .with_frequency(esp_hal::time::Rate::from_hz(hz))
        // The bus timeout is off by default on the S3, and its "maximum" is
        // tens of seconds. A short one turns a line held low by a
        // half-connected module into a prompt error instead of a stall.
        .with_timeout(esp_hal::i2c::master::BusTimeout::BusCycles(20))
}

/// Every 7-bit address that acknowledges a one-byte read. Returns up to eight
/// of them and the total count.
async fn scan_bus(bus: &mut HalI2c) -> ([u8; 8], usize, bool) {
    let mut found = [0u8; 8];
    let mut count = 0usize;
    // A stuck line makes every address fail slowly; stop at the first sign of
    // that, and cap the whole scan, so it can never hold up the watchdog.
    let scan = async {
        for addr in 0x08u8..=0x77 {
            HARVEST_BEAT.fetch_add(1, Ordering::Relaxed);
            let mut b = [0u8; 1];
            match bus.read_async(addr, &mut b).await {
                Ok(()) => {
                    if count < found.len() {
                        found[count] = addr;
                    }
                    count += 1;
                }
                Err(esp_hal::i2c::master::Error::AcknowledgeCheckFailed(_)) => {}
                Err(_) => return true,
            }
        }
        false
    };
    let stuck = with_timeout(Duration::from_secs(1), scan).await.unwrap_or(true);
    (found, count, stuck)
}

// ---------------------------------------------------------------------------
// Settings <-> live state
// ---------------------------------------------------------------------------

/// Everything the dashboard or a command can change, captured for flash.
fn snapshot(sh: &Shared) -> Settings {
    let mut h = [0u16; SOURCE_COUNT];
    for (slot, source) in h.iter_mut().zip(sh.harvester.sources.iter()) {
        *slot = source.h;
    }
    Settings {
        wifi: sh.wifi_credentials,
        strum_pin: sh.strum_pin,
        entropy_pin: sh.entropy_pin,
        strum_port: sh.strum_port,
        entropy_port: sh.entropy_port,
        udp_enabled: sh.udp_enabled,
        udp_control: sh.udp_control,
        debounce_ms: DEBOUNCE_MS.load(Ordering::Relaxed).min(persist::MAX_DEBOUNCE_MS as u32) as u16,
        mot_thr: sh.mot_thr,
        accel_hpf: sh.accel_hpf,
        gyro_thr: sh.gyro_thr,
        min_live: sh.min_live,
        h,
        admin_salt: sh.admin_salt,
        admin_hash: sh.admin_hash,
    }
}

/// Load stored settings over the compiled defaults. Only called at boot,
/// before the sampler or the radio has started.
fn apply_settings(sh: &mut Shared, s: &Settings) {
    sh.wifi_credentials = s.wifi;
    sh.strum_pin = s.strum_pin;
    sh.entropy_pin = s.entropy_pin;
    sh.strum_port = s.strum_port;
    sh.entropy_port = s.entropy_port;
    sh.udp_enabled = s.udp_enabled;
    sh.udp_control = s.udp_control;
    sh.mot_thr = s.mot_thr;
    sh.gyro_thr = s.gyro_thr;
    sh.accel_hpf = s.accel_hpf;
    sh.min_live = s.min_live;
    MOT_THR.store(s.mot_thr, Ordering::Relaxed);
    GYRO_THR.store(s.gyro_thr, Ordering::Relaxed);
    MOTION_HPF.store(s.accel_hpf, Ordering::Relaxed);
    sh.admin_salt = s.admin_salt;
    sh.admin_hash = s.admin_hash;
    DEBOUNCE_MS.store(s.debounce_ms as u32, Ordering::Relaxed);
    for (source, h) in sh.harvester.sources.iter_mut().zip(s.h.iter()) {
        if source.h != *h {
            // Crediting follows the assessment (and whether the source may be
            // credited at all), so it is recomputed rather than carried over.
            *source = entropy::SourceHealth::new(source.id, *h, true);
        }
    }
}

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------
//
// Two flash sectors at the start of the `nvs` data partition from the default
// espflash partition table. Nothing else in this firmware uses that partition.
// persist.rs decides what goes in a record and which copy to trust; this part
// only moves bytes.

const P_DIRTY: u32 = 1;
const P_NOW: u32 = 2;
const P_REBOOT: u32 = 4;
const P_FACTORY: u32 = 8;
static PERSIST_FLAGS: AtomicU32 = AtomicU32::new(0);
static PERSIST_WAKE: Signal<CriticalSectionRawMutex, ()> = Signal::new();

const SAVE_NEVER: u8 = 0;
const SAVE_SAVED: u8 = 1;
const SAVE_ERROR: u8 = 2;
const SAVE_UNAVAILABLE: u8 = 3;
const SAVE_CORRUPT: u8 = 4;
static SAVE_STATE: AtomicU8 = AtomicU8::new(SAVE_NEVER);
static SAVE_WRITES: AtomicU32 = AtomicU32::new(0);

fn persist_request(bits: u32) {
    PERSIST_FLAGS.fetch_or(bits, Ordering::Relaxed);
    PERSIST_WAKE.signal(());
}

fn mark_dirty() {
    persist_request(P_DIRTY);
}

/// The flash ROM routines want word-aligned buffers; an unaligned one is
/// bounced through a 4 KB stack copy instead.
#[repr(C, align(4))]
struct Aligned([u8; persist::RECORD_LEN]);

struct Store {
    base: u32,
    loaded: Loaded,
    /// What flash holds right now, so an unchanged snapshot costs no write.
    last: Option<Settings>,
}

struct Boot {
    store: Option<Store>,
    settings: Option<Settings>,
}

fn load_settings(flash: &mut FlashStorage<'static>) -> Boot {
    use esp_bootloader_esp_idf::partitions::{
        read_partition_table, DataPartitionSubType, PartitionType, PARTITION_TABLE_MAX_LEN,
    };

    let mut table = [0u8; PARTITION_TABLE_MAX_LEN];
    let region = match read_partition_table(flash, &mut table) {
        Ok(pt) => match pt.find_partition(PartitionType::Data(DataPartitionSubType::Nvs)) {
            Ok(Some(p)) if p.len() >= persist::SLOT_SIZE * persist::SLOT_COUNT as u32 => {
                Some(p.offset())
            }
            _ => None,
        },
        Err(_) => None,
    };
    let Some(base) = region else {
        SAVE_STATE.store(SAVE_UNAVAILABLE, Ordering::Relaxed);
        queue_usb(b"SETTINGS state=unavailable reason=no_nvs_partition using=compiled_defaults\r\n");
        return Boot {
            store: None,
            settings: None,
        };
    };

    let mut decoded: [Option<Settings>; persist::SLOT_COUNT] = [None; persist::SLOT_COUNT];
    let mut results = [Err(persist::DecodeError::Blank); persist::SLOT_COUNT];
    for slot in 0..persist::SLOT_COUNT {
        let mut raw = Aligned([0xFF; persist::RECORD_LEN]);
        let addr = base + slot as u32 * persist::SLOT_SIZE;
        results[slot] = match flash.read_nor(addr, &mut raw.0) {
            Ok(()) => match persist::decode(&raw.0) {
                Ok((settings, seq)) => {
                    decoded[slot] = Some(settings);
                    Ok(seq)
                }
                Err(e) => Err(e),
            },
            Err(_) => Err(persist::DecodeError::BadCrc),
        };
    }

    let loaded = persist::choose(results);
    let settings = match loaded {
        Loaded::Found { slot, seq } => {
            SAVE_STATE.store(SAVE_SAVED, Ordering::Relaxed);
            let mut line = net::Buf::<96>::new();
            let _ = write!(line, "SETTINGS state=loaded slot={slot} seq={seq}\r\n");
            queue_usb(line.as_bytes());
            decoded[slot]
        }
        Loaded::Blank => {
            SAVE_STATE.store(SAVE_NEVER, Ordering::Relaxed);
            queue_usb(b"SETTINGS state=never_saved using=compiled_defaults\r\n");
            None
        }
        Loaded::Corrupt => {
            SAVE_STATE.store(SAVE_CORRUPT, Ordering::Relaxed);
            queue_usb(b"WARN component=settings reason=no_valid_record using=compiled_defaults\r\n");
            None
        }
    };
    Boot {
        store: Some(Store {
            base,
            loaded,
            last: settings,
        }),
        settings,
    }
}

fn write_record(
    flash: &mut FlashStorage<'static>,
    store: &mut Store,
    settings: &Settings,
) -> Result<(), &'static str> {
    persist::validate(settings)?;
    let (slot, seq) = persist::next_write(store.loaded);
    let mut record = Aligned([0u8; persist::RECORD_LEN]);
    persist::encode(settings, seq, &mut record.0);

    let addr = store.base + slot as u32 * persist::SLOT_SIZE;
    flash
        .erase(addr, addr + persist::SLOT_SIZE)
        .map_err(|_| "erase")?;
    flash.write_nor(addr, &record.0).map_err(|_| "write")?;

    // Read it back and decode it with the same code the next boot will use.
    // A save is only reported once the bytes in flash are known to load.
    let mut back = Aligned([0u8; persist::RECORD_LEN]);
    flash.read_nor(addr, &mut back.0).map_err(|_| "readback")?;
    match persist::decode(&back.0) {
        Ok((stored, stored_seq)) if stored == *settings && stored_seq == seq => {}
        _ => return Err("verify"),
    }

    store.loaded = Loaded::Found { slot, seq };
    store.last = Some(*settings);
    Ok(())
}

async fn save_current(flash: &mut FlashStorage<'static>, store: &mut Option<Store>) {
    let Some(store) = store.as_mut() else {
        return;
    };
    let current = {
        let guard = SHARED.lock().await;
        let Some(sh) = guard.as_ref() else {
            return;
        };
        snapshot(sh)
    };
    if store.last == Some(current) {
        SAVE_STATE.store(SAVE_SAVED, Ordering::Relaxed);
        return;
    }
    match write_record(flash, store, &current) {
        Ok(()) => {
            SAVE_STATE.store(SAVE_SAVED, Ordering::Relaxed);
            SAVE_WRITES.fetch_add(1, Ordering::Relaxed);
            if let Loaded::Found { slot, seq } = store.loaded {
                let mut line = net::Buf::<96>::new();
                let _ = write!(line, "SETTINGS state=saved slot={slot} seq={seq}\r\n");
                queue_usb(line.as_bytes());
            }
        }
        Err(why) => {
            SAVE_STATE.store(SAVE_ERROR, Ordering::Relaxed);
            let mut line = net::Buf::<96>::new();
            let _ = write!(line, "ERR component=settings reason=save_{why}\r\n");
            queue_usb(line.as_bytes());
        }
    }
}

#[embassy_executor::task]
async fn persist_task(mut flash: FlashStorage<'static>, mut store: Option<Store>) {
    let mut last_write: Option<Instant> = None;
    loop {
        if PERSIST_FLAGS.load(Ordering::Relaxed) == 0 {
            PERSIST_WAKE.wait().await;
        }

        // Coalesce: wait for a quiet period after the last change, unless an
        // explicit save, reboot or factory reset is asking for it now.
        let started = Instant::now();
        loop {
            let flags = PERSIST_FLAGS.load(Ordering::Relaxed);
            if flags == 0 || flags & (P_NOW | P_REBOOT | P_FACTORY) != 0 {
                break;
            }
            let waited = Instant::now().duration_since(started);
            let max = Duration::from_millis(cfg::SAVE_MAX_DEFER_MS);
            if waited >= max {
                break;
            }
            let quiet = Duration::from_millis(cfg::SAVE_QUIET_MS).min(max - waited);
            if let Either::First(_) = select(Timer::after(quiet), PERSIST_WAKE.wait()).await {
                break;
            }
        }

        // Hard floor between flash writes, whatever asked for them. A script
        // hammering SAVE gets one write every few seconds at most, which keeps
        // wear negligible and keeps interrupts from being masked back to back.
        if let Some(at) = last_write {
            let since = Instant::now().duration_since(at);
            let floor = Duration::from_millis(cfg::SAVE_MIN_INTERVAL_MS);
            if since < floor {
                Timer::after(floor - since).await;
            }
        }

        let flags = PERSIST_FLAGS.swap(0, Ordering::Relaxed);

        if flags & P_FACTORY != 0 {
            if let Some(s) = store.as_ref() {
                let end = s.base + persist::SLOT_SIZE * persist::SLOT_COUNT as u32;
                if flash.erase(s.base, end).is_err() {
                    queue_usb(b"ERR component=settings reason=factory_erase_failed\r\n");
                }
            }
            queue_usb(b"SETTINGS state=erased rebooting=1\r\n");
            Timer::after(Duration::from_millis(500)).await;
            esp_hal::system::software_reset();
        }

        if flags & (P_DIRTY | P_NOW | P_REBOOT) != 0 {
            let before = SAVE_WRITES.load(Ordering::Relaxed);
            save_current(&mut flash, &mut store).await;
            if SAVE_WRITES.load(Ordering::Relaxed) != before
                || SAVE_STATE.load(Ordering::Relaxed) == SAVE_ERROR
            {
                last_write = Some(Instant::now());
            }
        }

        if flags & P_REBOOT != 0 {
            queue_usb(b"SYSTEM state=rebooting\r\n");
            // Long enough for the command reply to leave over HTTP or USB.
            Timer::after(Duration::from_millis(500)).await;
            esp_hal::system::software_reset();
        }
    }
}

// ---------------------------------------------------------------------------
// Admin password
// ---------------------------------------------------------------------------

const ADMIN_DOMAIN: &[u8] = b"GuitaRNG/nocturnus/admin/SHA3-256/v1";

fn admin_digest(salt: &[u8; 16], password: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(ADMIN_DOMAIN);
    hasher.update(salt);
    hasher.update(password);
    let mut out = [0u8; 32];
    out.copy_from_slice(&hasher.finalize());
    out
}

/// Check a dashboard password. An all-zero stored hash means no password was
/// ever set, and the compiled default applies.
pub async fn verify_admin(password: &[u8]) -> bool {
    let (salt, hash) = {
        let guard = SHARED.lock().await;
        let Some(sh) = guard.as_ref() else {
            return false;
        };
        (sh.admin_salt, sh.admin_hash)
    };
    if hash.iter().all(|b| *b == 0) {
        return net::ct_eq(password, cfg::ADMIN_DEFAULT_PASSWORD.as_bytes());
    }
    net::ct_eq(&admin_digest(&salt, password), &hash)
}

async fn set_admin_password(password: &net::AdminPassword) -> Result<(), &'static str> {
    let mut salt = [0u8; 16];
    esp_hal::rng::Rng::new().read(&mut salt);
    let hash = admin_digest(&salt, password.as_bytes());
    let mut guard = SHARED.lock().await;
    let sh = guard.as_mut().ok_or("not_ready")?;
    sh.admin_salt = salt;
    sh.admin_hash = hash;
    drop(guard);
    mark_dirty();
    Ok(())
}

// ---------------------------------------------------------------------------
// Control plane and reports
// ---------------------------------------------------------------------------

/// Where a command came from. USB needs physical access and the dashboard
/// needs the password; the UDP control port needs neither, so it is refused
/// anything that could lock the owner out or take the node down.
#[derive(Copy, Clone, PartialEq, Eq)]
pub enum Origin {
    Usb,
    Udp,
    Web,
}

async fn request_wifi_update(credentials: net::WifiCredentials) -> Result<(), &'static str> {
    let mut guard = SHARED.lock().await;
    let sh = guard.as_mut().ok_or("not_ready")?;
    WIFI_UPDATES
        .try_send(credentials)
        .map_err(|_| "wifi_update_busy")?;
    sh.wifi_credentials = credentials;
    sh.wifi_connected = false;
    sh.targets_dirty = true;
    drop(guard);
    mark_dirty();
    Ok(())
}

pub async fn apply_command(line: &str, origin: Origin, reply: &mut net::Buf<512>) {
    reply.clear();

    if origin == Origin::Udp {
        let open = SHARED
            .lock()
            .await
            .as_ref()
            .map(|sh| sh.udp_control)
            .unwrap_or(false);
        if !open {
            let _ = reply.write_str("ERR reason=udp_control_closed use=dashboard_or_usb");
            return;
        }
    }

    if let Some(action) = net::parse_admin_command(line) {
        if origin == Origin::Udp {
            let _ = reply.write_str("ERR reason=pass_not_allowed_over_udp");
            return;
        }
        match action {
            net::AdminAction::Set(password) => match set_admin_password(&password).await {
                Ok(()) => {
                    let _ = reply.write_str("OK admin_password=changed");
                }
                Err(why) => {
                    let _ = write!(reply, "ERR reason={why}");
                }
            },
            net::AdminAction::Err(why) => {
                let _ = write!(reply, "ERR reason={why}");
            }
        }
        return;
    }

    if let Some(action) = net::parse_wifi_command(line) {
        // Anyone on the hotspot can reach UDP 5013. Now that settings survive
        // a reboot, a Wi-Fi change from there could keep the node off the
        // hotspot for good, so UDP may read the Wi-Fi state but not change it.
        if origin == Origin::Udp && !matches!(action, net::WifiAction::Get) {
            let _ = reply.write_str("ERR reason=wifi_change_not_allowed_over_udp use=dashboard_or_usb");
            return;
        }
        match action {
            net::WifiAction::Get => {
                let guard = SHARED.lock().await;
                let Some(sh) = guard.as_ref() else {
                    let _ = reply.write_str("ERR reason=not_ready");
                    return;
                };
                let _ = write!(
                    reply,
                    "OK wifi_ssid=\"{}\" connected={} persistent=1",
                    sh.wifi_credentials.ssid(),
                    if sh.wifi_connected { 1 } else { 0 },
                );
            }
            net::WifiAction::Err(why) => {
                let _ = write!(reply, "ERR reason={why}");
            }
            net::WifiAction::Defaults => {
                let Ok(credentials) = net::WifiCredentials::new(cfg::WIFI_SSID, cfg::WIFI_PASSWORD)
                else {
                    let _ = reply.write_str("ERR reason=bad_compiled_wifi_defaults");
                    return;
                };
                if let Err(why) = request_wifi_update(credentials).await {
                    let _ = write!(reply, "ERR reason={why}");
                    return;
                }
                let _ = write!(
                    reply,
                    "OK wifi_ssid=\"{}\" reconnecting=1 persistent=1",
                    credentials.ssid(),
                );
            }
            net::WifiAction::Set(credentials) => {
                if let Err(why) = request_wifi_update(credentials).await {
                    let _ = write!(reply, "ERR reason={why}");
                    return;
                }
                let _ = write!(
                    reply,
                    "OK wifi_ssid=\"{}\" reconnecting=1 persistent=1",
                    credentials.ssid(),
                );
            }
        }
        return;
    }

    let cmd = net::parse_command(line);
    match cmd {
        net::Command::Help => {
            let _ = reply.write_str(net::HELP_TEXT);
            return;
        }
        net::Command::Stats => {
            if origin == Origin::Usb {
                print_stats_usb().await;
                let _ = reply.write_str("OK stats=printed");
            } else {
                let _ = reply.write_str("OK stats=on_the_dashboard_sources_panel");
            }
            return;
        }
        net::Command::StatsReset => {
            if origin == Origin::Udp {
                let _ = reply.write_str("ERR reason=stats_reset_not_allowed_over_udp");
                return;
            }
            let mut guard = SHARED.lock().await;
            if let Some(sh) = guard.as_mut() {
                sh.harvester.reset_measurements();
            }
            let _ = reply.write_str("OK measurements=reset");
            return;
        }
        net::Command::Dump(index, count) => {
            // Raw samples leave only by cable. Over the air they would be one
            // sniffer away from anyone on the hotspot.
            if origin != Origin::Usb {
                let _ = reply.write_str("ERR reason=dump_is_usb_only");
                return;
            }
            let mut guard = SHARED.lock().await;
            let Some(sh) = guard.as_mut() else {
                let _ = reply.write_str("ERR reason=not_ready");
                return;
            };
            if sh.harvester.tap.source.is_some() {
                let _ = reply.write_str("ERR reason=dump_already_running use=DUMP_STOP");
                return;
            }
            let id = SourceId::ALL[index];
            if id.needs_mpu() && !sh.mpu_ready {
                let _ = reply.write_str("ERR reason=mpu_not_running");
                return;
            }
            DUMP_CAPTURED.store(0, Ordering::Relaxed);
            DUMP_GAP.store(false, Ordering::Relaxed);
            DUMP_LEFT.store(count, Ordering::Relaxed);
            sh.harvester.tap = entropy::Tap::new();
            sh.harvester.tap.source = Some(id);
            DUMP_SOURCE.store(id as u8, Ordering::Relaxed);
            let _ = write!(
                reply,
                "OK dump={} samples={} releases=paused format=RAW:<source>:<hex>",
                id.name(),
                count
            );
            return;
        }
        net::Command::DumpStop => {
            if origin != Origin::Usb {
                let _ = reply.write_str("ERR reason=dump_is_usb_only");
                return;
            }
            let mut guard = SHARED.lock().await;
            match guard.as_mut() {
                Some(sh) if sh.harvester.tap.source.is_some() => {
                    end_dump(sh, "stopped");
                    let _ = reply.write_str("OK dump=stopped releases=resumed");
                }
                _ => {
                    let _ = reply.write_str("OK dump=not_running");
                }
            }
            return;
        }
        net::Command::Err(why) => {
            let _ = write!(reply, "ERR reason={why}");
            return;
        }
        net::Command::Save => {
            if origin == Origin::Udp {
                let _ = reply.write_str("ERR reason=save_not_allowed_over_udp changes_save_automatically=1");
                return;
            }
            if SAVE_STATE.load(Ordering::Relaxed) == SAVE_UNAVAILABLE {
                let _ = reply.write_str("ERR reason=no_settings_partition");
                return;
            }
            persist_request(P_NOW);
            let _ = reply.write_str("OK save=now");
            return;
        }
        net::Command::Reboot => {
            if origin == Origin::Udp {
                let _ = reply.write_str("ERR reason=reboot_not_allowed_over_udp");
                return;
            }
            persist_request(P_REBOOT);
            let _ = reply.write_str("OK rebooting=1 pending_changes=saving_first");
            return;
        }
        net::Command::Factory => {
            if origin == Origin::Udp {
                let _ = reply.write_str("ERR reason=factory_not_allowed_over_udp");
                return;
            }
            persist_request(P_FACTORY);
            let _ = reply.write_str("OK factory=1 settings=erasing rebooting=1");
            return;
        }
        net::Command::Get | net::Command::Set(_) => {}
    }

    let mut guard = SHARED.lock().await;
    let Some(sh) = guard.as_mut() else {
        let _ = reply.write_str("ERR reason=not_ready");
        return;
    };

    if let net::Command::Set(ops) = cmd {
        // Check the whole SET before applying any of it, so a refused line
        // changes nothing.
        let mut strum_port = sh.strum_port;
        let mut entropy_port = sh.entropy_port;
        for op in ops.iter().flatten() {
            match *op {
                net::Op::StrumPort(port) => strum_port = port,
                net::Op::EntropyPort(port) => entropy_port = port,
                // Assessments and the release floor decide how much credit a
                // key is allowed to claim, and they persist, so they are not
                // taken from an unauthenticated port.
                net::Op::SetH(..) if origin == Origin::Udp => {
                    let _ = reply.write_str("ERR reason=h_not_allowed_over_udp use=dashboard_or_usb");
                    return;
                }
                net::Op::MinLive(_) if origin == Origin::Udp => {
                    let _ = reply.write_str("ERR reason=min_live_not_allowed_over_udp use=dashboard_or_usb");
                    return;
                }
                _ => {}
            }
        }
        if strum_port == entropy_port {
            let _ = reply.write_str("ERR reason=ports_must_differ");
            return;
        }

        for op in ops.iter().flatten() {
            match *op {
                net::Op::StrumTarget(target) => {
                    sh.strum_pin = target;
                    sh.targets_dirty = true;
                }
                net::Op::EntropyTarget(target) => {
                    sh.entropy_pin = target;
                    sh.targets_dirty = true;
                }
                net::Op::StrumPort(port) => sh.strum_port = port,
                net::Op::EntropyPort(port) => sh.entropy_port = port,
                net::Op::UdpEnable(enabled) => sh.udp_enabled = enabled,
                net::Op::UdpControl(enabled) => sh.udp_control = enabled,
                net::Op::MinLive(n) => sh.min_live = n,
                net::Op::Debounce(ms) => DEBOUNCE_MS.store(ms, Ordering::Relaxed),
                net::Op::MotionThreshold(thr) => {
                    MOT_THR.store(thr, Ordering::Relaxed);
                    sh.mot_thr = thr;
                }
                net::Op::GyroThreshold(thr) => {
                    GYRO_THR.store(thr, Ordering::Relaxed);
                    sh.gyro_thr = thr;
                }
                net::Op::Hpf(hpf) => {
                    MOTION_HPF.store(hpf, Ordering::Relaxed);
                    sh.accel_hpf = hpf;
                }
                net::Op::ResetHealth(which) => {
                    match which {
                        Some(index) => sh.harvester.sources[index].reset(),
                        None => {
                            for source in sh.harvester.sources.iter_mut() {
                                source.reset();
                            }
                        }
                    }
                    sh.harvester.discard_credit();
                }
                net::Op::SetH(index, h) => {
                    let id = sh.harvester.sources[index].id;
                    sh.harvester.sources[index] = entropy::SourceHealth::new(id, h, true);
                    sh.harvester.discard_credit();
                }
            }
        }
        // Every SET is a candidate for flash. An unchanged snapshot is
        // recognised by the saver and costs no write.
        mark_dirty();
    }

    let status = net::Status {
        strum_pin: sh.strum_pin,
        entropy_pin: sh.entropy_pin,
        strum: sh.strum,
        entropy: sh.entropy,
        strum_port: sh.strum_port,
        entropy_port: sh.entropy_port,
        udp_enabled: sh.udp_enabled,
        live_credited: sh.harvester.live_credited(),
        budget_percent: sh.harvester.budget.percent(),
        releases: sh.harvester.budget.releases,
    };
    net::format_status(reply, &status);
}

fn save_state_name() -> &'static str {
    if PERSIST_FLAGS.load(Ordering::Relaxed) & (P_DIRTY | P_NOW) != 0 {
        return "pending";
    }
    match SAVE_STATE.load(Ordering::Relaxed) {
        SAVE_SAVED => "saved",
        SAVE_ERROR => "error",
        SAVE_UNAVAILABLE => "unavailable",
        SAVE_CORRUPT => "corrupt",
        _ => "never",
    }
}

async fn format_health(out: &mut net::Buf<1024>) {
    let guard = SHARED.lock().await;
    out.clear();
    let Some(sh) = guard.as_ref() else {
        let _ = out.write_str("HEALTH state=not_ready\r\n");
        return;
    };

    let _ = write!(
        out,
        "HEALTH node={} id={} conditioner=SHA3-512 tests=RCT,APT,MARKOV wifi={} mpu={} mpu_addr=0x{:02x} live={} budget={}% keys={} bus_faults={}",
        cfg::NODE_NAME,
        cfg::NODE_CALLSIGN,
        if sh.wifi_connected { 1 } else { 0 },
        if sh.mpu_ready { 1 } else { 0 },
        sh.mpu_address,
        sh.harvester.live_credited(),
        sh.harvester.budget.percent(),
        sh.harvester.budget.releases,
        sh.bus_faults,
    );
    for source in sh.harvester.sources.iter() {
        let _ = write!(
            out,
            " {}={}:r{}:a{}:m{}",
            source.id.name(),
            verdict_char(source.verdict),
            source.rct.failures,
            source.apt.failures,
            source.markov.last_h_q8,
        );
    }
    // Appended after the original fields so nothing that reads them by
    // position moves.
    let _ = write!(
        out,
        " debounce={}ms mot_thr={} hpf={} settings={} reset={} gyro_thr={}",
        DEBOUNCE_MS.load(Ordering::Relaxed),
        sh.mot_thr,
        sh.accel_hpf,
        save_state_name(),
        sh.reset_reason,
        sh.gyro_thr,
    );
    let _ = out.write_str("\r\n");
}

// ---------------------------------------------------------------------------
// Dashboard status document
// ---------------------------------------------------------------------------
//
// Everything is copied out under the lock and formatted after it is released,
// so a phone polling once a second never holds the sampler up. The JSON itself
// is built in net.rs, where it is tested on the host.

/// One source's health and estimates, as the dashboard and STATS show them.
fn source_row(h: &Harvester, i: usize) -> net::SourceRow {
    let source = &h.sources[i];
    let stats = &h.stats[i];
    let est = stats.last.unwrap_or(entropy::Estimate {
        n: 0,
        shannon_q8: 0,
        min_q8: 0,
        distinct: 0,
    });
    net::SourceRow {
        name: source.id.name(),
        verdict: verdict_char(source.verdict),
        credited: source.credited,
        h: source.h,
        rct: source.rct.failures,
        apt: source.apt.failures,
        // u16::MAX: no Markov window completed yet (distinct from a real 0).
        markov: if source.markov.windows == 0 { u16::MAX } else { source.markov.last_h_q8 },
        est_n: est.n as u16,
        shannon: est.shannon_q8,
        min: est.min_q8,
        progress: stats.progress(),
        window: stats.window(),
        rct_max: source.rct.max_run,
        rct_cut: source.rct.cutoff(),
        apt_max: source.apt.max_matches,
        apt_cut: source.apt.cutoff(),
        tot_n: stats.total.map_or(0, |t| t.n),
        tot_shannon: stats.total.map_or(0, |t| t.shannon_q8),
        tot_min: stats.total.map_or(0, |t| t.min_q8),
        funded_bits: h.funded[i] / entropy::H_UNIT as u64,
    }
}

fn output_row(h: &Harvester) -> net::OutputRow {
    let o = &h.output;
    let est = o.stats.last;
    net::OutputRow {
        bytes: o.bytes,
        est_n: est.map_or(0, |e| e.n as u16),
        shannon: est.map_or(0, |e| e.shannon_q8),
        min: est.map_or(0, |e| e.min_q8),
        progress: o.stats.progress(),
        window: o.stats.window(),
        markov: if o.markov.windows == 0 { u16::MAX } else { o.markov.last_h_q8 },
        rct_max: o.rct.max_run,
        rct_cut: o.rct.cutoff(),
        rct_fail: o.rct.failures,
        apt_max: o.apt.max_matches,
        apt_cut: o.apt.cutoff(),
        apt_fail: o.apt.failures,
        tot_n: o.stats.total.map_or(0, |t| t.n),
        tot_shannon: o.stats.total.map_or(0, |t| t.shannon_q8),
        tot_min: o.stats.total.map_or(0, |t| t.min_q8),
    }
}

/// STATS over USB: one line per source, then the output.
async fn print_stats_usb() {
    let (rows, output) = {
        let guard = SHARED.lock().await;
        let Some(sh) = guard.as_ref() else {
            return;
        };
        let rows: [net::SourceRow; SOURCE_COUNT] =
            core::array::from_fn(|i| source_row(&sh.harvester, i));
        (rows, output_row(&sh.harvester))
    };
    // Bits to two decimals from 1/256-bit fixed point, without floats.
    struct Q8(u32);
    impl core::fmt::Display for Q8 {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            let hundredths = (self.0 * 100 + 128) / 256;
            write!(f, "{}.{:02}", hundredths / 100, hundredths % 100)
        }
    }
    // Markov is per raw bit; x8 gives bits per 8-bit sample.
    struct MarkovQ8(u16);
    impl core::fmt::Display for MarkovQ8 {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            if self.0 == u16::MAX {
                f.write_str("-")
            } else {
                write!(f, "{}", Q8(self.0 as u32 * 8))
            }
        }
    }
    for r in rows.iter() {
        let mut line = net::Buf::<320>::new();
        let _ = write!(
            line,
            "STAT source={} credited={} verdict={} assessed={} ",
            r.name,
            r.credited as u8,
            r.verdict,
            Q8(r.h as u32)
        );
        if r.tot_n == 0 {
            let _ = write!(line, "total_min=- total_shannon=- total_n=0");
        } else {
            let _ = write!(
                line,
                "total_min={} total_shannon={} total_n={}",
                Q8(r.tot_min as u32),
                Q8(r.tot_shannon as u32),
                r.tot_n
            );
        }
        if r.est_n == 0 {
            let _ = write!(line, " window=collecting:{}/{}", r.progress, r.window);
        } else {
            let _ = write!(line, " window_min={} window_shannon={}", Q8(r.min as u32), Q8(r.shannon as u32));
        }
        let _ = write!(
            line,
            " markov={} rct={}/{}:{} apt={}/{}:{} funded_bits={}\r\n",
            MarkovQ8(r.markov),
            r.rct_max,
            r.rct_cut,
            r.rct,
            r.apt_max,
            r.apt_cut,
            r.apt,
            r.funded_bits
        );
        // Bounded, so a host that closes the port mid-report cannot wedge the
        // USB command reader.
        if with_timeout(Duration::from_secs(1), USB_TEXT.send(UsbText::from_slice(line.as_bytes())))
            .await
            .is_err()
        {
            return;
        }
    }
    let mut line = net::Buf::<256>::new();
    let _ = write!(line, "STAT source=output bytes={} ", output.bytes);
    if output.tot_n == 0 {
        let _ = write!(line, "total_min=- total_shannon=- total_n=0 collecting={}/{}", output.progress, output.window);
    } else {
        let _ = write!(
            line,
            "total_min={} total_shannon={} total_n={}",
            Q8(output.tot_min as u32),
            Q8(output.tot_shannon as u32),
            output.tot_n
        );
    }
    let _ = write!(
        line,
        " markov={} rct={}/{}:{} apt={}/{}:{}\r\n",
        MarkovQ8(output.markov),
        output.rct_max,
        output.rct_cut,
        output.rct_fail,
        output.apt_max,
        output.apt_cut,
        output.apt_fail
    );
    let _ = with_timeout(Duration::from_secs(1), USB_TEXT.send(UsbText::from_slice(line.as_bytes()))).await;
}

pub async fn status_json(out: &mut net::Buf<{ net::STATUS_JSON_LEN }>) {

    let guard = SHARED.lock().await;
    let Some(sh) = guard.as_ref() else {
        drop(guard);
        out.clear();
        let _ = out.write_str("{\"ready\":false}");
        return;
    };
    let rows: [net::SourceRow; SOURCE_COUNT] =
        core::array::from_fn(|i| source_row(&sh.harvester, i));
    let output = output_row(&sh.harvester);
    let dump = sh
        .harvester
        .tap
        .source
        .map(|id| (id.name(), DUMP_LEFT.load(Ordering::Relaxed)));
    let credentials = sh.wifi_credentials;
    let mpu_error = sh.mpu_error;
    let mpu_link = sh.mpu_link;
    let mut d = net::Dashboard {
        uptime_ms: Instant::now().as_millis(),
        admin_default: sh.admin_hash.iter().all(|b| *b == 0),
        reset: sh.reset_reason,
        live: sh.harvester.live_credited(),
        min_live: sh.min_live as usize,
        keys: sh.harvester.budget.releases,
        budget: sh.harvester.budget.percent(),
        motion_raw: MOTION_RAW.load(Ordering::Relaxed),
        motion_events: MOTION_EVENTS.load(Ordering::Relaxed),
        mpu_ready: sh.mpu_ready,
        mpu_addr: sh.mpu_address,
        mpu_chip: sh.mpu_chip,
        mpu_error: "",
        mpu_link: "",
        motion_level_mg: MOTION_LEVEL_MG.load(Ordering::Relaxed),
        gyro_level_dps10: GYRO_LEVEL_DPS10.load(Ordering::Relaxed),
        frames: FRAMES.load(Ordering::Relaxed),
        faults: sh.bus_faults,
        mot_thr: sh.mot_thr,
        gyro_thr: sh.gyro_thr,
        debounce_ms: DEBOUNCE_MS.load(Ordering::Relaxed),
        hpf: sh.accel_hpf,
        sources: &[],
        output,
        dump,
        ssid: "",
        wifi_up: sh.wifi_connected,
        ip: sh.sta_ip,
        gw: sh.sta_gw,
        rssi: RSSI.load(Ordering::Relaxed) as i8,
        strum: sh.strum,
        strum_pin: sh.strum_pin,
        entropy: sh.entropy,
        entropy_pin: sh.entropy_pin,
        strum_port: sh.strum_port,
        entropy_port: sh.entropy_port,
        udp: sh.udp_enabled,
        udpctl: sh.udp_control,
        sent_entropy: SENT_ENTROPY.load(Ordering::Relaxed),
        sent_strum: SENT_STRUM.load(Ordering::Relaxed),
        sent_heartbeat: SENT_HEARTBEAT.load(Ordering::Relaxed),
        send_errors: SEND_ERRORS.load(Ordering::Relaxed),
        save_state: save_state_name(),
        save_writes: SAVE_WRITES.load(Ordering::Relaxed),
        wdt: WDT_ARMED.load(Ordering::Relaxed),
    };
    drop(guard);

    d.sources = &rows;
    d.ssid = credentials.ssid();
    d.mpu_error = mpu_error.as_str();
    d.mpu_link = mpu_link.as_str();
    net::format_dashboard_json(out, &d);
}

// ---------------------------------------------------------------------------
// Native USB Serial/JTAG
// ---------------------------------------------------------------------------

fn base64_32(input: &[u8; 32], output: &mut [u8; 44]) {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut i = 0usize;
    let mut o = 0usize;
    while i + 3 <= input.len() {
        let n = ((input[i] as u32) << 16) | ((input[i + 1] as u32) << 8) | input[i + 2] as u32;
        output[o] = TABLE[((n >> 18) & 63) as usize];
        output[o + 1] = TABLE[((n >> 12) & 63) as usize];
        output[o + 2] = TABLE[((n >> 6) & 63) as usize];
        output[o + 3] = TABLE[(n & 63) as usize];
        i += 3;
        o += 4;
    }
    let n = (input[30] as u32) << 16 | (input[31] as u32) << 8;
    output[40] = TABLE[((n >> 18) & 63) as usize];
    output[41] = TABLE[((n >> 12) & 63) as usize];
    output[42] = TABLE[((n >> 6) & 63) as usize];
    output[43] = b'=';
}

#[embassy_executor::task]
async fn usb_tx_task(mut tx: UsbSerialJtagTx<'static, Async>) {
    let mut health_tick = Ticker::every(Duration::from_millis(cfg::USB_HEALTH_INTERVAL_MS));
    loop {
        match select4(
            USB_KEYS.receive(),
            USB_TEXT.receive(),
            health_tick.next(),
            DUMP_CHUNKS.receive(),
        )
        .await
        {
            Either4::Fourth(DumpChunk::Data { source, len, bytes }) => {
                // RAW:<source>:<hex of each sample, in order>. Uppercase so
                // coreutils `basenc --base16 -d` decodes it with nothing else
                // installed.
                const HEX: &[u8; 16] = b"0123456789ABCDEF";
                let mut line = [0u8; 24 + 2 * entropy::TAP_LEN];
                let mut at = 0usize;
                for &b in b"RAW:".iter().chain(source.name().as_bytes()).chain(b":".iter()) {
                    line[at] = b;
                    at += 1;
                }
                for &b in &bytes[..len as usize] {
                    line[at] = HEX[(b >> 4) as usize];
                    line[at + 1] = HEX[(b & 15) as usize];
                    at += 2;
                }
                line[at] = b'\r';
                line[at + 1] = b'\n';
                let _ = tx.write_all(&line[..at + 2]).await;
                let _ = tx.flush().await;
            }
            Either4::Fourth(DumpChunk::Done {
                source,
                captured,
                reason,
            }) => {
                let mut report = net::Buf::<160>::new();
                let _ = write!(
                    report,
                    "DUMP state={} source={} samples={} releases=resumed\r\n",
                    reason,
                    source.name(),
                    captured
                );
                let _ = tx.write_all(report.as_bytes()).await;
                let _ = tx.flush().await;
            }
            Either4::First(packet) => {
                let mut encoded = [0u8; 44];
                base64_32(&packet.bytes, &mut encoded);
                let mut line = [0u8; 52];
                line[..5].copy_from_slice(b"TRNG:");
                line[5..49].copy_from_slice(&encoded);
                line[49..51].copy_from_slice(b"\r\n");
                let _ = tx.write_all(&line[..51]).await;
                let _ = tx.flush().await;
            }
            Either4::Second(message) => {
                let _ = tx.write_all(message.as_bytes()).await;
                let _ = tx.flush().await;
            }
            Either4::Third(_) => {
                // No periodic health line in the middle of a capture: it
                // would only have to be filtered back out of the data.
                if DUMP_LEFT.load(Ordering::Relaxed) != 0 {
                    continue;
                }
                let mut report = net::Buf::<1024>::new();
                format_health(&mut report).await;
                let _ = tx.write_all(report.as_bytes()).await;
                let _ = tx.flush().await;
            }
        }
    }
}

#[embassy_executor::task]
async fn usb_rx_task(mut rx: UsbSerialJtagRx<'static, Async>) {
    let mut read_buf = [0u8; 64];
    let mut line = [0u8; 320];
    let mut used = 0usize;

    loop {
        let count = rx.read(&mut read_buf).await.unwrap_or(0);
        capture_aux(SourceId::UsbTiming, timer_byte());
        for &byte in &read_buf[..count] {
            if byte == b'\r' || byte == b'\n' {
                if used == 0 {
                    continue;
                }
                let mut reply = net::Buf::<512>::new();
                match core::str::from_utf8(&line[..used]) {
                    Ok(command) => apply_command(command, Origin::Usb, &mut reply).await,
                    Err(_) => {
                        let _ = reply.write_str("ERR reason=utf8");
                    }
                }
                let mut message = UsbText::from_slice(reply.as_bytes());
                if message.len + 2 <= message.bytes.len() {
                    message.bytes[message.len..message.len + 2].copy_from_slice(b"\r\n");
                    message.len += 2;
                }
                let _ = USB_TEXT.try_send(message);
                used = 0;
            } else if used < line.len() {
                line[used] = byte;
                used += 1;
            } else {
                used = 0;
                queue_usb(b"ERR reason=line_too_long\r\n");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Wi-Fi and UDP
// ---------------------------------------------------------------------------

fn wifi_station_config(credentials: net::WifiCredentials) -> WifiConfig {
    let station = StationConfig::default().with_ssid(credentials.ssid().try_into().unwrap());
    let station = if credentials.is_open() {
        station.with_authentication(AuthenticationMethodConfig::Open)
    } else {
        station.with_authentication(AuthenticationMethodConfig::Wpa2Personal(
            credentials.password().try_into().unwrap(),
        ))
    };
    let access_point = AccessPointConfig::default()
        .with_ssid(cfg::PROVISION_AP_SSID.try_into().unwrap())
        .with_max_connections(1)
        .with_authentication(AuthenticationMethodConfig::Wpa2Personal(
            cfg::PROVISION_AP_PASSWORD.try_into().unwrap(),
        ));
    WifiConfig::AccessPointStation(station, access_point)
}

/// Apply new station credentials.
///
/// The station is disconnected FIRST. Changing the station config underneath
/// a live connection leaves the radio driver in a state where the next connect
/// attempt never reports success or failure, which is exactly the hang where
/// Nocturnus stopped reconnecting after a Wi-Fi change. Every await here is
/// bounded, so this can never hang either.
async fn reconfigure_wifi(
    controller: &mut WifiController<'static>,
    credentials: net::WifiCredentials,
) {
    // Returns straight away if neither connected nor connecting.
    let _ = with_timeout(Duration::from_secs(5), controller.disconnect_async()).await;
    mark_wifi_disconnected().await;
    if controller
        .set_config(&wifi_station_config(credentials))
        .is_err()
    {
        // esp-radio shuts the whole radio down when set_config fails, setup
        // network included, and nothing short of a restart brings it back.
        // The new credentials are already queued for flash, so save them and
        // restart: the node comes back up on the network that was asked for.
        queue_usb(b"WIFI state=reconfigure_failed action=save_and_reboot\r\n");
        persist_request(P_REBOOT);
    } else {
        let mut line = net::Buf::<96>::new();
        let _ = write!(
            line,
            "WIFI state=reconfigured ssid=\"{}\" reconnecting=1\r\n",
            credentials.ssid()
        );
        queue_usb(line.as_bytes());
    }
}

async fn mark_wifi_disconnected() {
    let mut guard = SHARED.lock().await;
    if let Some(sh) = guard.as_mut() {
        sh.wifi_connected = false;
        sh.targets_dirty = true;
    }
}

/// Newest queued credentials, if any. Older queued entries are superseded.
fn latest_wifi_update(first: Option<net::WifiCredentials>) -> Option<net::WifiCredentials> {
    let mut latest = first;
    while let Ok(credentials) = WIFI_UPDATES.try_receive() {
        latest = Some(credentials);
    }
    latest
}

#[embassy_executor::task]
async fn wifi_connection_task(mut controller: WifiController<'static>) {
    let mut pending: Option<net::WifiCredentials> = None;
    loop {
        if let Some(credentials) = latest_wifi_update(pending.take()) {
            reconfigure_wifi(&mut controller, credentials).await;
        }

        // A connect attempt that has heard nothing in this long is abandoned
        // and retried, instead of waiting on an event that may never come.
        let attempt = with_timeout(
            Duration::from_secs(cfg::WIFI_CONNECT_TIMEOUT_S),
            controller.connect_async(),
        );
        match select(attempt, WIFI_UPDATES.receive()).await {
            Either::First(Ok(Ok(_))) => {
                {
                    let mut guard = SHARED.lock().await;
                    if let Some(sh) = guard.as_mut() {
                        sh.wifi_connected = true;
                        sh.targets_dirty = true;
                    }
                }
                queue_usb(b"WIFI state=connected\r\n");
                while controller.is_connected() {
                    match select(Timer::after(Duration::from_secs(1)), WIFI_UPDATES.receive()).await
                    {
                        Either::First(_) => {
                            if let Ok(rssi) = controller.rssi() {
                                RSSI.store(rssi as i8 as u8, Ordering::Relaxed);
                                capture_aux(SourceId::WifiRssi, rssi as u8);
                            }
                        }
                        Either::Second(credentials) => {
                            pending = Some(credentials);
                            break;
                        }
                    }
                }
                mark_wifi_disconnected().await;
                if pending.is_some() {
                    // Straight to the new network, no backoff.
                    continue;
                }
                queue_usb(b"WIFI state=disconnected reconnecting=1\r\n");
            }
            Either::First(Ok(Err(e))) => {
                let mut line = net::Buf::<128>::new();
                let _ = match e {
                    esp_radio::wifi::ConnectionError::Failed(info) => {
                        write!(line, "WIFI state=connect_failed reason={:?}\r\n", info.reason)
                    }
                    other => write!(line, "WIFI state=connect_failed reason={:?}\r\n", other),
                };
                queue_usb(line.as_bytes());
                mark_wifi_disconnected().await;
            }
            Either::First(Err(_)) => {
                queue_usb(b"WIFI state=connect_timeout retrying=1\r\n");
                // Cancel the attempt the driver may still be running.
                let _ = with_timeout(Duration::from_secs(5), controller.disconnect_async()).await;
                mark_wifi_disconnected().await;
            }
            Either::Second(credentials) => {
                // New credentials mid-attempt: abandon it and use them now.
                pending = Some(credentials);
                continue;
            }
        }

        // A credential update interrupts the reconnect delay immediately.
        if let Either::Second(credentials) = select(
            Timer::after(Duration::from_millis(cfg::WIFI_RECONNECT_BACKOFF_MS)),
            WIFI_UPDATES.receive(),
        )
        .await
        {
            pending = Some(credentials);
        }
    }
}

#[embassy_executor::task]
async fn net_runner_task(mut runner: Runner<'static, Interface>) {
    runner.run().await
}

fn to_local_ip(address: Ipv4Address) -> net::Ipv4 {
    net::Ipv4(address.octets())
}

async fn resolve_targets(stack: Stack<'static>) {
    let config = stack.config_v4();
    let (own, mask, gateway) = match config {
        Some(config) => (
            Some(to_local_ip(config.address.address())),
            Some(to_local_ip(config.address.netmask())),
            config.gateway.map(to_local_ip),
        ),
        None => (None, None, None),
    };
    let mut announce = None;
    {
        let mut guard = SHARED.lock().await;
        if let Some(sh) = guard.as_mut() {
            sh.strum = net::resolve(sh.strum_pin, own, mask, gateway);
            sh.entropy = net::resolve(sh.entropy_pin, own, mask, gateway);
            sh.targets_dirty = false;
            if own != sh.sta_ip {
                announce = own;
            }
            sh.sta_ip = own;
            sh.sta_gw = gateway;
        }
    }
    // The dashboard address changes whenever the hotspot hands out a new
    // lease, so say it on USB every time it does.
    if let Some(ip) = announce {
        let mut line = net::Buf::<96>::new();
        let _ = write!(line, "WEB url=http://{ip}/ user={}\r\n", cfg::ADMIN_USER);
        queue_usb(line.as_bytes());
    }
}

fn endpoint(target: Resolved, port: u16) -> Option<IpEndpoint> {
    let address = target.address()?;
    Some(IpEndpoint::new(
        IpAddress::Ipv4(Ipv4Address::new(
            address.0[0],
            address.0[1],
            address.0[2],
            address.0[3],
        )),
        port,
    ))
}

fn ensure_bound(socket: &mut UdpSocket<'_>, current: &mut u16, wanted: u16) {
    if *current == wanted {
        return;
    }
    if *current != 0 {
        socket.close();
    }
    if socket.bind(wanted).is_ok() {
        *current = wanted;
    } else {
        *current = 0;
    }
}

fn count_send<E>(result: Result<(), E>, counter: &AtomicU32) {
    match result {
        Ok(()) => counter.fetch_add(1, Ordering::Relaxed),
        Err(_) => SEND_ERRORS.fetch_add(1, Ordering::Relaxed),
    };
}

#[embassy_executor::task]
async fn net_io_task(stack: Stack<'static>) {
    let mut strum_rx_meta = [PacketMetadata::EMPTY; 2];
    let mut strum_rx = [0u8; 64];
    let mut strum_tx_meta = [PacketMetadata::EMPTY; 2];
    let mut strum_tx = [0u8; 128];
    let mut strum_socket = UdpSocket::new(
        stack,
        &mut strum_rx_meta,
        &mut strum_rx,
        &mut strum_tx_meta,
        &mut strum_tx,
    );

    let mut entropy_rx_meta = [PacketMetadata::EMPTY; 2];
    let mut entropy_rx = [0u8; 64];
    let mut entropy_tx_meta = [PacketMetadata::EMPTY; 2];
    let mut entropy_tx = [0u8; 128];
    let mut entropy_socket = UdpSocket::new(
        stack,
        &mut entropy_rx_meta,
        &mut entropy_rx,
        &mut entropy_tx_meta,
        &mut entropy_tx,
    );

    let mut control_rx_meta = [PacketMetadata::EMPTY; 4];
    let mut control_rx_storage = [0u8; 1024];
    let mut control_tx_meta = [PacketMetadata::EMPTY; 4];
    let mut control_tx_storage = [0u8; 1024];
    let mut control_socket = UdpSocket::new(
        stack,
        &mut control_rx_meta,
        &mut control_rx_storage,
        &mut control_tx_meta,
        &mut control_tx_storage,
    );
    let _ = control_socket.bind(cfg::PORT_CONTROL);

    let mut strum_bound = 0u16;
    let mut entropy_bound = 0u16;
    let mut control_buf = [0u8; 512];
    stack.wait_config_up().await;
    resolve_targets(stack).await;
    let mut net_tick = Ticker::every(Duration::from_millis(cfg::NET_TICK_MS));
    let mut last_heartbeat = Instant::now();

    loop {
        let (strum_target, entropy_target, strum_port, entropy_port, enabled, dirty) = {
            let guard = SHARED.lock().await;
            let Some(sh) = guard.as_ref() else {
                Timer::after(Duration::from_millis(cfg::NET_TICK_MS)).await;
                continue;
            };
            (
                sh.strum,
                sh.entropy,
                sh.strum_port,
                sh.entropy_port,
                sh.udp_enabled,
                sh.targets_dirty,
            )
        };
        if dirty {
            resolve_targets(stack).await;
            continue;
        }
        ensure_bound(&mut strum_socket, &mut strum_bound, strum_port);
        ensure_bound(&mut entropy_socket, &mut entropy_bound, entropy_port);

        match select4(
            NET_KEYS.receive(),
            STRUMS.receive(),
            control_socket.recv_from(&mut control_buf),
            net_tick.next(),
        )
        .await
        {
            Either4::First(packet) => {
                if enabled {
                    if let Some(remote) = endpoint(entropy_target, entropy_port) {
                        let sent = entropy_socket.send_to(&packet.bytes, remote).await;
                        count_send(sent, &SENT_ENTROPY);
                        capture_aux(SourceId::NetworkTiming, timer_byte());
                    }
                }
            }
            Either4::Second(()) => {
                if enabled {
                    if let Some(remote) = endpoint(strum_target, strum_port) {
                        let sent = strum_socket.send_to(cfg::STRUM_PAYLOAD, remote).await;
                        count_send(sent, &SENT_STRUM);
                        capture_aux(SourceId::NetworkTiming, timer_byte());
                    }
                }
            }
            Either4::Third(Ok((count, metadata))) => {
                capture_aux(SourceId::NetworkTiming, timer_byte());
                let mut reply = net::Buf::<512>::new();
                match core::str::from_utf8(&control_buf[..count]) {
                    Ok(command) => apply_command(command, Origin::Udp, &mut reply).await,
                    Err(_) => {
                        let _ = reply.write_str("ERR reason=utf8");
                    }
                }
                let _ = control_socket
                    .send_to(reply.as_bytes(), metadata.endpoint)
                    .await;
            }
            Either4::Third(Err(_)) => {}
            Either4::Fourth(_) => {
                // Periodic wake updates DHCP-derived gateway targets and lets
                // port changes take effect even on an otherwise quiet node.
                resolve_targets(stack).await;
                if enabled
                    && Instant::now().duration_since(last_heartbeat)
                        >= Duration::from_millis(cfg::HEARTBEAT_INTERVAL_MS)
                {
                    if let Some(remote) = endpoint(strum_target, strum_port) {
                        let sent = strum_socket.send_to(cfg::HEARTBEAT_PAYLOAD, remote).await;
                        count_send(sent, &SENT_HEARTBEAT);
                        capture_aux(SourceId::NetworkTiming, timer_byte());
                    }
                    last_heartbeat = Instant::now();
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Entry
// ---------------------------------------------------------------------------

type HalI2c = esp_hal::i2c::master::I2c<'static, Async>;

impl mpu::I2cBus for HalI2c {
    type Error = esp_hal::i2c::master::Error;

    async fn write(&mut self, addr: u8, bytes: &[u8]) -> Result<(), Self::Error> {
        self.write_async(addr, bytes).await
    }

    async fn write_read(
        &mut self,
        addr: u8,
        write: &[u8],
        read: &mut [u8],
    ) -> Result<(), Self::Error> {
        self.write_read_async(addr, write, read).await
    }
}

/// Header pins the sensor could plausibly be wired to. GPIO1 (ADC noise) and
/// GPIO11 (INT) are left out: they have jobs of their own, and INT is driven
/// by the MPU, so it must never be driven from this side.
const I2C_CANDIDATES: usize = 11;

/// What the boot-time wiring search found.
struct Wiring {
    /// Index into the candidate table of the SDA and SCL pins to use.
    sda: usize,
    scl: usize,
    /// True when the MPU acknowledged on that pair.
    answered: bool,
    /// Plain-language summary for USB, the probe report and the dashboard.
    summary: net::Buf<320>,
}

/// Find the sensor wherever it is actually wired.
///
/// Step 1: every candidate pin is read with the ESP32's weak pull-down on. The
/// sensor board's pull-up resistors overpower that, but only on pins that a
/// powered board's SDA or SCL wire really reaches. That survey alone tells a
/// dead or disconnected board from a wiring mistake.
///
/// Step 2: I2C is tried on the documented pair (GPIO8/GPIO9), then the same
/// pair swapped, then every ordered pair of pulled-up pins, asking addresses
/// 0x68 and 0x69 for WHO_AM_I. The first pair that answers is used, wherever
/// it is, and reported.
///
/// I2C only ever pulls a line low, never drives it high, so this cannot fight
/// an open-drain line. A pin tied hard to 3V3 would read as pulled up and be
/// pulled low for a fraction of a millisecond per try: brief, and bounded by
/// the bus timeout.
fn find_i2c_wiring(
    pins: &mut [(u8, Option<esp_hal::gpio::AnyPin<'static>>); I2C_CANDIDATES],
    mut i2c0: esp_hal::peripherals::I2C0<'_>,
) -> Wiring {
    use esp_hal::gpio::{Input, InputConfig, Pull};

    let delay = esp_hal::delay::Delay::new();
    let mut pulled = [false; I2C_CANDIDATES];
    for (i, (_, pin)) in pins.iter_mut().enumerate() {
        if let Some(pin) = pin.as_mut() {
            let input = Input::new(pin.reborrow(), InputConfig::default().with_pull(Pull::Down));
            delay.delay_micros(300);
            pulled[i] = input.is_high();
        }
    }

    let index_of = |gpio: u8| pins.iter().position(|(n, _)| *n == gpio).unwrap_or(0);
    let (d_sda, d_scl) = (index_of(8), index_of(9));

    let mut order: [(usize, usize); I2C_CANDIDATES * I2C_CANDIDATES] =
        [(0, 0); I2C_CANDIDATES * I2C_CANDIDATES];
    let mut n = 0usize;
    order[n] = (d_sda, d_scl);
    n += 1;
    order[n] = (d_scl, d_sda);
    n += 1;
    for a in 0..I2C_CANDIDATES {
        for b in 0..I2C_CANDIDATES {
            if a != b && pulled[a] && pulled[b] && !order[..n].contains(&(a, b)) {
                order[n] = (a, b);
                n += 1;
            }
        }
    }

    let mut hit: Option<(usize, usize, u8, u8)> = None;
    'search: for &(a, b) in &order[..n] {
        let (Some(mut sda), Some(mut scl)) = (pins[a].1.take(), pins[b].1.take()) else {
            continue;
        };
        if let Ok(bus) = esp_hal::i2c::master::I2c::new(i2c0.reborrow(), i2c_config(100_000)) {
            let mut bus = bus.with_sda(sda.reborrow()).with_scl(scl.reborrow());
            for addr in [mpu::ADDR_AD0_LOW, mpu::ADDR_AD0_HIGH] {
                let mut id = [0u8; 1];
                if bus.write_read(addr, &[mpu::reg::WHO_AM_I], &mut id).is_ok() {
                    hit = Some((a, b, addr, id[0]));
                    break;
                }
            }
        }
        pins[a].1 = Some(sda);
        pins[b].1 = Some(scl);
        if hit.is_some() {
            break 'search;
        }
    }

    let mut summary = net::Buf::<320>::new();
    match hit {
        Some((a, b, addr, id)) => {
            let _ = write!(
                summary,
                "sensor answers at 0x{addr:02x} (WHO_AM_I 0x{id:02x}) on SDA=GPIO{} SCL=GPIO{}",
                pins[a].0, pins[b].0
            );
            if (a, b) != (d_sda, d_scl) {
                let _ = summary.write_str(", not the documented GPIO8/GPIO9; using it");
            }
            Wiring { sda: a, scl: b, answered: true, summary }
        }
        None => {
            let count = pulled.iter().filter(|p| **p).count();
            if count == 0 {
                let _ = summary.write_str(
                    "no header pin is pulled up: the sensor board has no power or its wires are not making contact",
                );
            } else {
                let _ = summary.write_str("pulled up:");
                for (i, p) in pulled.iter().enumerate() {
                    if *p {
                        let _ = write!(summary, " GPIO{}", pins[i].0);
                    }
                }
                let _ = summary.write_str("; no MPU answered on any of them");
            }
            Wiring { sda: d_sda, scl: d_scl, answered: false, summary }
        }
    }
}

/// Independent checks for when the I2C driver finds nothing. All of this runs
/// on plain GPIO, with no I2C hardware involved, before the driver exists.
///
/// 1. Short test: pull each line low and see whether the other follows. Two
///    wires touching, or a solder bridge, drags both down together.
/// 2. Bit-banged I2C: the whole conversation (bus recovery, START, address,
///    acknowledge) clocked out by hand at about 20 kHz. If the chip answers
///    this but not the driver, the fault is on this side; if it answers
///    neither, it is the hardware.
/// 3. INT: after power-up the MPU drives its INT pin low (push-pull, active
///    high, nothing enabled). Read against the ESP32's pull-UP, a low INT
///    proves the chip itself has power and ground, which pull-ups on SDA/SCL
///    alone cannot: those resistors light up from VCC even with no ground or
///    a dead chip.
fn bus_forensics(
    sda: esp_hal::gpio::AnyPin<'_>,
    scl: esp_hal::gpio::AnyPin<'_>,
    int: esp_hal::peripherals::GPIO11<'_>,
    out: &mut net::Buf<320>,
) {
    use esp_hal::gpio::{DriveMode, Flex, OutputConfig, Pull};

    let delay = esp_hal::delay::Delay::new();
    let half = || delay.delay_micros(25);
    let od = OutputConfig::default()
        .with_drive_mode(DriveMode::OpenDrain)
        .with_pull(Pull::Up);
    let mut sda = Flex::new(sda);
    let mut scl = Flex::new(scl);
    for line in [&mut sda, &mut scl] {
        line.set_high();
        line.apply_output_config(&od);
        line.set_input_enable(true);
        line.set_output_enable(true);
    }
    delay.delay_micros(200);

    // 1. Shorts and stuck lines.
    let (sda_idle, scl_idle) = (sda.is_high(), scl.is_high());
    scl.set_low();
    half();
    let sda_follows = sda.is_low();
    scl.set_high();
    half();
    sda.set_low();
    half();
    let scl_follows = scl.is_low();
    sda.set_high();
    half();
    if !sda_idle || !scl_idle {
        let _ = write!(
            out,
            "; line held low at rest:{}{}",
            if sda_idle { "" } else { " SDA" },
            if scl_idle { "" } else { " SCL" }
        );
    } else if sda_follows || scl_follows {
        let _ = out.write_str("; SDA and SCL are shorted together");
    }

    // 2. Bit-banged probe. Nine clocks first free a chip left mid-byte.
    for _ in 0..9 {
        scl.set_low();
        half();
        scl.set_high();
        half();
    }
    let stop = |sda: &mut Flex, scl: &mut Flex| {
        sda.set_low();
        half();
        scl.set_high();
        half();
        sda.set_high();
        half();
    };
    stop(&mut sda, &mut scl);
    // A line held low would read as an ACK to everything, so only probe a
    // bus that is idle high. 0x5A is probed too as a control: no MPU answers
    // there, so an ACK at it means the bus, not a chip, is answering.
    if !sda_idle || !scl_idle || sda_follows || scl_follows {
        let _ = out.write_str("; bit-banged I2C skipped (lines not free)");
        drop(sda);
        drop(scl);
        int_check(int, out);
        return;
    }
    let mut acks = [false; 3];
    for (slot, addr) in [mpu::ADDR_AD0_LOW, mpu::ADDR_AD0_HIGH, 0x5A].into_iter().enumerate() {
        // START: SDA falls while SCL is high.
        sda.set_high();
        scl.set_high();
        half();
        sda.set_low();
        half();
        scl.set_low();
        half();
        let byte = addr << 1; // write
        for bit in (0..8).rev() {
            if (byte >> bit) & 1 == 1 {
                sda.set_high();
            } else {
                sda.set_low();
            }
            half();
            scl.set_high();
            half();
            scl.set_low();
        }
        // Acknowledge: the chip pulls SDA low during the ninth clock.
        sda.set_high();
        half();
        scl.set_high();
        half();
        let ack = sda.is_low();
        scl.set_low();
        half();
        stop(&mut sda, &mut scl);
        acks[slot] = ack;
    }
    let _ = match acks {
        [_, _, true] => out.write_str("; bit-banged I2C: even the unused control address ACKs, so SDA is being pulled low, not answered"),
        [true, _, false] => out.write_str("; bit-banged I2C DID get an ACK at 0x68: the chip works, the fault is in the I2C driver path"),
        [false, true, false] => out.write_str("; bit-banged I2C DID get an ACK at 0x69: the chip works, the fault is in the I2C driver path"),
        [false, false, false] => out.write_str("; bit-banged I2C (no I2C hardware used): no ACK at 0x68/0x69 either"),
    };
    drop(sda);
    drop(scl);
    int_check(int, out);
}

/// Is the chip itself holding its INT pin low, as a powered MPU does after
/// power-up? Read against the ESP32's pull-up.
///
/// Low is CONSISTENT with a powered chip but not proof: an unpowered chip
/// with its ground connected can clamp the pin low through its protection
/// diode, and so can an INT wire shorted to ground. High, with SDA/SCL pulled
/// up, is the telling case: the board's resistors have VCC but the chip is not
/// driving INT, which most often means its ground is not connected.
fn int_check(int: esp_hal::peripherals::GPIO11<'_>, out: &mut net::Buf<320>) {
    use esp_hal::gpio::{Input, InputConfig, Pull};
    let int = Input::new(int, InputConfig::default().with_pull(Pull::Up));
    esp_hal::delay::Delay::new().delay_micros(300);
    if int.is_low() {
        let _ = out.write_str("; INT reads low, consistent with a powered chip: suspect the chip itself");
    } else {
        let _ = out.write_str("; INT reads high: the chip is not driving it, most often no GND at the sensor, or the INT wire is open");
    }
}

fn reset_reason_name() -> &'static str {
    match esp_hal::system::reset_reason() {
        Some(SocResetReason::ChipPowerOn) => "power_on",
        Some(SocResetReason::CoreSw) | Some(SocResetReason::CpuSw) => "software",
        Some(SocResetReason::CoreRtcWdt)
        | Some(SocResetReason::CpuRtcWdt)
        | Some(SocResetReason::SysRtcWdt) => "watchdog",
        Some(SocResetReason::CoreMwdt0)
        | Some(SocResetReason::CoreMwdt1)
        | Some(SocResetReason::CpuMwdt0)
        | Some(SocResetReason::CpuMwdt1)
        | Some(SocResetReason::SysSuperWdt) => "system_watchdog",
        Some(SocResetReason::SysBrownOut) => "brownout",
        Some(SocResetReason::CoreUsbUart) | Some(SocResetReason::CoreUsbJtag) => "usb",
        Some(SocResetReason::CoreDeepSleep) => "deep_sleep",
        Some(_) => "other",
        None => "unknown",
    }
}

#[esp_rtos::main]
async fn main(spawner: Spawner) {
    esp_alloc::heap_allocator!(size: 72 * 1024);

    let mut peripherals = esp_hal::init(esp_hal::Config::default());
    let timer_group = esp_hal::timer::timg::TimerGroup::new(peripherals.TIMG0);
    esp_rtos::start(timer_group.timer0, peripherals.FROM_CPU_INTR0);

    let usb =
        esp_hal::usb::usb_serial_jtag::UsbSerialJtag::new(peripherals.USB_DEVICE).into_async();
    let (usb_rx, usb_tx) = usb.split();
    if let Ok(task) = usb_tx_task(usb_tx) {
        spawner.spawn(task);
    }
    if let Ok(task) = usb_rx_task(usb_rx) {
        spawner.spawn(task);
    }
    let reset_reason = reset_reason_name();
    {
        let mut line = net::Buf::<160>::new();
        let _ = write!(
            line,
            "BOOT node=nocturnus id=A-004 conditioner=SHA3-512 tests=RCT,APT,MARKOV assessment=PROVISIONAL reset={reset_reason}\r\n"
        );
        queue_usb(line.as_bytes());
    }
    queue_usb(b"PORTAL ssid=NOCTURNUS-SETUP password=guitarng-setup url=http://192.168.4.1/\r\n");

    let initial_wifi = match net::WifiCredentials::new(cfg::WIFI_SSID, cfg::WIFI_PASSWORD) {
        Ok(credentials) => credentials,
        Err(_) => {
            queue_usb(b"FATAL component=wifi reason=bad_compiled_credentials\r\n");
            loop {
                Timer::after(Duration::from_secs(60)).await;
            }
        }
    };

    // Compiled defaults first, then whatever flash holds on top. A node that
    // has never saved, or whose records do not validate, runs on exactly the
    // defaults it always did.
    // The second core is never started, but auto-park makes flash writes safe
    // even if something starts it later, instead of failing every save.
    let mut flash = FlashStorage::new(peripherals.FLASH).multicore_auto_park();
    let boot = load_settings(&mut flash);

    // Built directly inside the lock, and nothing is awaited while it exists
    // anywhere else, so the 30 KB state is never kept twice in RAM.
    let mut guard = SHARED.lock().await;
    *guard = Some(Shared {
        harvester: Harvester::new(cfg::TARGET_BITS),
        strum_pin: TargetPin::parse(cfg::TARGET_STRUM).unwrap_or(TargetPin::Auto),
        entropy_pin: TargetPin::parse(cfg::TARGET_ENTROPY).unwrap_or(TargetPin::Auto),
        strum: Resolved::None(net::NoTarget::NoGateway),
        entropy: Resolved::None(net::NoTarget::NoGateway),
        strum_port: cfg::PORT_STRUM,
        entropy_port: cfg::PORT_ENTROPY,
        udp_enabled: true,
        udp_control: true,
        targets_dirty: true,
        bus_faults: 0,
        mpu_ready: false,
        mpu_address: 0,
        mpu_chip: "none",
        mpu_error: net::Buf::new(),
        mpu_link: net::Buf::new(),
        mot_thr: mpu::Config::default().mot_thr,
        gyro_thr: mpu::Config::default().gyro_thr,
        accel_hpf: mpu::Config::default().accel_hpf,
        min_live: persist::DEFAULT_MIN_LIVE,
        wifi_connected: false,
        wifi_credentials: initial_wifi,
        sta_ip: None,
        sta_gw: None,
        admin_salt: [0; 16],
        admin_hash: [0; 32],
        reset_reason,
    });
    let station_credentials = match guard.as_mut() {
        Some(sh) => {
            if let Some(settings) = boot.settings.as_ref() {
                apply_settings(sh, settings);
            }
            // The sampler reads the motion settings from these every frame.
            MOT_THR.store(sh.mot_thr, Ordering::Relaxed);
            GYRO_THR.store(sh.gyro_thr, Ordering::Relaxed);
            MOTION_HPF.store(sh.accel_hpf, Ordering::Relaxed);
            sh.wifi_credentials
        }
        None => initial_wifi,
    };
    drop(guard);

    if let Ok(task) = persist_task(flash, boot.store) {
        spawner.spawn(task);
    } else {
        queue_usb(b"FATAL component=embassy reason=persist_task_pool\r\n");
    }

    // Find the sensor on whatever header pins it is actually wired to.
    let mut pins: [(u8, Option<esp_hal::gpio::AnyPin<'static>>); I2C_CANDIDATES] = [
        (2, Some(peripherals.GPIO2.into())),
        (3, Some(peripherals.GPIO3.into())),
        (4, Some(peripherals.GPIO4.into())),
        (5, Some(peripherals.GPIO5.into())),
        (6, Some(peripherals.GPIO6.into())),
        (7, Some(peripherals.GPIO7.into())),
        (8, Some(peripherals.GPIO8.into())),
        (9, Some(peripherals.GPIO9.into())),
        (10, Some(peripherals.GPIO10.into())),
        (12, Some(peripherals.GPIO12.into())),
        (13, Some(peripherals.GPIO13.into())),
    ];
    let mut wiring = find_i2c_wiring(&mut pins, peripherals.I2C0.reborrow());
    if !wiring.answered {
        // Taken out and put back, since both pins are borrowed at once.
        let (a, b) = (wiring.sda, wiring.scl);
        if let (Some(mut sda), Some(mut scl)) = (pins[a].1.take(), pins[b].1.take()) {
            bus_forensics(
                sda.reborrow(),
                scl.reborrow(),
                peripherals.GPIO11.reborrow(),
                &mut wiring.summary,
            );
            pins[a].1 = Some(sda);
            pins[b].1 = Some(scl);
        }
    }
    {
        let mut line = net::Buf::<384>::new();
        let _ = write!(
            line,
            "WIRING found={} detail=\"{}\"\r\n",
            if wiring.answered { 1 } else { 0 },
            wiring.summary.as_str()
        );
        queue_usb(line.as_bytes());
    }
    let (sda_gpio, scl_gpio) = (pins[wiring.sda].0, pins[wiring.scl].0);
    let (Some(sda_pin), Some(scl_pin)) = (pins[wiring.sda].1.take(), pins[wiring.scl].1.take())
    else {
        queue_usb(b"FATAL component=i2c reason=pin_table\r\n");
        loop {
            Timer::after(Duration::from_secs(60)).await;
        }
    };
    let i2c = esp_hal::i2c::master::I2c::new(peripherals.I2C0, i2c_config(100_000))
    .unwrap()
    .with_sda(sda_pin)
    .with_scl(scl_pin)
    .into_async();
    let int_pin = esp_hal::gpio::Input::new(
        peripherals.GPIO11,
        esp_hal::gpio::InputConfig::default().with_pull(esp_hal::gpio::Pull::Down),
    );

    let device = mpu::Mpu6050::new(i2c, mpu::ADDR_AD0_LOW, mpu::Config::default());

    // Noise source: ADC1 on an unconnected pin, widest attenuation.
    let mut adc_config = esp_hal::analog::adc::AdcConfig::new();
    let adc_pin = adc_config.enable_pin(
        peripherals.GPIO1,
        esp_hal::analog::adc::Attenuation::_11dB,
    );
    let adc = esp_hal::analog::adc::Adc::new(peripherals.ADC1, adc_config);

    if let Ok(task) = harvest_task(device, int_pin, adc, adc_pin, wiring.summary, (sda_gpio, scl_gpio)) {
        spawner.spawn(task);
    } else {
        queue_usb(b"FATAL component=embassy reason=harvest_task_pool\r\n");
    }

    let station = Interface::station();
    let access_point = Interface::access_point();
    let station_config = wifi_station_config(station_credentials);
    let controller = match WifiController::new(
        peripherals.WIFI,
        ControllerConfig::default().with_initial_config(station_config),
    ) {
        Ok(controller) => {
            RADIO_UP.store(true, Ordering::Relaxed);
            controller
        }
        Err(_) => {
            queue_usb(b"FATAL component=wifi reason=controller_init_failed usb_only=1\r\n");
            loop {
                Timer::after(Duration::from_secs(60)).await;
            }
        }
    };

    let rng = esp_hal::rng::Rng::new();
    let seed = (rng.random() as u64) << 32 | rng.random() as u64;

    // Station sockets: strum, entropy and control UDP, the DHCP client, and
    // three dashboard listeners.
    let mut dhcp = embassy_net::DhcpConfig::default();
    dhcp.hostname = heapless::String::try_from(cfg::DHCP_HOSTNAME).ok();
    let resources = mk_static!(StackResources<8>, StackResources::<8>::new());
    let (stack, runner) = embassy_net::new(
        station,
        embassy_net::Config::dhcpv4(dhcp),
        resources,
        seed,
    );
    // Setup-network sockets: DHCP server, DNS, two dashboard listeners.
    let ap_resources = mk_static!(StackResources<6>, StackResources::<6>::new());
    let ap_ip = Ipv4Address::new(
        cfg::PROVISION_AP_IP[0],
        cfg::PROVISION_AP_IP[1],
        cfg::PROVISION_AP_IP[2],
        cfg::PROVISION_AP_IP[3],
    );
    let (ap_stack, ap_runner) = embassy_net::new(
        access_point,
        embassy_net::Config::ipv4_static(StaticConfigV4 {
            address: Ipv4Cidr::new(ap_ip, 24),
            gateway: None,
            dns_servers: Default::default(),
        }),
        ap_resources,
        seed ^ 0xa004_1921_6804_0001,
    );

    if let Ok(task) = wifi_connection_task(controller) {
        spawner.spawn(task);
    }
    if let Ok(task) = net_runner_task(runner) {
        spawner.spawn(task);
    }
    if let Ok(task) = web::ap_net_runner_task(ap_runner) {
        spawner.spawn(task);
    }
    if let Ok(task) = web::dhcp_task(ap_stack) {
        spawner.spawn(task);
    }
    if let Ok(task) = web::dns_task(ap_stack) {
        spawner.spawn(task);
    }
    for _ in 0..3 {
        if let Ok(task) = web::sta_http_task(stack) {
            spawner.spawn(task);
        }
    }
    for _ in 0..2 {
        if let Ok(task) = web::ap_http_task(ap_stack) {
            spawner.spawn(task);
        }
    }
    if let Ok(task) = net_io_task(stack) {
        spawner.spawn(task);
    }

    // Watchdog. Armed last, once everything is running, and fed only while
    // the sampler is advancing. The sampler advances at least once a second
    // while sampling and once per probe attempt (about every 5 s) while the
    // MPU is missing, so a 15 s timeout fires only on a real hang.
    let mut rtc = Rtc::new(peripherals.RTC_TIMER);
    rtc.rwdt.set_timeout(
        RwdtStage::Stage0,
        esp_hal::time::Duration::from_millis(cfg::WATCHDOG_TIMEOUT_MS),
    );
    rtc.rwdt.enable();
    WDT_ARMED.store(true, Ordering::Relaxed);

    let mut last_beat = HARVEST_BEAT.load(Ordering::Relaxed);
    loop {
        Timer::after(Duration::from_secs(1)).await;
        let beat = HARVEST_BEAT.load(Ordering::Relaxed);
        if beat != last_beat {
            rtc.rwdt.feed();
            last_beat = beat;
        }
    }
}
