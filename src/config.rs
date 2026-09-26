// ============================================================================
//  config.rs - every tunable in one place
//  Jupiter Labs / CHIRASU Network
//
//  NOCTURNUS  -  A-004  -  "Paradox Heart and Bloom"
//  Tease SBH-HD, tele style, Open F#
//  ESP32-S3 Super Mini + MPU-6050, battery powered
//
//  Fourth artifact of the Null Order Collective to carry a harvester, and the
//  first with no piezo: motion measured from the MPU's own samples is the
//  strum detector.
// ============================================================================

#![allow(dead_code)]

/// Node identity, sent in the heartbeat so the relay can tell six guitars
/// apart without inferring it from the source port.
pub const NODE_NAME: &str = "nocturnus";
pub const NODE_CALLSIGN: &str = "A-004";

// ---------------------------------------------------------------------------
// Pins - ESP32-S3 Super Mini
// ---------------------------------------------------------------------------
//
// Only GPIO1-13 are broken out on this board, plus the UART pins. GPIO19/20
// are consumed by the onboard USB-C connector and are not header pins.
// GPIO0, 3, 45 and 46 are strapping pins; 26-37 belong to flash and PSRAM.

pub const PIN_I2C_SDA: u8 = 8;
pub const PIN_I2C_SCL: u8 = 9;

/// MPU-6050 INT. ADC2 is unusable while the radio is up, so this pin has no
/// competing use and is free for a digital input.
pub const PIN_MPU_INT: u8 = 11;

/// ADC noise source: ADC1 channel 0. Leave this pin UNCONNECTED; the reading
/// is the converter's own noise plus whatever the bare pad picks up. ADC1 is
/// used because ADC2 cannot be read while the radio is on.
pub const PIN_ADC_NOISE: u8 = 1;

/// WS2812, when the board has one. Revisions differ and many Super Minis
/// share this pin between a plain LED and the addressable one.
///
/// The board lives sealed inside a guitar, so nobody sees this during a set.
/// It is bench diagnostics only, and the firmware must run identically with
/// `ENABLE_LED = false`. Real status goes out over the wire.
///
/// On battery, leave it OFF outside the bench: a WS2812 draws current even
/// while dark, and this node has no wall socket behind it.
pub const PIN_LED: u8 = 48;
pub const ENABLE_LED: bool = false;

// ---------------------------------------------------------------------------
// Physical placement - Nocturnus
// ---------------------------------------------------------------------------
//
// The SBH-HD's control cavity is shielded AND sits under a chrome control
// plate. That is a closed Faraday cage at 2.4 GHz. A radio in there
// associates at soundcheck three feet from the phone and drops the moment you
// walk downstage, which is the kind of fault that only ever shows up in front
// of people.
//
//   MPU      -> control cavity, tethered, semi-loose. I2C over wire does not
//               care about RF. Travel limit MUST stay shorter than the reach
//               to the pots, the switch and the jack.
//   ESP32    -> pickup route, NOT the control cavity. Antenna edge pointed
//               away from the control plate and away from the string plane,
//               which is a grounded-ish sheet that detunes it.
//   Battery  -> secured, protected cell, ideally not sharing a route with the
//               radio.

// ---------------------------------------------------------------------------
// I2C
// ---------------------------------------------------------------------------

/// 400 kHz is the MPU-6050's documented maximum. 1 MHz is out of spec but
/// widely reported to work if the GY-521's 4.7k pull-ups are swapped for 2.2k.
/// Do not raise this without also raising the sample rate, and read the note
/// on SMPLRT_DIV in mpu.rs before doing either.
pub const I2C_FREQ_HZ: u32 = 400_000;

// ---------------------------------------------------------------------------
// Network
// ---------------------------------------------------------------------------

pub const WIFI_SSID: &str = "your-wifi";
pub const WIFI_PASSWORD: &str = "your-password";

/// Local provisioning network. The access point stays available while the
/// station connection runs, so changing the destination hotspot never needs a
/// firmware rebuild or a working old network.
pub const PROVISION_AP_SSID: &str = "NOCTURNUS-SETUP";
pub const PROVISION_AP_PASSWORD: &str = "guitarng-setup";
pub const PROVISION_AP_IP: [u8; 4] = [192, 168, 4, 1];
pub const PROVISION_CLIENT_IP: [u8; 4] = [192, 168, 4, 2];

// ---------------------------------------------------------------------------
// Dashboard
// ---------------------------------------------------------------------------
//
// The dashboard is served on port 80 on BOTH networks: the hotspot address
// (whatever the phone's DHCP hands out) and 192.168.4.1 on the setup network.
// Every page and API call needs HTTP Basic authentication.

/// Username the browser asks for. Fixed; only the password is a secret.
pub const ADMIN_USER: &str = "admin";

/// Used ONLY until a password is set with `PASS "..."` or from the dashboard.
/// The dashboard shows a warning banner for as long as this is in effect.
/// `FACTORY` returns to it, so a forgotten password is recovered over USB.
pub const ADMIN_DEFAULT_PASSWORD: &str = "nocturnus";

/// Name the node gives the phone's DHCP server, so it shows up by name in the
/// hotspot's connected-devices list instead of as a bare MAC address.
pub const DHCP_HOSTNAME: &str = "nocturnus";

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

/// Settings are written to flash this long after the LAST change, so dragging
/// a slider or typing a burst of commands costs one flash write, not twenty.
/// `SAVE` writes immediately.
pub const SAVE_QUIET_MS: u64 = 3_000;

/// Upper bound on how long a stream of changes can postpone a save.
pub const SAVE_MAX_DEFER_MS: u64 = 30_000;

/// Minimum spacing between two flash writes, whatever asks for them.
pub const SAVE_MIN_INTERVAL_MS: u64 = 5_000;

// ---------------------------------------------------------------------------
// Liveness
// ---------------------------------------------------------------------------

/// Hardware RTC watchdog. It is fed only while the sampling loop is making
/// progress, so a wedged executor or an I2C call that never returns ends in a
/// clean reboot instead of a guitar that silently stopped harvesting halfway
/// through a set. The dashboard reports the reason for the last reset.
pub const WATCHDOG_TIMEOUT_MS: u64 = 15_000;

/// With no MPU interrupt for this long, the sampler treats the sensor as lost
/// (a loose wire, a brownout that reset its registers) and re-probes it.
pub const MPU_STALL_MS: u64 = 1_000;

// CHIRASU port scheme. Ports are FIXED and never derived from anything.
//
//   Spectra    5005 / 5056      Neptonius  5006 / 5057
//   Thalyn     5007 / 5058      Sylvia     5009 / 5060
//   this node  5008 / 5059      control    5013
//
// Both data sockets bind LOCALLY to the same port they send to. Symmetric
// binding means the phone's replies land on the exact socket that sent, so
// nothing has to guess about NAT, and the inbound packets are themselves a
// timing source.
pub const PORT_STRUM: u16 = 5008;
pub const PORT_ENTROPY: u16 = 5059;
pub const PORT_CONTROL: u16 = 5013;

/// "auto" resolves to the DHCP gateway, which on a phone hotspot is the phone.
/// See net.rs for what happens to a stale pin.
pub const TARGET_STRUM: &str = "auto";
pub const TARGET_ENTROPY: &str = "auto";

pub const WIFI_RECONNECT_BACKOFF_MS: u64 = 5_000;

/// A connection attempt that has produced neither success nor failure in this
/// long is abandoned and retried.
pub const WIFI_CONNECT_TIMEOUT_S: u64 = 20;

/// Sent when movement crosses the motion threshold. This node has no piezo:
/// motion detected from the MPU's accelerometer samples is the strum detector. The payload matches what the other
/// five guitars send so the Android relay needs no change.
pub const STRUM_PAYLOAD: &[u8] = b"STRUM";

/// Minimum gap between two motion events reaching the relay.
///
/// The MPU's motion latch is cleared every time INT_STATUS is read, and that
/// happens on every data-ready edge, so a moving instrument can re-assert the
/// condition up to 1000 times a second. Without this the relay would be
/// flooded and a "strum" would stop meaning anything.
///
/// 60 ms allows roughly 16 events a second: fast enough that strums, headbangs
/// and body movement each register, slow enough to stay legible. Tunable live
/// with `SET debounce=`.
pub const MOTION_DEBOUNCE_MS: u64 = 60;

/// Liveness beacon when nothing is being played, so the relay can tell a quiet
/// guitar from a dead one.
pub const HEARTBEAT_INTERVAL_MS: u64 = 10_000;
pub const HEARTBEAT_PAYLOAD: &[u8] = b"HEARTBEAT nocturnus A-004";

// ---------------------------------------------------------------------------
// Harvest
// ---------------------------------------------------------------------------

/// Bits of assessed min-entropy required from CREDITED sources before any
/// 32-byte conditioned block is released.
pub const TARGET_BITS: u32 = 256;

/// Independent credited sources that must be alive at release.
///
/// Without this floor, one unusually noisy axis could fund an entire key while
/// the other five sat dead, and the budget alone would be perfectly happy.
pub const MIN_LIVE_SOURCES: usize = 4;

/// Bytes of key material per release.
pub const KEY_BYTES: usize = 32;

/// Hard ceiling on release rate. At 1 kHz across eight credited sources the
/// budget fills in well under a second, which would flood the relay with keys
/// nobody asked for.
pub const MIN_RELEASE_INTERVAL_MS: u64 = 1_000;

/// The SP 800-90B Markov estimate is evaluated over this many raw bits per
/// source. 4096 bits is 512 byte samples and keeps the per-source estimator
/// responsive without pretending that a tiny window is a characterization.
pub const MARKOV_WINDOW_BITS: u32 = 4096;

/// Emit a full health line on native USB Serial/JTAG at this interval. Entropy
/// lines are emitted on every release as `TRNG:<base64>`, matching Spectra.
pub const USB_HEALTH_INTERVAL_MS: u64 = 10_000;

/// Network task wake interval. This bounds control/target-update latency even
/// when no entropy or strum event is queued.
pub const NET_TICK_MS: u64 = 250;
