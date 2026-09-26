// ============================================================================
//  net.rs - addressing and control plane
//  Jupiter Labs / CHIRASU Network
//
//  Pure `core` code, zero dependencies, host-testable. The actual sockets live
//  in main.rs; everything that can be gotten subtly wrong lives here.
//
//  This module is a direct descendant of Spectra's target-resolution work,
//  which was the strongest part of that firmware and is carried over
//  deliberately. The failure it exists to prevent:
//
//    A phone hotspot renegotiates its subnet between sessions. A target IP
//    pinned in a config file goes stale. UDP has no delivery signal, so every
//    send still reports success while the listener's counters sit at zero.
//    The node looks perfectly healthy and is talking to nobody.
//
//  PORTS ARE NEVER DERIVED from anything here. They are fixed by the CHIRASU
//  port scheme and live in config.rs.
// ============================================================================

#![allow(dead_code)]

use core::fmt::Write as _;

// ---------------------------------------------------------------------------
// IPv4
// ---------------------------------------------------------------------------

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Ipv4(pub [u8; 4]);

impl Ipv4 {
    pub const UNSPECIFIED: Ipv4 = Ipv4([0, 0, 0, 0]);

    pub fn is_unspecified(&self) -> bool {
        self.0 == [0, 0, 0, 0]
    }

    /// Parse a dotted quad. Rejects empty octets, values above 255, leading
    /// `+`/`-`, and any count of parts other than four.
    pub fn parse(s: &str) -> Option<Ipv4> {
        let mut out = [0u8; 4];
        let mut seen = 0usize;
        for part in s.split('.') {
            if seen >= 4 || part.is_empty() || part.len() > 3 {
                return None;
            }
            let mut v: u32 = 0;
            for c in part.bytes() {
                if !c.is_ascii_digit() {
                    return None;
                }
                v = v * 10 + (c - b'0') as u32;
            }
            if v > 255 {
                return None;
            }
            out[seen] = v as u8;
            seen += 1;
        }
        if seen != 4 {
            return None;
        }
        Some(Ipv4(out))
    }
}

impl core::fmt::Display for Ipv4 {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}.{}.{}.{}", self.0[0], self.0[1], self.0[2], self.0[3])
    }
}

/// Subnet comparison.
///
/// Returns None for "cannot tell", which is a distinct answer from "not on the
/// same subnet" and must not be conflated with it. An unknown mask that got
/// treated as a mismatch would send every pinned target to the gateway.
pub fn same_subnet(a: Ipv4, b: Ipv4, mask: Ipv4) -> Option<bool> {
    if mask.is_unspecified() || a.is_unspecified() || b.is_unspecified() {
        return None;
    }
    for i in 0..4 {
        if (a.0[i] & mask.0[i]) != (b.0[i] & mask.0[i]) {
            return Some(false);
        }
    }
    Some(true)
}

// ---------------------------------------------------------------------------
// Targets
// ---------------------------------------------------------------------------

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum TargetPin {
    /// Follow the DHCP gateway. On a phone hotspot the gateway IS the phone,
    /// which is where the listener runs, and it survives a subnet change with
    /// no edit anywhere.
    Auto,
    Pinned(Ipv4),
}

impl TargetPin {
    pub fn parse(s: &str) -> Option<TargetPin> {
        let t = s.trim();
        if t.is_empty() || t.eq_ignore_ascii_case("auto") || t.eq_ignore_ascii_case("gateway") {
            return Some(TargetPin::Auto);
        }
        Ipv4::parse(t).map(TargetPin::Pinned)
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum NoTarget {
    /// "auto" was asked for but DHCP has not produced a gateway yet.
    NoGateway,
    /// The only candidate was this device, and there is no usable gateway to
    /// fall back to.
    WouldBeSelf,
}

/// What resolution decided, and why. The caller logs it; the variants exist so
/// a surprising outcome is visible rather than silent.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Resolved {
    /// Pin accepted as written.
    Pinned(Ipv4),
    /// "auto" followed the DHCP gateway.
    Gateway(Ipv4),
    /// Pin is off our subnet. Unreachable as written, so the gateway is used
    /// instead and the operator is told loudly.
    OffSubnet { wanted: Ipv4, used: Ipv4 },
    /// The candidate was this device's own address. A packet sent there never
    /// leaves the radio while every send still reports OK, which is the exact
    /// silent failure this module exists to end.
    SelfAddress { rejected: Ipv4, used: Ipv4 },
    /// Nowhere to send. The send path treats this as "do not send" rather than
    /// as an error, so the harvester keeps running and keeps its budget.
    None(NoTarget),
}

impl Resolved {
    pub fn address(&self) -> Option<Ipv4> {
        match *self {
            Resolved::Pinned(a) => Some(a),
            Resolved::Gateway(a) => Some(a),
            Resolved::OffSubnet { used, .. } => Some(used),
            Resolved::SelfAddress { used, .. } => Some(used),
            Resolved::None(_) => None,
        }
    }

    /// True when the operator should see this in the log even on a quiet boot.
    pub fn is_notable(&self) -> bool {
        !matches!(self, Resolved::Pinned(_) | Resolved::Gateway(_))
    }
}

/// Resolve one target against the link state we actually have.
///
/// Order of precedence:
///   1. a pin that is on our subnet wins outright
///   2. a pin that is off our subnet loses to the gateway
///   3. "auto" takes the gateway
///   4. anything resolving to our own address is rejected and recovered
pub fn resolve(
    pin: TargetPin,
    own_ip: Option<Ipv4>,
    netmask: Option<Ipv4>,
    gateway: Option<Ipv4>,
) -> Resolved {
    let gw = gateway.filter(|g| !g.is_unspecified());

    let candidate = match pin {
        TargetPin::Pinned(p) => {
            let off_subnet = match (own_ip, netmask) {
                (Some(ip), Some(mask)) => same_subnet(p, ip, mask) == Some(false),
                _ => false,
            };
            if off_subnet {
                match gw {
                    Some(g) => Resolved::OffSubnet { wanted: p, used: g },
                    // No gateway to recover to. Keep the pin: it is probably
                    // wrong, but refusing to send at all is worse than trying.
                    None => Resolved::Pinned(p),
                }
            } else {
                Resolved::Pinned(p)
            }
        }
        TargetPin::Auto => match gw {
            Some(g) => Resolved::Gateway(g),
            None => return Resolved::None(NoTarget::NoGateway),
        },
    };

    // Self-address guard, applied last so it catches a pin, a gateway, and a
    // fallback alike.
    if let (Some(ip), Some(addr)) = (own_ip, candidate.address()) {
        if addr == ip {
            return match gw.filter(|g| *g != ip) {
                Some(g) => Resolved::SelfAddress {
                    rejected: addr,
                    used: g,
                },
                None => Resolved::None(NoTarget::WouldBeSelf),
            };
        }
    }

    candidate
}

// ---------------------------------------------------------------------------
// Control plane
// ---------------------------------------------------------------------------
//
// Same text protocol over UDP and USB serial, matching Spectra so the same
// operator habits carry across the fleet.
//
//   GET
//   HELP
//   SET ip=auto | ip=10.153.103.30
//   SET strum_ip=auto entropy_ip=10.153.103.30
//   SET port=5008 entropy_port=5059
//   SET udp=0|1
//   SET reset=accel_x | reset=all
//   SET h_accel_x=3.5
//
// The `h_` form is why the control plane matters more here than it did on
// Spectra: after a Phase 0 bench run produces real per-axis min-entropy
// figures, they are typed in over the wire and the cutoffs recompute live. No
// reflash, no rebuild, no edit to a constant.

// ---------------------------------------------------------------------------
// Runtime Wi-Fi credentials
// ---------------------------------------------------------------------------

/// A fixed-capacity credential pair that can cross an Embassy channel without
/// allocating. `Debug` is deliberately not implemented: an accidental debug
/// print must not disclose the password.
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct WifiCredentials {
    ssid: [u8; 32],
    ssid_len: u8,
    password: [u8; 64],
    password_len: u8,
}

impl WifiCredentials {
    pub fn new(ssid: &str, password: &str) -> Result<Self, &'static str> {
        let ssid_bytes = ssid.as_bytes();
        let password_bytes = password.as_bytes();

        if ssid_bytes.is_empty() || ssid_bytes.len() > 32 {
            return Err("bad_wifi_ssid");
        }
        // Empty selects an open network. WPA/WPA2 passphrases are 8..=63
        // characters; a 64-byte value is accepted for controllers that allow
        // a precomputed hexadecimal PSK.
        if !password_bytes.is_empty() && !(8..=64).contains(&password_bytes.len()) {
            return Err("bad_wifi_password_length");
        }
        // Control characters make status/log lines ambiguous. A quote would
        // make WIFI GET impossible to copy and paste without an escape grammar.
        if ssid_bytes
            .iter()
            .chain(password_bytes.iter())
            .any(|b| b.is_ascii_control() || *b == b'"')
        {
            return Err("bad_wifi_character");
        }

        let mut result = Self {
            ssid: [0; 32],
            ssid_len: ssid_bytes.len() as u8,
            password: [0; 64],
            password_len: password_bytes.len() as u8,
        };
        result.ssid[..ssid_bytes.len()].copy_from_slice(ssid_bytes);
        result.password[..password_bytes.len()].copy_from_slice(password_bytes);
        Ok(result)
    }

    pub fn ssid(&self) -> &str {
        // Construction only accepts slices copied from valid UTF-8 strings.
        core::str::from_utf8(&self.ssid[..self.ssid_len as usize]).unwrap_or("")
    }

    pub fn password(&self) -> &str {
        core::str::from_utf8(&self.password[..self.password_len as usize]).unwrap_or("")
    }

    pub fn is_open(&self) -> bool {
        self.password_len == 0
    }
}

#[derive(Copy, Clone, PartialEq, Eq)]
pub enum WifiAction {
    Get,
    Defaults,
    Set(WifiCredentials),
    Err(&'static str),
}

/// Return `None` when the line is not a Wi-Fi command, leaving the ordinary
/// control parser to handle it. Wi-Fi updates are atomic: a complete validated
/// SSID/password pair is produced or no state changes.
///
/// Supported forms:
///   WIFI GET
///   WIFI DEFAULT
///   WIFI "SSID with spaces" "password with spaces"
///   WIFI SimpleSSID simple-password
pub fn parse_wifi_command(line: &str) -> Option<WifiAction> {
    let line = line.trim();
    let verb_end = line
        .bytes()
        .position(|b| b.is_ascii_whitespace())
        .unwrap_or(line.len());
    let verb = &line[..verb_end];

    if verb.eq_ignore_ascii_case("WIFI?") && verb_end == line.len() {
        return Some(WifiAction::Get);
    }
    if !verb.eq_ignore_ascii_case("WIFI") {
        return None;
    }

    let rest = line[verb_end..].trim();
    if rest.eq_ignore_ascii_case("GET") || rest == "?" {
        return Some(WifiAction::Get);
    }
    if rest.eq_ignore_ascii_case("DEFAULT") || rest.eq_ignore_ascii_case("DEFAULTS") {
        return Some(WifiAction::Defaults);
    }
    if rest.is_empty() {
        return Some(WifiAction::Err("wifi_usage"));
    }

    let (ssid, rest) = match take_wifi_field(rest) {
        Ok(field) => field,
        Err(why) => return Some(WifiAction::Err(why)),
    };
    let (password, trailing) = match take_wifi_field(rest) {
        Ok(field) => field,
        Err(why) => return Some(WifiAction::Err(why)),
    };
    if !trailing.trim().is_empty() {
        return Some(WifiAction::Err("wifi_too_many_args"));
    }

    Some(match WifiCredentials::new(ssid, password) {
        Ok(credentials) => WifiAction::Set(credentials),
        Err(why) => WifiAction::Err(why),
    })
}

fn take_wifi_field(input: &str) -> Result<(&str, &str), &'static str> {
    let input = input.trim_start();
    if input.is_empty() {
        return Err("wifi_missing_arg");
    }

    if let Some(quoted) = input.strip_prefix('"') {
        let Some(end) = quoted.find('"') else {
            return Err("wifi_unclosed_quote");
        };
        let value = &quoted[..end];
        let trailing = &quoted[end + 1..];
        if trailing
            .as_bytes()
            .first()
            .is_some_and(|b| !b.is_ascii_whitespace())
        {
            return Err("wifi_bad_quote");
        }
        Ok((value, trailing))
    } else {
        let end = input
            .bytes()
            .position(|b| b.is_ascii_whitespace())
            .unwrap_or(input.len());
        Ok((&input[..end], &input[end..]))
    }
}

/// Decode the `application/x-www-form-urlencoded` body submitted by the setup
/// page. This is allocation-free and returns the same validated atomic pair as
/// the USB command parser.
pub fn parse_wifi_form(body: &str) -> Result<WifiCredentials, &'static str> {
    let mut ssid_buf = [0u8; 32];
    let mut password_buf = [0u8; 64];
    let mut ssid_len = None;
    let mut password_len = None;

    for item in body.split('&') {
        let Some((key, value)) = item.split_once('=') else {
            return Err("bad_wifi_form");
        };
        match key {
            "ssid" if ssid_len.is_none() => {
                ssid_len = Some(decode_form_component(value, &mut ssid_buf)?);
            }
            "password" if password_len.is_none() => {
                password_len = Some(decode_form_component(value, &mut password_buf)?);
            }
            "ssid" | "password" => return Err("duplicate_wifi_field"),
            _ => {}
        }
    }

    let ssid = core::str::from_utf8(&ssid_buf[..ssid_len.ok_or("missing_wifi_ssid")?])
        .map_err(|_| "bad_wifi_utf8")?;
    let password =
        core::str::from_utf8(&password_buf[..password_len.ok_or("missing_wifi_password")?])
            .map_err(|_| "bad_wifi_utf8")?;
    WifiCredentials::new(ssid, password)
}

fn decode_form_component(input: &str, output: &mut [u8]) -> Result<usize, &'static str> {
    let bytes = input.as_bytes();
    let mut src = 0usize;
    let mut dst = 0usize;
    while src < bytes.len() {
        if dst == output.len() {
            return Err("wifi_field_too_long");
        }
        match bytes[src] {
            b'+' => {
                output[dst] = b' ';
                src += 1;
            }
            b'%' => {
                if src + 2 >= bytes.len() {
                    return Err("bad_wifi_percent_encoding");
                }
                let high = hex_nibble(bytes[src + 1]).ok_or("bad_wifi_percent_encoding")?;
                let low = hex_nibble(bytes[src + 2]).ok_or("bad_wifi_percent_encoding")?;
                output[dst] = (high << 4) | low;
                src += 3;
            }
            byte => {
                output[dst] = byte;
                src += 1;
            }
        }
        dst += 1;
    }
    Ok(dst)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

pub const MAX_OPS: usize = 8;

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Op {
    StrumTarget(TargetPin),
    EntropyTarget(TargetPin),
    StrumPort(u16),
    EntropyPort(u16),
    UdpEnable(bool),
    /// None means every source.
    ResetHealth(Option<usize>),
    /// (source index, min-entropy in 1/256-bit units)
    SetH(usize, u16),
    /// Minimum milliseconds between motion events reaching the relay.
    Debounce(u32),
    /// Acceleration trigger, 8 mg per step against the smoothed,
    /// high-passed signal.
    MotionThreshold(u8),
    /// Rotation trigger, degrees per second. 0 turns it off.
    GyroThreshold(u8),
    /// High-pass corner of the firmware motion detector.
    /// 0 off, 1..=4; see mpu.rs for what each value means.
    Hpf(u8),
    /// Whether the unauthenticated UDP control port accepts commands.
    UdpControl(bool),
    /// Credited sources that must be live before a block is released.
    MinLive(u8),
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Command {
    Get,
    Help,
    Set([Option<Op>; MAX_OPS]),
    /// Write current settings to flash now rather than after the quiet period.
    Save,
    /// Flush any pending save, then restart.
    Reboot,
    /// Erase stored settings and restart on the compiled defaults.
    Factory,
    /// Print the entropy estimates for every source and the output.
    Stats,
    /// Start every running measurement total over.
    StatsReset,
    /// Stream `count` raw samples of one source (by index) over USB for the
    /// NIST SP 800-90B tools. Releases pause until it finishes.
    Dump(usize, u32),
    /// End a capture early.
    DumpStop,
    Err(&'static str),
}

/// Largest single capture. NIST's tools want 1,000,000 samples; this leaves
/// room for a restart-test set without letting a typo run for days.
pub const MAX_DUMP: u32 = 10_000_000;

fn parse_u16(s: &str) -> Option<u16> {
    if s.is_empty() || s.len() > 5 {
        return None;
    }
    let mut v: u32 = 0;
    for c in s.bytes() {
        if !c.is_ascii_digit() {
            return None;
        }
        v = v * 10 + (c - b'0') as u32;
        if v > u16::MAX as u32 {
            return None;
        }
    }
    Some(v as u16)
}

/// Parse a decimal min-entropy like "3.5" or "0.75" into 1/256-bit fixed
/// point. Up to three fractional digits; anything above 8.0 is rejected,
/// because a byte cannot carry more than 8 bits of min-entropy and accepting
/// such a claim would silently inflate the credit budget.
pub fn parse_h(s: &str) -> Option<u16> {
    let mut it = s.split('.');
    let int_part = it.next()?;
    let frac_part = it.next().unwrap_or("0");
    if it.next().is_some() || int_part.is_empty() || int_part.len() > 1 {
        return None;
    }

    let mut whole: u32 = 0;
    for c in int_part.bytes() {
        if !c.is_ascii_digit() {
            return None;
        }
        whole = whole * 10 + (c - b'0') as u32;
    }

    if frac_part.is_empty() || frac_part.len() > 3 {
        return None;
    }
    let mut frac: u32 = 0;
    let mut scale: u32 = 1;
    for c in frac_part.bytes() {
        if !c.is_ascii_digit() {
            return None;
        }
        frac = frac * 10 + (c - b'0') as u32;
        scale *= 10;
    }

    let fixed = whole * 256 + (frac * 256) / scale;
    if fixed > 8 * 256 {
        return None;
    }
    Some(fixed as u16)
}

/// Map a source name to its index. Kept here rather than in entropy.rs so that
/// module stays free of string handling.
pub fn source_index(name: &str) -> Option<usize> {
    Some(match name {
        "accel_x" => 0,
        "accel_y" => 1,
        "accel_z" => 2,
        "gyro_x" => 3,
        "gyro_y" => 4,
        "gyro_z" => 5,
        "mpu_temp" => 6,
        "clock_beat" => 7,
        "motion_timing" => 8,
        "bus_timing" => 9,
        "mpu_frame" => 10,
        "hw_rng" => 11,
        "wifi_rssi" => 12,
        "network_timing" => 13,
        "usb_timing" => 14,
        "adc_noise" => 15,
        _ => return None,
    })
}

pub fn parse_command(line: &str) -> Command {
    let line = line.trim();
    if line.is_empty() {
        return Command::Err("empty");
    }

    let mut words = line.split_ascii_whitespace();
    let verb = match words.next() {
        Some(v) => v,
        None => return Command::Err("empty"),
    };

    if verb.eq_ignore_ascii_case("GET") {
        return Command::Get;
    }
    if verb.eq_ignore_ascii_case("HELP") {
        return Command::Help;
    }

    // Single-word actions. Anything trailing is refused rather than ignored,
    // so a typo like `FACTORY RESET NOW` cannot be half-understood.
    let bare = words.clone().next().is_none();
    if verb.eq_ignore_ascii_case("SAVE") {
        return if bare { Command::Save } else { Command::Err("save_takes_no_args") };
    }
    if verb.eq_ignore_ascii_case("REBOOT") {
        return if bare { Command::Reboot } else { Command::Err("reboot_takes_no_args") };
    }
    if verb.eq_ignore_ascii_case("FACTORY") {
        return if bare { Command::Factory } else { Command::Err("factory_takes_no_args") };
    }
    if verb.eq_ignore_ascii_case("STATS") {
        let mut args = words.clone();
        return match (args.next(), args.next()) {
            (None, _) => Command::Stats,
            (Some(a), None) if a.eq_ignore_ascii_case("RESET") => Command::StatsReset,
            _ => Command::Err("stats_usage"),
        };
    }
    if verb.eq_ignore_ascii_case("DUMP") {
        let mut args = words.clone();
        let (Some(first), second, None) = (args.next(), args.next(), args.next()) else {
            return Command::Err("dump_usage");
        };
        if first.eq_ignore_ascii_case("STOP") && second.is_none() {
            return Command::DumpStop;
        }
        let Some(index) = source_index(first) else {
            return Command::Err("bad_source");
        };
        let mut count: u64 = 0;
        let digits = match second {
            Some(d) if !d.is_empty() && d.len() <= 8 && d.bytes().all(|b| b.is_ascii_digit()) => d,
            _ => return Command::Err("bad_dump_count"),
        };
        for b in digits.bytes() {
            count = count * 10 + (b - b'0') as u64;
        }
        if count == 0 || count > MAX_DUMP as u64 {
            return Command::Err("bad_dump_count");
        }
        return Command::Dump(index, count as u32);
    }

    if !verb.eq_ignore_ascii_case("SET") {
        return Command::Err("unknown_cmd");
    }

    let mut ops: [Option<Op>; MAX_OPS] = [None; MAX_OPS];
    let mut n = 0usize;

    for kv in words {
        if n >= MAX_OPS {
            return Command::Err("too_many_ops");
        }
        let mut split = kv.splitn(2, '=');
        let k = match split.next() {
            Some(k) if !k.is_empty() => k,
            _ => return Command::Err("bad_kv"),
        };
        let v = match split.next() {
            Some(v) => v,
            None => return Command::Err("bad_kv"),
        };

        let op = if let Some(src) = k.strip_prefix("h_") {
            let idx = match source_index(src) {
                Some(i) => i,
                None => return Command::Err("bad_source"),
            };
            let h = match parse_h(v) {
                Some(h) => h,
                None => return Command::Err("bad_h"),
            };
            // An assessment only counts on a source that may be credited at
            // all; refuse rather than accept a number that silently does
            // nothing.
            if h > 0 && !crate::entropy::SourceId::ALL[idx].creditable() {
                return Command::Err("source_not_creditable");
            }
            Op::SetH(idx, h)
        } else {
            match k {
                // `ip` drives BOTH targets, which is the common case: one
                // phone carrying the relay for pings and entropy alike.
                "ip" => {
                    let t = match TargetPin::parse(v) {
                        Some(t) => t,
                        None => return Command::Err("bad_ip"),
                    };
                    ops[n] = Some(Op::StrumTarget(t));
                    n += 1;
                    if n >= MAX_OPS {
                        return Command::Err("too_many_ops");
                    }
                    ops[n] = Some(Op::EntropyTarget(t));
                    n += 1;
                    continue;
                }
                "strum_ip" | "sip" => match TargetPin::parse(v) {
                    Some(t) => Op::StrumTarget(t),
                    None => return Command::Err("bad_strum_ip"),
                },
                "entropy_ip" | "eip" => match TargetPin::parse(v) {
                    Some(t) => Op::EntropyTarget(t),
                    None => return Command::Err("bad_entropy_ip"),
                },
                "port" => match parse_u16(v).filter(|p| crate::persist::data_port_allowed(*p)) {
                    Some(p) => Op::StrumPort(p),
                    None => return Command::Err("bad_port"),
                },
                "entropy_port" => match parse_u16(v).filter(|p| crate::persist::data_port_allowed(*p)) {
                    Some(p) => Op::EntropyPort(p),
                    None => return Command::Err("bad_entropy_port"),
                },
                "udp" => Op::UdpEnable(matches!(v, "1" | "true" | "True" | "on" | "ON")),
                // Bounded here to the same limits the save path enforces, so a
                // live change can never produce a value that refuses to persist.
                "debounce" => match parse_u16(v).filter(|ms| *ms <= crate::persist::MAX_DEBOUNCE_MS) {
                    Some(ms) => Op::Debounce(ms as u32),
                    None => return Command::Err("bad_debounce"),
                },
                "mot_thr" => match parse_u16(v).filter(|t| (1..=255).contains(t)) {
                    Some(t) => Op::MotionThreshold(t as u8),
                    None => return Command::Err("bad_mot_thr"),
                },
                "gyro_thr" => match parse_u16(v).filter(|t| *t <= 255) {
                    Some(t) => Op::GyroThreshold(t as u8),
                    None => return Command::Err("bad_gyro_thr"),
                },
                "hpf" => match parse_u16(v).filter(|h| *h <= 4 && crate::persist::valid_hpf(*h as u8)) {
                    Some(h) => Op::Hpf(h as u8),
                    None => return Command::Err("bad_hpf"),
                },
                "udpctl" => Op::UdpControl(matches!(v, "1" | "true" | "True" | "on" | "ON")),
                "min_live" => match parse_u16(v)
                    .filter(|n| *n >= 1 && *n as usize <= crate::entropy::SOURCE_COUNT)
                {
                    Some(n) => Op::MinLive(n as u8),
                    None => return Command::Err("bad_min_live"),
                },
                "reset" => {
                    if v.eq_ignore_ascii_case("all") {
                        Op::ResetHealth(None)
                    } else {
                        match source_index(v) {
                            Some(i) => Op::ResetHealth(Some(i)),
                            None => return Command::Err("bad_source"),
                        }
                    }
                }
                _ => return Command::Err("bad_key"),
            }
        };

        ops[n] = Some(op);
        n += 1;
    }

    if n == 0 {
        return Command::Err("set_without_args");
    }
    Command::Set(ops)
}

// ---------------------------------------------------------------------------
// Small formatting buffer
// ---------------------------------------------------------------------------
//
// core::fmt::Write into a fixed array, so replies can be built without an
// allocator and without pulling in heapless.

#[derive(Clone, Copy)]
pub struct Buf<const N: usize> {
    data: [u8; N],
    len: usize,
    overflowed: bool,
}

impl<const N: usize> Buf<N> {
    pub const fn new() -> Self {
        Buf {
            data: [0u8; N],
            len: 0,
            overflowed: false,
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.data[..self.len]
    }

    pub fn as_str(&self) -> &str {
        // Only ever written through core::fmt, which emits valid UTF-8, and
        // truncation happens on a char boundary because a partial write is
        // rejected wholesale below.
        core::str::from_utf8(self.as_bytes()).unwrap_or("")
    }

    pub fn clear(&mut self) {
        self.len = 0;
        self.overflowed = false;
    }

    pub fn overflowed(&self) -> bool {
        self.overflowed
    }
}

impl<const N: usize> core::fmt::Write for Buf<N> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let b = s.as_bytes();
        if self.len + b.len() > N {
            // Drop the whole fragment rather than half of it, which keeps the
            // buffer valid UTF-8 at every point.
            self.overflowed = true;
            return Err(core::fmt::Error);
        }
        self.data[self.len..self.len + b.len()].copy_from_slice(b);
        self.len += b.len();
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Status reply
// ---------------------------------------------------------------------------

#[derive(Copy, Clone, Debug)]
pub struct Status {
    pub strum_pin: TargetPin,
    pub entropy_pin: TargetPin,
    pub strum: Resolved,
    pub entropy: Resolved,
    pub strum_port: u16,
    pub entropy_port: u16,
    pub udp_enabled: bool,
    pub live_credited: usize,
    pub budget_percent: u32,
    pub releases: u32,
}

fn write_pin<const N: usize>(b: &mut Buf<N>, p: TargetPin) {
    match p {
        TargetPin::Auto => {
            let _ = write!(b, "auto");
        }
        TargetPin::Pinned(a) => {
            let _ = write!(b, "{}", a);
        }
    }
}

fn write_resolved<const N: usize>(b: &mut Buf<N>, r: Resolved) {
    match r.address() {
        Some(a) => {
            let _ = write!(b, "{}", a);
        }
        None => {
            let _ = write!(b, "unresolved");
        }
    }
}

pub fn format_status<const N: usize>(b: &mut Buf<N>, s: &Status) {
    b.clear();
    let _ = write!(b, "OK strum_ip=");
    write_pin(b, s.strum_pin);
    let _ = write!(b, " strum=");
    write_resolved(b, s.strum);
    let _ = write!(b, ":{} entropy_ip=", s.strum_port);
    write_pin(b, s.entropy_pin);
    let _ = write!(b, " entropy=");
    write_resolved(b, s.entropy);
    let _ = write!(
        b,
        ":{} udp={} live={} budget={}% keys={}",
        s.entropy_port,
        if s.udp_enabled { 1 } else { 0 },
        s.live_credited,
        s.budget_percent,
        s.releases
    );
}

pub const HELP_TEXT: &str =
    "OK cmds: GET | STATS | STATS RESET | SAVE | REBOOT | FACTORY | PASS \"new password\" | WIFI GET | \
     WIFI DEFAULT | WIFI \"ssid\" \"password\" | SET ip=auto|a.b.c.d | strum_ip= | \
     entropy_ip= | port= | entropy_port= | udp=0|1 | udpctl=0|1 | debounce=<ms> | \
     mot_thr=<1-255 x8 mg> | gyro_thr=<0-255 deg/s, 0 off> | hpf=<0-4> | min_live=<1-16> | reset=<source>|all | h_<source>=<bits e.g. 3.5> | \
     USB only: DUMP <source> <count> | DUMP STOP";

// Every reply buffer is 512 bytes.
const _: () = assert!(HELP_TEXT.len() < 512);

// ---------------------------------------------------------------------------
// Admin password
// ---------------------------------------------------------------------------

/// The dashboard password. Like WifiCredentials, `Debug` is deliberately not
/// implemented so an accidental debug print cannot disclose it.
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct AdminPassword {
    bytes: [u8; 64],
    len: u8,
}

impl AdminPassword {
    pub fn new(password: &str) -> Result<Self, &'static str> {
        let b = password.as_bytes();
        if b.len() < 8 || b.len() > 64 {
            return Err("bad_pass_length");
        }
        if b.iter().any(|c| c.is_ascii_control() || *c == b'"') {
            return Err("bad_pass_character");
        }
        let mut bytes = [0u8; 64];
        bytes[..b.len()].copy_from_slice(b);
        Ok(AdminPassword {
            bytes,
            len: b.len() as u8,
        })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }
}

#[derive(Copy, Clone, PartialEq, Eq)]
pub enum AdminAction {
    Set(AdminPassword),
    Err(&'static str),
}

/// `PASS "new password"`. Returns None when the line is not a PASS command.
///
/// Only accepted over USB and the authenticated dashboard; main.rs refuses it
/// on the UDP control port, which has no authentication of its own.
pub fn parse_admin_command(line: &str) -> Option<AdminAction> {
    let line = line.trim();
    let verb_end = line
        .bytes()
        .position(|b| b.is_ascii_whitespace())
        .unwrap_or(line.len());
    if !line[..verb_end].eq_ignore_ascii_case("PASS") {
        return None;
    }
    let rest = line[verb_end..].trim();
    if rest.is_empty() {
        return Some(AdminAction::Err("pass_usage"));
    }
    let (value, trailing) = match take_wifi_field(rest) {
        Ok(field) => field,
        Err(why) => return Some(AdminAction::Err(why)),
    };
    if !trailing.trim().is_empty() {
        return Some(AdminAction::Err("pass_too_many_args"));
    }
    Some(match AdminPassword::new(value) {
        Ok(p) => AdminAction::Set(p),
        Err(why) => AdminAction::Err(why),
    })
}

/// Constant-time comparison, so a wrong password does not leak how many
/// leading bytes it got right through response timing.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

// ---------------------------------------------------------------------------
// Base64 (RFC 4648), decode only, for HTTP Basic authentication
// ---------------------------------------------------------------------------

fn b64_value(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// Decode padded base64 into `out`. Returns the number of bytes written, or
/// None for malformed input or insufficient space.
pub fn base64_decode(input: &[u8], out: &mut [u8]) -> Option<usize> {
    if input.len() % 4 != 0 {
        return None;
    }
    let mut written = 0usize;
    for (i, chunk) in input.chunks(4).enumerate() {
        let last = (i + 1) * 4 == input.len();
        let pad = chunk.iter().rev().take_while(|c| **c == b'=').count();
        if pad > 2 || (pad > 0 && !last) {
            return None;
        }
        let mut v = [0u8; 4];
        for (j, c) in chunk.iter().enumerate() {
            v[j] = if j >= 4 - pad { 0 } else { b64_value(*c)? };
        }
        let n = ((v[0] as u32) << 18) | ((v[1] as u32) << 12) | ((v[2] as u32) << 6) | v[3] as u32;
        let bytes = [(n >> 16) as u8, (n >> 8) as u8, n as u8];
        let take = 3 - pad;
        if written + take > out.len() {
            return None;
        }
        out[written..written + take].copy_from_slice(&bytes[..take]);
        written += take;
    }
    Some(written)
}

/// Extract the password from an `Authorization: Basic ...` header value,
/// provided the username matches. The decoded pair is written into `scratch`.
pub fn basic_auth_password<'a>(
    header_value: &str,
    expected_user: &str,
    scratch: &'a mut [u8; 192],
) -> Option<&'a [u8]> {
    let v = header_value.trim();
    let (scheme, encoded) = v.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("Basic") {
        return None;
    }
    let n = base64_decode(encoded.trim().as_bytes(), scratch)?;
    let pair = &scratch[..n];
    let colon = pair.iter().position(|b| *b == b':')?;
    if !ct_eq(&pair[..colon], expected_user.as_bytes()) {
        return None;
    }
    Some(&pair[colon + 1..])
}

// ---------------------------------------------------------------------------
// HTTP request parsing
// ---------------------------------------------------------------------------

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum HttpParse {
    /// Need more bytes: headers not finished, or body shorter than declared.
    Incomplete,
    Bad(&'static str),
}

#[derive(Copy, Clone, Debug)]
pub struct HttpRequest<'a> {
    pub method: &'a str,
    /// Path with any query string removed.
    pub path: &'a str,
    pub headers: &'a str,
    pub body: &'a [u8],
    /// Total bytes of `raw` this request occupied.
    pub consumed: usize,
}

pub fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    haystack.windows(needle.len()).position(|w| w == needle)
}

/// Case-insensitive header lookup over the header block (request line
/// excluded). Returns the trimmed value.
pub fn header<'a>(headers: &'a str, name: &str) -> Option<&'a str> {
    for line in headers.split("\r\n") {
        if let Some((k, v)) = line.split_once(':') {
            if k.trim().eq_ignore_ascii_case(name) {
                return Some(v.trim());
            }
        }
    }
    None
}

pub fn parse_http(raw: &[u8], max_body: usize) -> Result<HttpRequest<'_>, HttpParse> {
    let head_end = find_bytes(raw, b"\r\n\r\n").ok_or(HttpParse::Incomplete)?;
    let head = core::str::from_utf8(&raw[..head_end]).map_err(|_| HttpParse::Bad("head_utf8"))?;
    let (request_line, headers) = head.split_once("\r\n").unwrap_or((head, ""));

    let mut parts = request_line.split(' ');
    let method = parts.next().filter(|m| !m.is_empty()).ok_or(HttpParse::Bad("method"))?;
    let target = parts.next().filter(|p| p.starts_with('/')).ok_or(HttpParse::Bad("path"))?;
    let version = parts.next().ok_or(HttpParse::Bad("version"))?;
    if !version.starts_with("HTTP/1.") || parts.next().is_some() {
        return Err(HttpParse::Bad("version"));
    }
    let path = target.split('?').next().unwrap_or(target);

    let body_len = match header(headers, "content-length") {
        None => 0,
        Some(v) => {
            let mut n = 0usize;
            if v.is_empty() {
                return Err(HttpParse::Bad("content_length"));
            }
            for b in v.bytes() {
                if !b.is_ascii_digit() {
                    return Err(HttpParse::Bad("content_length"));
                }
                n = n
                    .checked_mul(10)
                    .and_then(|n| n.checked_add((b - b'0') as usize))
                    .ok_or(HttpParse::Bad("content_length"))?;
            }
            n
        }
    };
    if body_len > max_body {
        return Err(HttpParse::Bad("body_too_large"));
    }
    let body_start = head_end + 4;
    let body_end = body_start + body_len;
    if raw.len() < body_end {
        return Err(HttpParse::Incomplete);
    }
    Ok(HttpRequest {
        method,
        path,
        headers,
        body: &raw[body_start..body_end],
        consumed: body_end,
    })
}

// ---------------------------------------------------------------------------
// JSON string output
// ---------------------------------------------------------------------------

/// Write `s` as a quoted JSON string. Escapes quotes, backslashes and control
/// characters; an SSID is operator-supplied and must not be able to break the
/// status document the dashboard parses.
pub fn write_json_str<const N: usize>(b: &mut Buf<N>, s: &str) {
    let _ = b.write_str("\"");
    for c in s.chars() {
        let _ = match c {
            '"' => b.write_str("\\\""),
            '\\' => b.write_str("\\\\"),
            '\n' => b.write_str("\\n"),
            '\r' => b.write_str("\\r"),
            '\t' => b.write_str("\\t"),
            c if (c as u32) < 0x20 => write!(b, "\\u{:04x}", c as u32),
            c => b.write_char(c),
        };
    }
    let _ = b.write_str("\"");
}

// ---------------------------------------------------------------------------
// Dashboard status document
// ---------------------------------------------------------------------------
//
// main.rs copies everything out under the shared lock into a `Dashboard`, and
// the JSON is built here, outside the lock and testable on the host.
//
// The document carries health, counters and settings. There is no field for
// key material, so no future edit can leak a block through it by accident.

#[derive(Copy, Clone, Debug)]
pub struct SourceRow {
    pub name: &'static str,
    /// H healthy, D degraded, W warming, F failed.
    pub verdict: char,
    pub credited: bool,
    /// Assessed min-entropy, 1/256 bit.
    pub h: u16,
    pub rct: u32,
    pub apt: u32,
    /// Last Markov estimate, 1/256 bit per raw bit.
    pub markov: u16,
    /// Last completed Shannon/min-entropy window (n 0 when none yet).
    pub est_n: u16,
    pub shannon: u16,
    pub min: u16,
    /// Samples collected toward the next window, and the window size.
    pub progress: u16,
    pub window: u16,
    /// Worst RCT run and worst APT count seen, against their cutoffs.
    pub rct_max: u32,
    pub rct_cut: u32,
    pub apt_max: u32,
    pub apt_cut: u32,
    /// Running total since the last measurement reset (n 0 when none yet).
    pub tot_n: u32,
    pub tot_shannon: u16,
    pub tot_min: u16,
    /// Whole bits of this source's credit spent on released blocks since the
    /// last measurement reset.
    pub funded_bits: u64,
}

/// The conditioned output, as the dashboard shows it.
#[derive(Copy, Clone, Debug, Default)]
pub struct OutputRow {
    pub bytes: u64,
    pub est_n: u16,
    pub shannon: u16,
    pub min: u16,
    pub progress: u16,
    pub window: u16,
    pub markov: u16,
    pub rct_max: u32,
    pub rct_cut: u32,
    pub rct_fail: u32,
    pub apt_max: u32,
    pub apt_cut: u32,
    pub apt_fail: u32,
    pub tot_n: u32,
    pub tot_shannon: u16,
    pub tot_min: u16,
}

pub struct Dashboard<'a> {
    pub uptime_ms: u64,
    pub admin_default: bool,
    pub reset: &'static str,
    pub live: usize,
    pub min_live: usize,
    pub keys: u32,
    pub budget: u32,
    pub motion_raw: u32,
    pub motion_events: u32,
    pub mpu_ready: bool,
    pub mpu_addr: u8,
    pub mpu_chip: &'static str,
    /// Why the MPU is not running, in words. Empty when it is.
    pub mpu_error: &'a str,
    /// Pins, bus speed and INT mode once the MPU is running. Empty otherwise.
    pub mpu_link: &'a str,
    /// Largest movement in the last quarter second, mg.
    pub motion_level_mg: u32,
    /// Largest rotation in the last quarter second, tenths of a degree/s.
    pub gyro_level_dps10: u32,
    pub frames: u32,
    pub faults: u32,
    pub mot_thr: u8,
    pub gyro_thr: u8,
    pub debounce_ms: u32,
    pub hpf: u8,
    pub sources: &'a [SourceRow],
    pub output: OutputRow,
    /// Source being captured by DUMP, if any, and samples still to go.
    pub dump: Option<(&'static str, u32)>,
    pub ssid: &'a str,
    pub wifi_up: bool,
    pub ip: Option<Ipv4>,
    pub gw: Option<Ipv4>,
    pub rssi: i8,
    pub strum: Resolved,
    pub strum_pin: TargetPin,
    pub entropy: Resolved,
    pub entropy_pin: TargetPin,
    pub strum_port: u16,
    pub entropy_port: u16,
    pub udp: bool,
    pub udpctl: bool,
    pub sent_entropy: u32,
    pub sent_strum: u32,
    pub sent_heartbeat: u32,
    pub send_errors: u32,
    pub save_state: &'static str,
    pub save_writes: u32,
    pub wdt: bool,
}

/// Where packets for one target are actually going, and why if that is not
/// what was asked for.
pub fn describe_target<const N: usize>(b: &mut Buf<N>, r: Resolved, port: u16) {
    match r.address() {
        Some(a) => {
            let _ = write!(b, "{a}:{port}");
        }
        None => {
            let _ = b.write_str("unresolved");
        }
    }
    let _ = match r {
        Resolved::OffSubnet { wanted, .. } => {
            write!(b, ", pin {wanted} is off this subnet so the gateway is used")
        }
        Resolved::SelfAddress { rejected, .. } => {
            write!(b, ", pin {rejected} is this node so the gateway is used")
        }
        Resolved::None(NoTarget::NoGateway) => b.write_str(", no gateway yet"),
        Resolved::None(NoTarget::WouldBeSelf) => b.write_str(", only candidate is this node"),
        _ => Ok(()),
    };
}

fn json_bool(v: bool) -> &'static str {
    if v {
        "true"
    } else {
        "false"
    }
}

fn write_json_ip<const N: usize>(b: &mut Buf<N>, ip: Option<Ipv4>) {
    let _ = b.write_str("\"");
    if let Some(ip) = ip {
        let _ = write!(b, "{ip}");
    }
    let _ = b.write_str("\"");
}

/// Buffer size for the status document. The worst-case test below fills
/// every field at its longest and checks it still fits.
pub const STATUS_JSON_LEN: usize = 6144;

pub fn format_dashboard_json<const N: usize>(b: &mut Buf<N>, d: &Dashboard) {
    b.clear();
    let _ = write!(
        b,
        "{{\"uptime_ms\":{},\"admin_default\":{},\"reset\":",
        d.uptime_ms,
        json_bool(d.admin_default)
    );
    write_json_str(b, d.reset);
    let _ = write!(
        b,
        ",\"harvest\":{{\"live\":{},\"min\":{},\"keys\":{},\"budget\":{}}}",
        d.live, d.min_live, d.keys, d.budget
    );
    let _ = write!(
        b,
        ",\"motion\":{{\"raw\":{},\"events\":{},\"level_mg\":{},\"gyro_dps10\":{}}}",
        d.motion_raw, d.motion_events, d.motion_level_mg, d.gyro_level_dps10
    );
    let _ = write!(
        b,
        ",\"mpu\":{{\"ready\":{},\"addr\":{},\"frames\":{},\"faults\":{},\"thr\":{},\"gthr\":{},\"debounce\":{},\"hpf\":{},\"chip\":",
        json_bool(d.mpu_ready),
        d.mpu_addr,
        d.frames,
        d.faults,
        d.mot_thr,
        d.gyro_thr,
        d.debounce_ms,
        d.hpf
    );
    write_json_str(b, d.mpu_chip);
    let _ = b.write_str(",\"error\":");
    write_json_str(b, d.mpu_error);
    let _ = b.write_str(",\"link\":");
    write_json_str(b, d.mpu_link);
    let _ = b.write_str("}");

    let _ = b.write_str(",\"sources\":[");
    for (i, row) in d.sources.iter().enumerate() {
        if i > 0 {
            let _ = b.write_str(",");
        }
        let _ = b.write_str("[");
        write_json_str(b, row.name);
        let mut verdict = [0u8; 4];
        let _ = b.write_str(",");
        write_json_str(b, row.verdict.encode_utf8(&mut verdict));
        let _ = write!(
            b,
            ",{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}]",
            json_bool(row.credited),
            row.h,
            row.rct,
            row.apt,
            row.markov,
            row.est_n,
            row.shannon,
            row.min,
            row.progress,
            row.window,
            row.rct_max,
            row.rct_cut,
            row.apt_max,
            row.apt_cut,
            row.tot_n,
            row.tot_shannon,
            row.tot_min,
            row.funded_bits
        );
    }
    let _ = b.write_str("]");
    let o = &d.output;
    let _ = write!(
        b,
        ",\"output\":{{\"bytes\":{},\"n\":{},\"shannon\":{},\"min\":{},\"progress\":{},\"window\":{},\"markov\":{},\"rct\":[{},{},{}],\"apt\":[{},{},{}],\"total\":[{},{},{}]}}",
        o.bytes, o.est_n, o.shannon, o.min, o.progress, o.window, o.markov,
        o.rct_max, o.rct_cut, o.rct_fail, o.apt_max, o.apt_cut, o.apt_fail,
        o.tot_n, o.tot_shannon, o.tot_min
    );
    let _ = b.write_str(",\"dump\":");
    match d.dump {
        Some((name, left)) => {
            let _ = b.write_str("{\"source\":");
            write_json_str(b, name);
            let _ = write!(b, ",\"left\":{}}}", left);
        }
        None => {
            let _ = b.write_str("null");
        }
    }

    let _ = b.write_str(",\"wifi\":{\"ssid\":");
    write_json_str(b, d.ssid);
    let _ = write!(b, ",\"up\":{},\"ip\":", json_bool(d.wifi_up));
    write_json_ip(b, d.ip);
    let _ = b.write_str(",\"gw\":");
    write_json_ip(b, d.gw);
    let _ = write!(b, ",\"rssi\":{}}}", d.rssi);

    let mut text: Buf<112> = Buf::new();
    let _ = b.write_str(",\"targets\":{\"strum\":");
    describe_target(&mut text, d.strum, d.strum_port);
    write_json_str(b, text.as_str());
    let _ = b.write_str(",\"strum_pin\":");
    text.clear();
    write_pin(&mut text, d.strum_pin);
    write_json_str(b, text.as_str());
    let _ = b.write_str(",\"entropy\":");
    text.clear();
    describe_target(&mut text, d.entropy, d.entropy_port);
    write_json_str(b, text.as_str());
    let _ = b.write_str(",\"entropy_pin\":");
    text.clear();
    write_pin(&mut text, d.entropy_pin);
    write_json_str(b, text.as_str());
    let _ = write!(
        b,
        ",\"strum_port\":{},\"entropy_port\":{},\"udp\":{},\"udpctl\":{}}}",
        d.strum_port,
        d.entropy_port,
        json_bool(d.udp),
        json_bool(d.udpctl)
    );

    let _ = write!(
        b,
        ",\"sent\":{{\"entropy\":{},\"strum\":{},\"heartbeat\":{},\"errors\":{}}}",
        d.sent_entropy, d.sent_strum, d.sent_heartbeat, d.send_errors
    );
    let _ = b.write_str(",\"save\":{\"state\":");
    write_json_str(b, d.save_state);
    let _ = write!(
        b,
        ",\"writes\":{}}},\"wdt\":{}}}",
        d.save_writes,
        json_bool(d.wdt)
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wifi_command_accepts_quoted_spaces_atomically() {
        let action = parse_wifi_command("WIFI \"My Phone Hotspot\" \"correct horse battery\"");
        let Some(WifiAction::Set(credentials)) = action else {
            panic!("expected valid credentials");
        };
        assert_eq!(credentials.ssid(), "My Phone Hotspot");
        assert_eq!(credentials.password(), "correct horse battery");
    }

    #[test]
    fn wifi_command_supports_status_defaults_and_open_networks() {
        assert!(matches!(parse_wifi_command("WIFI?"), Some(WifiAction::Get)));
        assert!(matches!(
            parse_wifi_command("wifi defaults"),
            Some(WifiAction::Defaults)
        ));
        let Some(WifiAction::Set(credentials)) = parse_wifi_command("WIFI cafe \"\"") else {
            panic!("expected open-network credentials");
        };
        assert!(credentials.is_open());
    }

    #[test]
    fn wifi_command_rejects_partial_or_unsafe_updates() {
        assert!(matches!(
            parse_wifi_command("WIFI only-an-ssid"),
            Some(WifiAction::Err("wifi_missing_arg"))
        ));
        assert!(matches!(
            parse_wifi_command("WIFI x short"),
            Some(WifiAction::Err("bad_wifi_password_length"))
        ));
        assert!(matches!(
            parse_wifi_command("WIFI \"unterminated password"),
            Some(WifiAction::Err("wifi_unclosed_quote"))
        ));
    }

    #[test]
    fn wifi_form_decodes_browser_encoding() {
        let credentials = parse_wifi_form("ssid=My+Phone%27s+Hotspot&password=a%2Bb%26c%3D123")
            .expect("valid form");
        assert_eq!(credentials.ssid(), "My Phone's Hotspot");
        assert_eq!(credentials.password(), "a+b&c=123");
    }

    #[test]
    fn control_actions_are_exact_single_words() {
        assert_eq!(parse_command("save"), Command::Save);
        assert_eq!(parse_command("REBOOT"), Command::Reboot);
        assert_eq!(parse_command("Factory"), Command::Factory);
        assert_eq!(parse_command("FACTORY RESET NOW"), Command::Err("factory_takes_no_args"));
    }

    #[test]
    fn motion_tuning_is_bounded_to_what_can_be_saved() {
        assert!(matches!(parse_command("SET hpf=4"), Command::Set(o) if o[0] == Some(Op::Hpf(4))));
        assert_eq!(parse_command("SET hpf=7"), Command::Err("bad_hpf"));
        assert_eq!(parse_command("SET hpf=5"), Command::Err("bad_hpf"));
        assert_eq!(parse_command("SET mot_thr=0"), Command::Err("bad_mot_thr"));
        assert!(matches!(parse_command("SET gyro_thr=0"), Command::Set(o) if o[0] == Some(Op::GyroThreshold(0))));
        assert!(matches!(parse_command("SET gyro_thr=255"), Command::Set(o) if o[0] == Some(Op::GyroThreshold(255))));
        assert_eq!(parse_command("SET gyro_thr=256"), Command::Err("bad_gyro_thr"));
        assert_eq!(parse_command("SET gyro_thr=-1"), Command::Err("bad_gyro_thr"));
        assert_eq!(parse_command("SET debounce=10001"), Command::Err("bad_debounce"));
        assert!(matches!(parse_command("SET debounce=10000"), Command::Set(_)));
        assert!(matches!(parse_command("SET udpctl=0"), Command::Set(o) if o[0] == Some(Op::UdpControl(false))));
        assert_eq!(parse_command("SET port=5013"), Command::Err("bad_port"));
        assert!(matches!(parse_command("SET min_live=1"), Command::Set(o) if o[0] == Some(Op::MinLive(1))));
        assert_eq!(parse_command("SET min_live=0"), Command::Err("bad_min_live"));
        assert_eq!(parse_command("SET min_live=17"), Command::Err("bad_min_live"));
        assert!(matches!(parse_command("SET h_hw_rng=7.5"), Command::Set(_)));
        assert!(matches!(parse_command("SET h_adc_noise=2.0"), Command::Set(_)));
        assert_eq!(parse_command("SET h_network_timing=3.0"), Command::Err("source_not_creditable"));
        assert!(matches!(parse_command("SET h_network_timing=0.0"), Command::Set(_)));
        assert_eq!(parse_command("SET entropy_port=80"), Command::Err("bad_entropy_port"));
        assert!(matches!(parse_command("SET port=5008 entropy_port=5059"), Command::Set(_)));
    }

    #[test]
    fn admin_password_rules() {
        assert!(matches!(parse_admin_command("PASS \"long enough pw\""), Some(AdminAction::Set(p)) if p.as_bytes() == b"long enough pw"));
        assert!(matches!(parse_admin_command("pass hunter22"), Some(AdminAction::Set(_))));
        assert!(matches!(parse_admin_command("PASS short"), Some(AdminAction::Err("bad_pass_length"))));
        assert!(matches!(parse_admin_command("PASS"), Some(AdminAction::Err("pass_usage"))));
        assert!(parse_admin_command("SET udp=1").is_none());
        assert!(ct_eq(b"abc", b"abc") && !ct_eq(b"abc", b"abd") && !ct_eq(b"abc", b"ab"));
    }

    #[test]
    fn base64_matches_rfc4648_vectors() {
        let cases: [(&str, &str); 7] = [
            ("", ""), ("Zg==", "f"), ("Zm8=", "fo"), ("Zm9v", "foo"),
            ("Zm9vYg==", "foob"), ("Zm9vYmE=", "fooba"), ("Zm9vYmFy", "foobar"),
        ];
        for (enc, dec) in cases {
            let mut out = [0u8; 16];
            let n = base64_decode(enc.as_bytes(), &mut out).expect(enc);
            assert_eq!(&out[..n], dec.as_bytes(), "{enc}");
        }
        let mut out = [0u8; 16];
        assert!(base64_decode(b"Zm9", &mut out).is_none());
        assert!(base64_decode(b"Zm9!", &mut out).is_none());
        assert!(base64_decode(b"Zg==Zg==", &mut out).is_none());
    }

    #[test]
    fn basic_auth_checks_user_and_extracts_password() {
        let mut s = [0u8; 192];
        // admin:hunter2
        assert_eq!(basic_auth_password("Basic YWRtaW46aHVudGVyMg==", "admin", &mut s), Some(&b"hunter2"[..]));
        let mut s = [0u8; 192];
        // admin:a:b  (a colon inside the password is legal)
        assert_eq!(basic_auth_password("basic YWRtaW46YTpi", "admin", &mut s), Some(&b"a:b"[..]));
        let mut s = [0u8; 192];
        // root:hunter2
        assert_eq!(basic_auth_password("Basic cm9vdDpodW50ZXIy", "admin", &mut s), None);
        let mut s = [0u8; 192];
        assert_eq!(basic_auth_password("Bearer abc", "admin", &mut s), None);
    }

    #[test]
    fn http_requests_parse_and_wait_for_their_body() {
        let get = b"GET /api/status?x=1 HTTP/1.1\r\nHost: 10.0.0.2\r\nAuthorization: Basic abc\r\n\r\n";
        let r = parse_http(get, 512).unwrap();
        assert_eq!((r.method, r.path), ("GET", "/api/status"));
        assert_eq!(header(r.headers, "authorization"), Some("Basic abc"));
        assert_eq!(r.consumed, get.len());

        let post = b"POST /api/cmd HTTP/1.1\r\nContent-Length: 13\r\n\r\nSET udp=1 xyz";
        let r = parse_http(post, 512).unwrap();
        assert_eq!(r.body, b"SET udp=1 xyz");
        assert_eq!(parse_http(&post[..post.len() - 3], 512).err(), Some(HttpParse::Incomplete));
        assert_eq!(parse_http(b"GET / HTTP/1.1\r\nHost: x", 512).err(), Some(HttpParse::Incomplete));
        assert_eq!(parse_http(post, 4).err(), Some(HttpParse::Bad("body_too_large")));
        assert_eq!(parse_http(b"GET nope HTTP/1.1\r\n\r\n", 512).err(), Some(HttpParse::Bad("path")));
        assert_eq!(
            parse_http(b"POST / HTTP/1.1\r\nContent-Length: 1x\r\n\r\n", 512).err(),
            Some(HttpParse::Bad("content_length"))
        );
    }

    #[test]
    fn json_strings_cannot_break_the_document() {
        let mut b: Buf<128> = Buf::new();
        write_json_str(&mut b, "a\"b\\c\nd\u{1}e");
        assert_eq!(b.as_str(), "\"a\\\"b\\\\c\\nd\\u0001e\"");
    }

    fn sample_dashboard<'a>(rows: &'a [SourceRow], ssid: &'a str) -> Dashboard<'a> {
        Dashboard {
            uptime_ms: 123_456,
            admin_default: true,
            reset: "power_on",
            live: 8,
            min_live: 4,
            keys: 42,
            budget: 37,
            motion_raw: 900,
            motion_events: 31,
            mpu_ready: true,
            mpu_addr: 0x68,
            mpu_chip: "MPU-6050",
            mpu_error: "",
            mpu_link: "SDA=GPIO8 SCL=GPIO9, 400 kHz, INT on GPIO11",
            motion_level_mg: 18,
            gyro_level_dps10: 42,
            frames: 120_000,
            faults: 0,
            mot_thr: 2,
            gyro_thr: 8,
            debounce_ms: 60,
            hpf: 4,
            sources: rows,
            ssid,
            wifi_up: true,
            ip: Some(Ipv4([10, 153, 103, 44])),
            gw: Some(Ipv4([10, 153, 103, 30])),
            rssi: -61,
            strum: Resolved::Gateway(Ipv4([10, 153, 103, 30])),
            strum_pin: TargetPin::Auto,
            entropy: Resolved::OffSubnet {
                wanted: Ipv4([192, 168, 1, 9]),
                used: Ipv4([10, 153, 103, 30]),
            },
            entropy_pin: TargetPin::Pinned(Ipv4([192, 168, 1, 9])),
            strum_port: 5008,
            entropy_port: 5059,
            udp: true,
            udpctl: false,
            sent_entropy: 40,
            sent_strum: 31,
            sent_heartbeat: 12,
            send_errors: 0,
            save_state: "saved",
            save_writes: 3,
            wdt: true,
            output: OutputRow {
                bytes: 4096,
                est_n: 0,
                shannon: 0,
                min: 0,
                progress: 4096,
                window: 8192,
                markov: 250,
                rct_max: 2,
                rct_cut: 4,
                rct_fail: 0,
                apt_max: 6,
                apt_cut: 13,
                apt_fail: 0,
                tot_n: 0,
                tot_shannon: 0,
                tot_min: 0,
            },
            dump: None,
        }
    }

    fn rows15() -> [SourceRow; 16] {
        let mut rows = [SourceRow {
            name: "accel_x",
            verdict: 'H',
            credited: true,
            h: 128,
            rct: 0,
            apt: 0,
            markov: 1800,
            est_n: 4096,
            shannon: 1790,
            min: 1500,
            progress: 12,
            window: 4096,
            rct_max: 3,
            rct_cut: 41,
            apt_max: 40,
            apt_cut: 410,
            tot_n: 1_048_576,
            tot_shannon: 2047,
            tot_min: 2017,
            funded_bits: 524_288,
        }; 16];
        rows[8].name = "motion_timing";
        rows[8].credited = false;
        rows[8].verdict = 'W';
        rows[14].name = "usb_timing";
        rows[14].verdict = 'F';
        rows
    }

    #[test]
    fn dashboard_json_has_the_fields_the_page_reads() {
        let rows = rows15();
        let mut b: Buf<STATUS_JSON_LEN> = Buf::new();
        format_dashboard_json(&mut b, &sample_dashboard(&rows, "My \"Phone\""));
        assert!(!b.overflowed());
        let j = b.as_str();
        assert!(j.starts_with("{\"uptime_ms\":123456,\"admin_default\":true,\"reset\":\"power_on\","));
        assert!(j.contains("\"harvest\":{\"live\":8,\"min\":4,\"keys\":42,\"budget\":37}"));
        assert!(j.contains("\"motion\":{\"raw\":900,\"events\":31,\"level_mg\":18,\"gyro_dps10\":42}"));
        assert!(j.contains("\"mpu\":{\"ready\":true,\"addr\":104,\"frames\":120000,\"faults\":0,\"thr\":2,\"gthr\":8,\"debounce\":60,\"hpf\":4,\"chip\":\"MPU-6050\",\"error\":\"\",\"link\":\"SDA=GPIO8 SCL=GPIO9, 400 kHz, INT on GPIO11\"}"));
        assert!(j.contains("[\"accel_x\",\"H\",true,128,0,0,1800,4096,1790,1500,12,4096,3,41,40,410,1048576,2047,2017,524288]"));
        assert!(j.contains("[\"motion_timing\",\"W\",false,128,0,0,1800,4096,1790,1500,12,4096,3,41,40,410,1048576,2047,2017,524288]"));
        assert!(j.contains(",\"output\":{\"bytes\":4096,\"n\":0,\"shannon\":0,\"min\":0,\"progress\":4096,\"window\":8192,\"markov\":250,\"rct\":[2,4,0],\"apt\":[6,13,0],\"total\":[0,0,0]},\"dump\":null,"));
        assert!(j.contains("\"ssid\":\"My \\\"Phone\\\"\""));
        assert!(j.contains("\"ip\":\"10.153.103.44\",\"gw\":\"10.153.103.30\",\"rssi\":-61}"));
        assert!(j.contains("\"strum\":\"10.153.103.30:5008\",\"strum_pin\":\"auto\""));
        assert!(j.contains("\"entropy\":\"10.153.103.30:5059, pin 192.168.1.9 is off this subnet so the gateway is used\""));
        assert!(j.contains("\"udp\":true,\"udpctl\":false}"));
        assert!(j.ends_with("\"save\":{\"state\":\"saved\",\"writes\":3},\"wdt\":true}"));
        // Balanced braces and brackets outside strings: a cheap structural check.
        let (mut depth, mut in_str, mut esc) = (0i32, false, false);
        for c in j.chars() {
            if in_str {
                match (esc, c) {
                    (true, _) => esc = false,
                    (false, '\\') => esc = true,
                    (false, '"') => in_str = false,
                    _ => {}
                }
                continue;
            }
            match c {
                '"' => in_str = true,
                '{' | '[' => depth += 1,
                '}' | ']' => depth -= 1,
                _ => {}
            }
            assert!(depth >= 0);
        }
        assert_eq!(depth, 0);
        assert!(!in_str);
    }

    #[test]
    fn dashboard_json_fits_its_buffer_in_the_worst_case() {
        // Longest SSID, every counter at its maximum, both targets off-subnet
        // with the longest dotted quads, no address yet.
        let mut rows = rows15();
        for r in rows.iter_mut() {
            r.name = "network_timing";
            r.rct = u32::MAX;
            r.apt = u32::MAX;
            r.h = u16::MAX;
            r.markov = u16::MAX;
            r.est_n = u16::MAX;
            r.shannon = u16::MAX;
            r.min = u16::MAX;
            r.progress = u16::MAX;
            r.window = u16::MAX;
            r.rct_max = u32::MAX;
            r.rct_cut = u32::MAX;
            r.apt_max = u32::MAX;
            r.apt_cut = u32::MAX;
            r.tot_n = u32::MAX;
            r.tot_shannon = u16::MAX;
            r.tot_min = u16::MAX;
            r.funded_bits = u64::MAX;
        }
        let ssid = "\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"\"";
        let mut d = sample_dashboard(&rows, ssid);
        d.uptime_ms = u64::MAX;
        d.keys = u32::MAX;
        d.motion_raw = u32::MAX;
        d.motion_events = u32::MAX;
        d.frames = u32::MAX;
        d.faults = u32::MAX;
        d.debounce_ms = u32::MAX;
        d.sent_entropy = u32::MAX;
        d.sent_strum = u32::MAX;
        d.sent_heartbeat = u32::MAX;
        d.send_errors = u32::MAX;
        d.save_writes = u32::MAX;
        d.rssi = i8::MIN;
        d.motion_level_mg = u32::MAX;
        d.gyro_level_dps10 = u32::MAX;
        d.gyro_thr = u8::MAX;
        d.mpu_chip = "MPU-6500 clone";
        // The longest probe report the firmware can produce (512 bytes).
        let err = "0x68 setup failed: bus AcknowledgeCheckFailed(Address); 0x69 setup failed: bus AcknowledgeCheckFailed(Address); 0x69 register 0x6b wrote 0x00 read back 0x40\"\"\"\"\"\"\"\"\"\"\"\"\"\"";
        let long = err.repeat(4);
        d.mpu_error = &long[..long.len().min(512)];
        let link = "\"".repeat(96);
        d.mpu_link = &link;
        d.reset = "system_watchdog";
        d.save_state = "unavailable";
        d.output = OutputRow {
            bytes: u64::MAX,
            est_n: u16::MAX,
            shannon: u16::MAX,
            min: u16::MAX,
            progress: u16::MAX,
            window: u16::MAX,
            markov: u16::MAX,
            rct_max: u32::MAX,
            rct_cut: u32::MAX,
            rct_fail: u32::MAX,
            apt_max: u32::MAX,
            apt_cut: u32::MAX,
            apt_fail: u32::MAX,
            tot_n: u32::MAX,
            tot_shannon: u16::MAX,
            tot_min: u16::MAX,
        };
        d.dump = Some(("network_timing", u32::MAX));
        let wide = Ipv4([255, 255, 255, 255]);
        d.ip = Some(wide);
        d.gw = Some(wide);
        d.strum = Resolved::SelfAddress { rejected: wide, used: wide };
        d.entropy = Resolved::OffSubnet { wanted: wide, used: wide };
        d.strum_pin = TargetPin::Pinned(wide);
        d.entropy_pin = TargetPin::Pinned(wide);
        let mut b: Buf<STATUS_JSON_LEN> = Buf::new();
        format_dashboard_json(&mut b, &d);
        assert!(!b.overflowed(), "status document outgrew its buffer: {}", b.as_str().len());
        assert!(b.as_str().len() > 3072, "worst case should exercise the larger buffer");
    }

    #[test]
    fn stats_and_dump_commands_parse_strictly() {
        assert_eq!(parse_command("STATS"), Command::Stats);
        assert_eq!(parse_command("stats now"), Command::Err("stats_usage"));
        assert_eq!(parse_command("STATS reset"), Command::StatsReset);
        assert_eq!(parse_command("STATS RESET now"), Command::Err("stats_usage"));
        assert_eq!(parse_command("DUMP accel_x 1000000"), Command::Dump(0, 1_000_000));
        assert_eq!(parse_command("dump adc_noise 5"), Command::Dump(15, 5));
        assert_eq!(parse_command("DUMP STOP"), Command::DumpStop);
        assert_eq!(parse_command("DUMP accel_x"), Command::Err("bad_dump_count"));
        assert_eq!(parse_command("DUMP accel_x 0"), Command::Err("bad_dump_count"));
        assert_eq!(parse_command("DUMP accel_x 10000001"), Command::Err("bad_dump_count"));
        assert_eq!(parse_command("DUMP bogus 10"), Command::Err("bad_source"));
        assert_eq!(parse_command("DUMP accel_x 10 extra"), Command::Err("dump_usage"));
        assert_eq!(parse_command("DUMP"), Command::Err("dump_usage"));
    }

    #[test]
    fn wifi_form_requires_one_complete_pair() {
        assert_eq!(
            parse_wifi_form("ssid=only").err(),
            Some("missing_wifi_password")
        );
        assert_eq!(
            parse_wifi_form("ssid=a&ssid=b&password=abcdefgh").err(),
            Some("duplicate_wifi_field")
        );
    }
}
