# Nocturnus GuitaRNG MPU node

Embassy/no-std firmware for an ESP32-S3 Super Mini and MPU-6050. It joins the
configured phone hotspot, sends the same 32-byte conditioned entropy datagrams
used by the Spectra/Sylvia receiver, emits `STRUM` when the MPU detects
motion, and mirrors entropy plus health reports over the board's native USB
Serial/JTAG connection.

## Wiring

Power everything off before wiring. On a GY-521-style MPU-6050 breakout:

| MPU-6050 / GY-521 | ESP32-S3 Super Mini | Purpose |
|---|---|---|
| `VCC` | `3V3` | Sensor and I2C pull-up supply |
| `GND` | `GND` | Common ground |
| `SDA` | `GPIO8` / `IO8` | I2C data |
| `SCL` | `GPIO9` / `IO9` | I2C clock |
| `INT` | `GPIO11` / `IO11` | Data-ready interrupt |
| `AD0` | not connected | The breakout's own pull-down selects address `0x68` |
| `XDA`, `XCL` | not connected | Auxiliary I2C is unused |
| (nothing) | `GPIO1` / `IO1` | Leave unconnected: ADC noise source |

Both boards normally ship with their header pins loose in the bag. A header
pin pushed through an unsoldered hole touches the pad only by chance, which
gives exactly an MPU that is never found, or found only while it is being
wiggled. If soldering is not an option, use parts with the headers already
fitted (sold as "pre-soldered" GY-521 and Super Mini boards), or an MPU-6050
breakout with a STEMMA QT / Qwiic socket and a matching socket-to-jumper cable.

Every boot looks for the sensor before anything else uses the bus, and prints
the result as a `WIRING` line. First each spare header pin (GPIO2 to 13, except
GPIO11) is read against the ESP32's own weak pull-down: only a pin that a
powered sensor board's SDA or SCL wire really reaches is pulled high by the
board's resistors. Then I2C is tried on GPIO8/GPIO9, the same pair swapped, and
every pair of pulled-up pins. Whatever pair answers is used.

| `WIRING` says | Meaning |
|---|---|
| `found=1 ... on SDA=GPIO8 SCL=GPIO9` | wired as documented |
| `found=1 ... not the documented GPIO8/GPIO9; using it` | swapped or moved wires; it works anyway, but fix the wiring to match |
| `found=0 ... no header pin is pulled up` | the sensor board has no power, or its wires are not making contact |
| `found=0 ... pulled up: GPIO8 GPIO9; no MPU answered` | SDA and SCL reach the board's pull-up resistors, but the chip does not respond; the extra checks below say why |

When nothing answers, three more checks run on plain GPIO before the I2C
driver exists, and are appended to the same line: whether SDA and SCL are
shorted together or held low; a bit-banged I2C probe that uses no I2C
hardware at all (an ACK there means the fault is on the firmware side, none
means the hardware); and whether the chip is holding its INT pin low, which
only a chip with both power and ground does. The pull-ups on SDA/SCL come from
VCC alone, so they read fine even with no ground connection or a dead chip.

If the MPU answers but no data-ready pulses arrive on GPIO11, the INT wire is
the problem: the firmware says so and keeps sampling by polling the sensor
over I2C (the `clock_beat` source pauses, everything else runs). When the MPU
is not found, the dashboard and USB also report what each address answered
and a scan of the whole I2C bus.

Use **3.3 V**, even if a particular GY-521 advertises a 5 V-capable regulator.
Many modules pull SDA/SCL up to their VCC rail, and the ESP32-S3 GPIO is not
5 V tolerant. The breakout normally already has I2C pull-ups; do not add a
second set unless the bus waveform shows that they are needed.

Power the Super Mini from USB-C on the bench. For a battery installation, use a
protected cell and the correct regulator/charger for the exact board revision.
Do not connect a raw Li-ion cell to `3V3`, and do not power the board from USB
and an unisolated external supply at the same time.

For the guitar installation, keep the ESP32 antenna outside the shielded metal
control cavity. The MPU can live in the cavity on a short four/five-wire tether.
Secure it so it cannot hit pots, the selector, or jack wiring.

## Dashboard

Every setting and every health figure is on a phone dashboard served by the
node itself, so a guitar running from a battery never needs USB.

| Network | Address |
|---|---|
| Phone hotspot | `http://<node address>/` (the node registers the hostname `nocturnus`) |
| Setup network `NOCTURNUS-SETUP` | `http://192.168.4.1/` |

The browser asks for a user name and password. The user is **`admin`**; the
password is **`nocturnus`** until you change it under **Admin**, and the page
shows a warning banner until you do. The node's hotspot address is printed on
USB as `WEB url=http://.../` each time it gets a lease, and it appears as
`nocturnus` in the hotspot's connected-devices list.

The page refreshes once a second and shows movement (motion hits and events
sent per second, with a 60 second trace), harvest progress, every source's
verdict and counters, Wi-Fi, where packets are going, how many were sent, the
save state, and the reason for the last reset. It never shows released key
bytes. Motion tuning, targets, assessments, Wi-Fi, the dashboard password,
save, reboot and factory reset are all controls on the page, and a command box
accepts the same commands as USB.

A wrong password costs a growing delay (up to 4 s per attempt). A forgotten
password is recovered over USB with `PASS "new password"` or `FACTORY`.

## Wi-Fi setup portal

The firmware creates its own WPA2 setup network while also operating as a
station. You do not need to edit, rebuild, or reflash it to select a different
phone/router hotspot:

1. Power the ESP32-S3.
2. On the phone or computer, join **`NOCTURNUS-SETUP`** with password
   **`guitarng-setup`**.
3. Open **`http://192.168.4.1/`**. A captive-portal notification may open it
   automatically. If the sign-in sheet does not offer a password prompt, open
   the same address in the browser instead.
4. Sign in, then enter the Wi-Fi name and password of the hotspot that should
   carry the GuitaRNG traffic under **Wi-Fi**, then press **Connect**.
5. Rejoin the phone/computer to its normal network if the operating system did
   not do so automatically.

The board validates the complete SSID/password pair, reconfigures the station,
obtains fresh DHCP settings, and resumes `STRUM`, heartbeat, and conditioned
entropy traffic. The setup AP remains available alongside the station, so a
mistyped target password cannot lock you out. It allows one setup client at a
time.

Wi-Fi provisioning is independent of the MPU-6050. If the sensor is absent or
miswired, the setup AP still starts while the firmware retries both valid MPU
addresses (`0x68` and `0x69`) every five seconds. USB health then reports
`mpu=0`; entropy/strum output begins only after the sensor is detected and
configured. Meanwhile the sources that do not need the MPU (hardware RNG, ADC
noise, Wi-Fi RSSI, network and USB timing) keep running on the ESP32's own
1 kHz clock and are measured on the dashboard.

The values in [`src/config.rs`](src/config.rs) are the defaults for a node that
has never saved, and the values `FACTORY` returns to. You can select another
network from the setup page at any time without rebuilding.

## Settings persistence

Changes from the dashboard, USB or UDP are written to flash 3 seconds after the
last change, so a burst of edits costs one write. `SAVE` writes immediately and
`REBOOT` saves before restarting. Saved: Wi-Fi credentials, targets, ports,
`udp`, `udpctl`, debounce, both motion thresholds, high-pass, `min_live`, every source's
assessed `h`, and the dashboard password (as a salted SHA3-256 digest, never
the password itself). Key material never touches flash.

Records live in two 4 KB sectors at the start of the `nvs` partition. Each save
goes to the sector not holding the newest good copy, carries a sequence number
and CRC32, and is read back and decoded before it counts as saved. Power lost
mid-save leaves the previous settings intact. A record from different firmware,
or one that fails any check, is ignored and the node runs on defaults; the
dashboard says which happened.

## Network behavior

| Traffic | Local port | Destination port | Payload |
|---|---:|---:|---|
| Strum | `5008` | `5008` | ASCII `STRUM` |
| Liveness | `5008` | `5008` | ASCII `HEARTBEAT nocturnus A-004` every 10 s |
| Conditioned entropy | `5059` | `5059` | exactly 32 raw bytes |
| Control | `5013` | reply to sender | UTF-8 command/reply |

Both data sockets bind symmetrically to their destination port. With targets
set to `auto`, DHCP's gateway is used; on a normal phone hotspot that is the
phone running the receiver. Targets are re-resolved after reconnects, so a
changed hotspot subnet does not require reflashing.

UDP and USB accept the same control commands:

```text
GET
HELP
WIFI GET
WIFI "My Phone Hotspot" "my hotspot password"
WIFI DEFAULT
SET ip=auto
SET strum_ip=192.168.1.1 entropy_ip=192.168.1.1
SET port=5008 entropy_port=5059
SET udp=0
SET reset=all
SET h_accel_x=0.5 h_gyro_x=0.5
SET mot_thr=8 gyro_thr=8 debounce=60 hpf=4
SET udpctl=0
SAVE
REBOOT
FACTORY
PASS "new dashboard password"
```

Motion is measured in firmware from the accelerometer and gyro samples, so it
behaves the same on a genuine MPU-6050 and on
the MPU-6500-family dies many GY-521 boards ship with; both are accepted and
the dashboard names which one answered. If no sensor answers, the dashboard
and USB say exactly what each address replied.

Each sensor goes through a detection-only path: a median of 3 frames (drops
a corrupted frame), an average of 8 (cuts the noise about three times, adds
about 4 ms), then the slow resting value is subtracted (gravity for the
accelerometer, the zero-rate offset for the gyro). Motion is either sensor over
its threshold for 2 frames in a row. The entropy sources still get the raw,
unsmoothed samples.

`mot_thr` is the acceleration trigger in 8 mg steps (1 to 255; 8 is 64 mg, and
2 or 3 is about as fine as the sensor's noise allows), `gyro_thr` the rotation
trigger in degrees per second (0 to 255, `0` off; 1 to 3 picks up a lean or a
breath), `debounce` the minimum gap in ms between `STRUM` packets (0 to 10000),
and `hpf` the high-pass for both (`4` 0.63 Hz, `3` 1.25 Hz, `2` 2.5 Hz, `1`
5 Hz, `0` off). Settings saved by earlier firmware keep the same physical
threshold: an old `mot_thr=2` (2 x 32 mg) reads back as `mot_thr=8`.
The UDP control port has no password. Because its changes now survive a
reboot, it refuses `PASS`, `REBOOT`, `FACTORY`, `SAVE`, Wi-Fi changes and
`h_` assessments (it can still read everything, including `WIFI GET`), and
`SET udpctl=0` closes it entirely; USB and the dashboard keep working. Data
ports may not be `53`, `67`, `68`, `80` or `5013` (the node's own services) and
may not equal each other.

`WIFI "ssid" "password"` validates and applies both fields atomically, then
disconnects and reconnects immediately. Quotes are required when either field
contains spaces. Use `WIFI "Guest Network" ""` for an open network. `WIFI GET`
reports the selected SSID and connection state but never the password;
`WIFI DEFAULT` returns to the credentials compiled into `config.rs`.

`WIFI GET` reports `persistent=1`. USB remains a recovery/control alternative;
prefer the web portal for normal setup. Wi-Fi changes are not accepted over the
UDP control port.

## USB output

The USB-C connector exposes the ESP32-S3 native CDC-ACM serial port. No UART
adapter or additional pins are required. After the 4,096-sample startup health
window, a passing node emits one line per release in the same form as Spectra:

```text
TRNG:<44-character base64 value>
```

The decoded value is exactly the same 32 bytes sent on UDP 5059. Every ten
seconds the board also reports a `HEALTH` line. Per-source fields are:

- verdict: `W` warming, `H` healthy, `D` degraded, `F` failed and latched;
- `r`: RCT failure count;
- `a`: APT failure count;
- `m`: latest Markov estimate in Q8.8 bits per serialized raw input bit
  (`256` means 1.0 bit/bit).

The included capture utility filters out status lines and writes only decoded
conditioned bytes:

```powershell
py -m pip install pyserial
py tools/capture_usb.py COM7 conditioned.bin --blocks 4096
```

Replace `COM7` with the port shown by Device Manager or `espflash board-info`.
The baud value is nominal for native USB CDC; it does not set a physical UART
clock.

To change hotspots interactively, open that same COM port at any baud setting
(115200 is conventional), type one command followed by Enter, and wait for
`OK ... reconnecting=1` followed by `WIFI state=connected`. Close the capture
utility first because only one program should own the serial port at a time.
On Linux the port is normally `/dev/ttyACM0`; for example:

```bash
picocom -b 115200 /dev/ttyACM0
# Then type: WIFI "My Phone Hotspot" "my hotspot password"
```

## Entropy pipeline

Raw sources are source-tagged before entering SHA3-512:

- credited after warm-up and continuous health checks: accelerometer X/Y/Z low
  bytes, gyroscope X/Y/Z low bytes, MPU temperature low byte, MPU data-ready
  clock beat against the ESP timer, and the ESP32-S3 hardware RNG (true random
  while the radio is on, per Espressif; on this node the radio never turns off);
- creditable once given an assessment: ADC noise from the unconnected `GPIO1`
  pad;
- mixed but never credited: MPU gross-motion/high bytes, motion timing, I2C
  transaction timing, Wi-Fi RSSI, UDP timing and USB receive timing (all of
  them can be influenced from outside or by the firmware itself).

Every raw source is tested independently before conditioning. RCT and APT are
the continuous health tests from NIST SP 800-90B. The additional on-device
Markov gate serializes raw bytes to binary symbols, estimates the four Markov
transition probabilities over 4,096-bit windows, and uses the SP 800-90B
128-bit most-likely-path calculation. A credited-source failure clears all
unspent entropy credit and latches that source off until an explicit reset.

At least `min_live` credited sources (default four; `SET min_live=N` or the
dashboard, saved) must be live and at least 256 assessed bits must have
accrued before output. With the default, output needs the MPU. `min_live=1`
releases from the hardware RNG alone while the MPU is missing, and the MPU
sources join as soon as it answers. SHA3-512 then produces 64 bytes: the first 32 are
released, while the second 32 are never transmitted and are absorbed into the
next epoch. Release rate is capped at one block per second.

Unspent credit is capped at 512 bits, two blocks' worth. One SHA3-512 digest
holds no more than that, and only the 256-bit chaining half survives a
release, so credit past the cap would describe entropy the conditioner no
longer holds. A node that sat for an hour without releasing (MPU missing,
floor not met) therefore resumes at one block per second on fresh input
instead of emitting a backlog.

### Important assessment boundary

The compiled-in `0.5 bit/sample` values are deliberately low **provisional
engineering values**, not a NIST validation. RCT/APT/Markov detect failures;
they do not establish the original min-entropy claim. Before treating output as
certified key material, collect large raw per-source datasets with a separate
instrumented lab build, run NIST's `ea_iid`/`ea_non_iid` tools, enter the lowest
restart/non-IID result with `SET h_<source>=...`, and repeat across temperature,
power, stillness, playing, and multiple physical units.

NIST STS or Dieharder may be run on `conditioned.bin` as an output sanity check,
but passing a statistical battery does not prove source entropy. Production
firmware intentionally does not expose the raw stream alongside conditioned
output.

### Measuring the sources

Every source is measured on the device, on its raw samples, over everything
collected since the last `STATS RESET` (or the dashboard's **Reset
measurements**), and shown under **Sources** on the dashboard or printed on
USB with `STATS`. Entropy figures are bits per sample, 8 at most:

- **assessed**: what the release budget counts for that source.
- **funded bits**: bits of the source's credit spent on released blocks since
  the reset, and its share of the total. This is exactly who paid for the
  output: every block costs 256, split across the sources in proportion to
  what each had in the pool. Credit thrown away by a health failure, an
  assessment change or a DUMP never counts. `STATS` prints it as
  `funded_bits=`.
- **min-entropy**: SP 800-90B most-common-value estimate over the running
  total. Red when below the assessment.
- **perfect at n**: what an ideal random source reads at the same sample count.
- **Shannon**: average entropy over the running total.
- **last window**: the same two estimates over just the most recent 4096
  samples (256 for the slow sources), to spot a change.
- **Markov**: SP 800-90B Markov estimate over 128-bit paths.
- **RCT / APT worst**: the longest repeat run and the highest count in a
  512-sample window seen so far, against the cutoff that fails the source.

The min-entropy estimator carries NIST's 99% margin, which only shrinks with
more samples. A perfect random byte source reads 6.61 after 4,096 samples,
7.57 after 65 thousand, 7.88 after a million and 7.91 after two million, so a
reading of 7.9 needs about 1.8 million samples: roughly 4 minutes for
`hw_rng`, 30 for a 1 kHz source. The raw MPU sources will sit well below that
however long they run; that is the physics of a MEMS noise floor, and why
everything goes through SHA3. The **Conditioned output** panel runs the same
measures on the released blocks, with the perfect-source figure and progress
toward 1.8 million bytes beside it (about 16 hours at one block a second). It
checks the release path, not the sources: a hash output looks random whatever
went into it.

On-device numbers are screening. The full SP 800-90B assessment runs NIST's
`ea_non_iid` on at least 1,000,000 raw samples of one source. The firmware
streams them over USB with `DUMP`. Releases pause for the whole capture,
because printed samples are no longer secret, and any credit earned during
it is discarded when it ends. On Mitsu, with nothing beyond coreutils:

```bash
picocom -b 115200 --logfile accel_x.log /dev/ttyACM0
# type:  DUMP accel_x 1000000        (about 17 minutes at 1 kHz)
# wait:  DUMP state=done source=accel_x samples=1000000 releases=resumed
# quit:  Ctrl-A then Ctrl-X
grep -a '^RAW:accel_x:' accel_x.log | cut -d: -f3 | tr -d '\r\n' | basenc --base16 -d > accel_x.bin
ls -l accel_x.bin                     # must be exactly 1000000 bytes
ea_non_iid -v accel_x.bin 8
```

The capture is always contiguous. If a sample cannot be delivered, the
sensor drops out, or you send `DUMP STOP`, it ends on the spot and says why
(`state=usb_fell_behind`, `samples_lost_on_device`, `mpu_lost`, `stopped`)
instead of leaving a gap; only `state=done` with the full count is a complete
dataset. `DUMP` only works over USB and needs the MPU running. The MPU axes,
`mpu_temp`, `clock_beat`, `bus_timing` and `adc_noise` produce 1,000 samples
a second, `hw_rng` 8,000 and `mpu_frame` 7,000. The slow sources (RSSI,
network, USB and motion timing) are too slow to collect a million samples
in practice. Enter the lowest result with `SET h_<source>=...` or on the
dashboard.

References: [NIST SP 800-90B](https://csrc.nist.gov/pubs/sp/800/90/b/final),
[ESP32-S3 USB Serial/JTAG](https://docs.espressif.com/projects/esp-idf/en/latest/esp32s3/api-guides/usb-serial-jtag-console.html),
and the [MPU-6000/MPU-6050 register map](https://invensense.tdk.com/wp-content/uploads/2015/02/MPU-6000-Register-Map1.pdf).

## Build and flash

Install the Espressif Rust toolchain and `espflash`, then from this directory:

```powershell
cargo build --release
cargo run --release
```

The checked-in Cargo configuration selects `xtensa-esp32s3-none-elf`, builds
`core`/`alloc`, links `linkall.x`, and uses `espflash flash --monitor` as the
runner. Hold **BOOT**, tap **RESET**, then release **BOOT** if automatic download
mode does not engage.

Verification commands used for this revision:

```powershell
cargo check --release --offline
cargo build --release --offline
cargo +stable test --lib --target x86_64-pc-windows-msvc --offline --config 'unstable.build-std=[]'
```
