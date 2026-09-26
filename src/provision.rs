// ============================================================================
// provision.rs - captive Wi-Fi setup portal
//
// The ESP32-S3 runs this network alongside its ordinary station connection:
//
//   SSID:       NOCTURNUS-SETUP
//   address:    192.168.4.1/24
//   services:   DHCP, catch-all DNS, HTTP credential form
//
// No allocator, web framework, or external service is involved. Submitted
// credentials use the same validation and update channel as USB control.
// ============================================================================

use core::fmt::Write as _;

use embassy_net::tcp::TcpSocket;
use embassy_net::udp::{PacketMetadata, UdpSocket};
use embassy_net::{IpAddress, IpEndpoint, Ipv4Address, Runner, Stack};
use embassy_time::{Duration, Timer};
use esp_radio::wifi::Interface;

use crate::{config as cfg, net, request_wifi_update};

const PORT_DHCP_SERVER: u16 = 67;
const PORT_DHCP_CLIENT: u16 = 68;
const PORT_DNS: u16 = 53;
const PORT_HTTP: u16 = 80;

const PAGE: &[u8] = br#"<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Nocturnus Wi-Fi Setup</title>
<style>
:root{color-scheme:dark;font-family:system-ui,sans-serif;background:#090b10;color:#edf2ff}
body{margin:0;min-height:100vh;display:grid;place-items:center;background:radial-gradient(circle at top,#202846,#090b10 62%)}
main{box-sizing:border-box;width:min(92vw,430px);padding:28px;border:1px solid #46527a;border-radius:18px;background:#111625;box-shadow:0 20px 60px #0008}
h1{margin:0 0 8px;font-size:1.65rem}p{color:#b9c4df;line-height:1.45}label{display:block;margin-top:18px;font-weight:650}
input{box-sizing:border-box;width:100%;margin-top:7px;padding:13px;border:1px solid #59658c;border-radius:9px;background:#080b13;color:#fff;font-size:1rem}
button{width:100%;margin-top:24px;padding:13px;border:0;border-radius:9px;background:#8ca8ff;color:#081027;font-size:1rem;font-weight:800}
small{display:block;margin-top:15px;color:#8f9aba}code{color:#c9d5ff}
</style></head><body><main>
<h1>Nocturnus</h1><p>Choose the hotspot that will receive GuitaRNG strum and conditioned entropy traffic.</p>
<form method="post" action="/save">
<label for="ssid">Wi-Fi name</label><input id="ssid" name="ssid" maxlength="32" autocomplete="off" required>
<label for="password">Wi-Fi password</label><input id="password" name="password" type="password" maxlength="64" autocomplete="new-password">
<button type="submit">Connect</button></form>
<small>Leave the password empty only for an open network. The setup network remains available at <code>192.168.4.1</code>. A power cycle restores the compiled defaults.</small>
</main></body></html>"#;

const SUCCESS_PAGE: &[u8] = br#"<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Connecting</title><style>body{font-family:system-ui,sans-serif;background:#090b10;color:#edf2ff;display:grid;place-items:center;min-height:100vh;margin:0}main{max-width:32rem;padding:2rem}p{color:#b9c4df}</style></head><body><main><h1>Credentials accepted</h1><p>Nocturnus is reconnecting now. Its setup network stays available, so you can return to <b>192.168.4.1</b> if the target hotspot was mistyped.</p></main></body></html>"#;

const ERROR_PAGE: &[u8] = br#"<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Invalid settings</title></head><body><h1>Could not use those settings</h1><p>The SSID must be 1-32 bytes. Use an empty password for an open network, or an 8-64 byte password.</p><p><a href="/">Try again</a></p></body></html>"#;

#[embassy_executor::task]
pub async fn ap_net_runner_task(mut runner: Runner<'static, Interface>) {
    runner.run().await
}

// ---------------------------------------------------------------------------
// Minimal DHCP server
// ---------------------------------------------------------------------------

#[embassy_executor::task]
pub async fn dhcp_task(stack: Stack<'static>) {
    let mut rx_meta = [PacketMetadata::EMPTY; 2];
    let mut rx_storage = [0u8; 700];
    let mut tx_meta = [PacketMetadata::EMPTY; 2];
    let mut tx_storage = [0u8; 700];
    let mut socket = UdpSocket::new(
        stack,
        &mut rx_meta,
        &mut rx_storage,
        &mut tx_meta,
        &mut tx_storage,
    );
    if socket.bind(PORT_DHCP_SERVER).is_err() {
        return;
    }

    let mut request = [0u8; 600];
    let mut response = [0u8; 600];
    loop {
        let Ok((count, _)) = socket.recv_from(&mut request).await else {
            continue;
        };
        let Some(length) = build_dhcp_response(&request[..count], &mut response) else {
            continue;
        };
        let destination = IpEndpoint::new(
            IpAddress::Ipv4(Ipv4Address::new(255, 255, 255, 255)),
            PORT_DHCP_CLIENT,
        );
        let _ = socket.send_to(&response[..length], destination).await;
    }
}

fn build_dhcp_response(request: &[u8], response: &mut [u8]) -> Option<usize> {
    const COOKIE: [u8; 4] = [99, 130, 83, 99];
    if request.len() < 240 || response.len() < 300 || request[236..240] != COOKIE {
        return None;
    }
    let request_type = dhcp_message_type(&request[240..])?;
    let response_type = match request_type {
        1 => 2, // DISCOVER -> OFFER
        3 => 5, // REQUEST -> ACK
        _ => return None,
    };

    response[..300].fill(0);
    response[0] = 2; // BOOTREPLY
    response[1] = request[1];
    response[2] = request[2];
    response[4..8].copy_from_slice(&request[4..8]); // transaction ID
    response[10..12].copy_from_slice(&[0x80, 0x00]); // broadcast reply
    response[16..20].copy_from_slice(&cfg::PROVISION_CLIENT_IP); // yiaddr
    response[20..24].copy_from_slice(&cfg::PROVISION_AP_IP); // siaddr
    response[28..44].copy_from_slice(&request[28..44]); // client hardware address
    response[236..240].copy_from_slice(&COOKIE);

    let mut at = 240usize;
    push_dhcp_option(response, &mut at, 53, &[response_type])?;
    push_dhcp_option(response, &mut at, 54, &cfg::PROVISION_AP_IP)?;
    push_dhcp_option(response, &mut at, 1, &[255, 255, 255, 0])?;
    push_dhcp_option(response, &mut at, 3, &cfg::PROVISION_AP_IP)?;
    push_dhcp_option(response, &mut at, 6, &cfg::PROVISION_AP_IP)?;
    push_dhcp_option(response, &mut at, 51, &86_400u32.to_be_bytes())?;
    *response.get_mut(at)? = 255;
    Some(at + 1)
}

fn dhcp_message_type(options: &[u8]) -> Option<u8> {
    let mut at = 0usize;
    while at < options.len() {
        let kind = options[at];
        at += 1;
        match kind {
            0 => continue,
            255 => return None,
            _ => {
                let length = *options.get(at)? as usize;
                at += 1;
                let value = options.get(at..at + length)?;
                if kind == 53 && length == 1 {
                    return Some(value[0]);
                }
                at += length;
            }
        }
    }
    None
}

fn push_dhcp_option(packet: &mut [u8], at: &mut usize, kind: u8, value: &[u8]) -> Option<()> {
    let end = *at + 2 + value.len();
    let target = packet.get_mut(*at..end)?;
    target[0] = kind;
    target[1] = value.len() as u8;
    target[2..].copy_from_slice(value);
    *at = end;
    Some(())
}

// ---------------------------------------------------------------------------
// Catch-all DNS for captive-portal detection
// ---------------------------------------------------------------------------

#[embassy_executor::task]
pub async fn dns_task(stack: Stack<'static>) {
    let mut rx_meta = [PacketMetadata::EMPTY; 2];
    let mut rx_storage = [0u8; 600];
    let mut tx_meta = [PacketMetadata::EMPTY; 2];
    let mut tx_storage = [0u8; 600];
    let mut socket = UdpSocket::new(
        stack,
        &mut rx_meta,
        &mut rx_storage,
        &mut tx_meta,
        &mut tx_storage,
    );
    if socket.bind(PORT_DNS).is_err() {
        return;
    }

    let mut request = [0u8; 512];
    let mut response = [0u8; 512];
    loop {
        let Ok((count, metadata)) = socket.recv_from(&mut request).await else {
            continue;
        };
        let Some(length) = build_dns_response(&request[..count], &mut response) else {
            continue;
        };
        let _ = socket.send_to(&response[..length], metadata.endpoint).await;
    }
}

fn build_dns_response(request: &[u8], response: &mut [u8]) -> Option<usize> {
    if request.len() < 17 || request[4..6] != [0, 1] {
        return None;
    }
    let mut at = 12usize;
    loop {
        let length = *request.get(at)? as usize;
        at += 1;
        if length == 0 {
            break;
        }
        if length & 0xc0 != 0 || length > 63 {
            return None;
        }
        at = at.checked_add(length)?;
        request.get(at.saturating_sub(1))?;
    }
    let question_end = at.checked_add(4)?;
    request.get(question_end.saturating_sub(1))?;
    let response_len = question_end.checked_add(16)?;
    if response_len > response.len() {
        return None;
    }

    response[..question_end].copy_from_slice(&request[..question_end]);
    response[2..4].copy_from_slice(&[0x81, 0x80]); // response, recursion available
    response[6..8].copy_from_slice(&[0, 1]); // one answer
    response[8..12].fill(0);
    let answer = &mut response[question_end..response_len];
    answer.copy_from_slice(&[
        0xc0,
        0x0c, // compressed name pointer
        0x00,
        0x01, // A
        0x00,
        0x01, // IN
        0x00,
        0x00,
        0x00,
        0x3c, // TTL 60 seconds
        0x00,
        0x04,
        cfg::PROVISION_AP_IP[0],
        cfg::PROVISION_AP_IP[1],
        cfg::PROVISION_AP_IP[2],
        cfg::PROVISION_AP_IP[3],
    ]);
    Some(response_len)
}

// ---------------------------------------------------------------------------
// HTTP form
// ---------------------------------------------------------------------------

#[embassy_executor::task]
pub async fn http_task(stack: Stack<'static>) {
    let mut rx_storage = [0u8; 1536];
    let mut tx_storage = [0u8; 2048];
    let mut socket = TcpSocket::new(stack, &mut rx_storage, &mut tx_storage);
    socket.set_timeout(Some(Duration::from_secs(15)));

    loop {
        if socket.accept(PORT_HTTP).await.is_err() {
            Timer::after(Duration::from_millis(100)).await;
            continue;
        }

        let mut request = [0u8; 1536];
        let mut used = 0usize;
        let mut expected = None;
        while used < request.len() {
            let count = match socket.read(&mut request[used..]).await {
                Ok(0) | Err(_) => break,
                Ok(count) => count,
            };
            used += count;
            if let Some(header_end) = find_bytes(&request[..used], b"\r\n\r\n") {
                let body_length = content_length(&request[..header_end]).unwrap_or(0);
                expected = Some(header_end + 4 + body_length);
                if used >= expected.unwrap_or(usize::MAX) {
                    break;
                }
            }
        }

        let mut update = None;
        let outcome = if request[..used].starts_with(b"POST /save ") {
            match expected.filter(|end| *end <= used) {
                Some(end) => {
                    let header_end = find_bytes(&request[..used], b"\r\n\r\n").unwrap_or(used);
                    match core::str::from_utf8(&request[header_end + 4..end])
                        .map_err(|_| "bad_wifi_utf8")
                        .and_then(net::parse_wifi_form)
                    {
                        Ok(credentials) => {
                            update = Some(credentials);
                            HttpOutcome::Success
                        }
                        Err(_) => HttpOutcome::BadRequest,
                    }
                }
                None => HttpOutcome::BadRequest,
            }
        } else {
            HttpOutcome::Form
        };

        let (status, body) = match outcome {
            HttpOutcome::Form => ("200 OK", PAGE),
            HttpOutcome::Success => ("200 OK", SUCCESS_PAGE),
            HttpOutcome::BadRequest => ("400 Bad Request", ERROR_PAGE),
        };
        send_response(&mut socket, status, body).await;

        // Send the complete response before applying the radio change. APSTA
        // normally keeps the setup AP alive, but a channel transition can
        // briefly interrupt the phone.
        if let Some(credentials) = update {
            Timer::after(Duration::from_millis(150)).await;
            let _ = request_wifi_update(credentials).await;
        }

        socket.abort();
        Timer::after(Duration::from_millis(20)).await;
    }
}

#[derive(Copy, Clone)]
enum HttpOutcome {
    Form,
    Success,
    BadRequest,
}

async fn send_response(socket: &mut TcpSocket<'_>, status: &str, body: &[u8]) {
    let mut header = net::Buf::<256>::new();
    let _ = write!(
        header,
        "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let _ = tcp_write_all(socket, header.as_bytes()).await;
    let _ = tcp_write_all(socket, body).await;
    let _ = socket.flush().await;
    socket.close();
}

async fn tcp_write_all(socket: &mut TcpSocket<'_>, mut data: &[u8]) -> Result<(), ()> {
    while !data.is_empty() {
        match socket.write(data).await {
            Ok(0) | Err(_) => return Err(()),
            Ok(written) => data = &data[written..],
        }
    }
    Ok(())
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return Some(0);
    }
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn content_length(headers: &[u8]) -> Option<usize> {
    let text = core::str::from_utf8(headers).ok()?;
    for line in text.split("\r\n") {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("content-length") {
            let mut result = 0usize;
            for byte in value.trim().bytes() {
                if !byte.is_ascii_digit() {
                    return None;
                }
                result = result
                    .checked_mul(10)?
                    .checked_add((byte - b'0') as usize)?;
            }
            return Some(result);
        }
    }
    None
}
