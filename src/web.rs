// ============================================================================
// web.rs - phone dashboard, and the setup network it also serves
//
// The dashboard is one static page plus two API calls, served on port 80 on
// BOTH networks the radio runs:
//
//   hotspot    whatever address the phone's DHCP hands out
//              (the node asks for the hostname "nocturnus")
//   setup AP   NOCTURNUS-SETUP, http://192.168.4.1/
//
//   GET  /             the dashboard (web/dashboard.html, compiled in)
//   GET  /api/status   JSON: metrics and current settings, never key bytes
//   POST /api/cmd      one line of the same command grammar USB uses
//
// Every route needs HTTP Basic authentication (user "admin"). A browser asks
// once and then attaches the password to the page's own API calls.
//
// POST /api/cmd additionally requires an `X-Nocturnus` header. A page on some
// other site can make the phone's browser send a plain cross-site POST, and the
// browser would attach the cached password to it. A custom header cannot be
// added to a cross-site request without the browser first asking this server
// for permission, which it never grants, so that request dies in the browser.
//
// The setup network keeps its DHCP server and catch-all DNS from the original
// provisioning portal, unchanged, so a phone joining NOCTURNUS-SETUP still gets
// an address and still pops the sign-in sheet.
// ============================================================================

use core::fmt::Write as _;
use core::sync::atomic::{AtomicU32, Ordering};

use embassy_net::tcp::TcpSocket;
use embassy_net::udp::{PacketMetadata, UdpSocket};
use embassy_net::{IpAddress, IpEndpoint, Ipv4Address, Runner, Stack};
use embassy_sync::blocking_mutex::raw::CriticalSectionRawMutex;
use embassy_sync::mutex::Mutex;
use embassy_time::{with_timeout, Duration, Timer};
use esp_radio::wifi::Interface;

use crate::{apply_command, config as cfg, net, status_json, verify_admin, Origin};

const PORT_DHCP_SERVER: u16 = 67;
const PORT_DHCP_CLIENT: u16 = 68;
const PORT_DNS: u16 = 53;
const PORT_HTTP: u16 = 80;

const PAGE: &[u8] = include_bytes!("../web/dashboard.html");

/// Longest command line accepted over HTTP. Matches the USB line buffer, so
/// nothing that works over USB is refused here.
const MAX_CMD_BODY: usize = 320;

/// A client gets this long to deliver a complete request. Without a bound, a
/// handful of idle connections would hold every socket and lock the owner out.
const REQUEST_DEADLINE: Duration = Duration::from_secs(5);

/// Consecutive wrong passwords, across all connections. Each one adds delay
/// before the 401 goes out; a correct password clears it.
static AUTH_FAILURES: AtomicU32 = AtomicU32::new(0);

/// One status buffer shared by every listener. A listener holds it only while
/// building and sending one response, so five connections cost 6 KB, not 30.
static STATUS_BODY: Mutex<CriticalSectionRawMutex, net::Buf<{ net::STATUS_JSON_LEN }>> =
    Mutex::new(net::Buf::new());

#[embassy_executor::task]
pub async fn ap_net_runner_task(mut runner: Runner<'static, Interface>) {
    runner.run().await
}

// ---------------------------------------------------------------------------
// Minimal DHCP server (setup network)
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
// Catch-all DNS for captive-portal detection (setup network)
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
// HTTP
// ---------------------------------------------------------------------------
//
// Several listeners per network, because a browser polling once a second
// while a command is in flight wants two connections at the same moment, and
// a socket that is busy answering refuses the next connection outright.

#[embassy_executor::task(pool_size = 3)]
pub async fn sta_http_task(stack: Stack<'static>) {
    serve(stack, false).await
}

#[embassy_executor::task(pool_size = 2)]
pub async fn ap_http_task(stack: Stack<'static>) {
    serve(stack, true).await
}

async fn serve(stack: Stack<'static>, setup_network: bool) -> ! {
    let mut rx_storage = [0u8; 1024];
    let mut tx_storage = [0u8; 2048];
    let mut socket = TcpSocket::new(stack, &mut rx_storage, &mut tx_storage);
    socket.set_timeout(Some(Duration::from_secs(10)));

    loop {
        if socket.accept(PORT_HTTP).await.is_err() {
            socket.abort();
            Timer::after(Duration::from_millis(100)).await;
            continue;
        }
        handle(&mut socket, setup_network).await;

        // Same teardown the setup portal always used: everything written has
        // been acknowledged by the time flush returns, then the socket is
        // reset so it can listen again immediately.
        let _ = with_timeout(Duration::from_secs(2), socket.flush()).await;
        socket.close();
        Timer::after(Duration::from_millis(20)).await;
        socket.abort();
    }
}

async fn handle(socket: &mut TcpSocket<'_>, setup_network: bool) {
    let mut raw = [0u8; 1536];
    let used = match with_timeout(REQUEST_DEADLINE, read_request(socket, &mut raw)).await {
        Ok(Some(n)) => n,
        Ok(None) => {
            respond(socket, "413 Content Too Large", TEXT, b"ERR reason=request_too_large", &[]).await;
            return;
        }
        Err(_) => return,
    };
    let req = match net::parse_http(&raw[..used], MAX_CMD_BODY) {
        Ok(req) => req,
        Err(net::HttpParse::Bad("body_too_large")) => {
            respond(socket, "413 Content Too Large", TEXT, b"ERR reason=command_too_long", &[]).await;
            return;
        }
        Err(_) => {
            respond(socket, "400 Bad Request", TEXT, b"ERR reason=bad_request", &[]).await;
            return;
        }
    };

    let known = matches!(req.path, "/" | "/index.html" | "/api/status" | "/api/cmd");

    // Captive-portal probes on the setup network (generate_204, hotspot-detect
    // and friends) are pointed at the dashboard, which is what makes the phone
    // offer its sign-in sheet. Nothing is disclosed by a redirect, so this
    // happens before authentication.
    if !known {
        if setup_network && req.method == "GET" {
            respond(
                socket,
                "302 Found",
                TEXT,
                b"",
                &[("Location", "http://192.168.4.1/")],
            )
            .await;
        } else {
            respond(socket, "404 Not Found", TEXT, b"ERR reason=not_found", &[]).await;
        }
        return;
    }

    if !authorized(req.headers).await {
        respond(
            socket,
            "401 Unauthorized",
            TEXT,
            b"ERR reason=auth_required",
            &[("WWW-Authenticate", "Basic realm=\"Nocturnus\", charset=\"UTF-8\"")],
        )
        .await;
        return;
    }

    match (req.method, req.path) {
        ("GET", "/") | ("GET", "/index.html") => {
            respond(socket, "200 OK", HTML, PAGE, &[]).await;
        }
        ("GET", "/api/status") => {
            let mut body = STATUS_BODY.lock().await;
            status_json(&mut body).await;
            if body.overflowed() {
                respond(socket, "500 Internal Server Error", TEXT, b"ERR reason=status_overflow", &[]).await;
            } else {
                respond(socket, "200 OK", JSON, body.as_bytes(), &[]).await;
            }
        }
        ("POST", "/api/cmd") => {
            if net::header(req.headers, "x-nocturnus").is_none() {
                respond(socket, "403 Forbidden", TEXT, b"ERR reason=missing_x_nocturnus_header", &[]).await;
                return;
            }
            let mut reply = net::Buf::<512>::new();
            match core::str::from_utf8(req.body) {
                Ok(line) if !line.contains(['\r', '\n']) => {
                    apply_command(line, Origin::Web, &mut reply).await
                }
                Ok(_) => {
                    let _ = reply.write_str("ERR reason=one_line_only");
                }
                Err(_) => {
                    let _ = reply.write_str("ERR reason=utf8");
                }
            }
            respond(socket, "200 OK", TEXT, reply.as_bytes(), &[]).await;
        }
        _ => {
            respond(socket, "405 Method Not Allowed", TEXT, b"ERR reason=method", &[]).await;
        }
    }
}

/// Read until one complete request is buffered. `None` means it cannot fit.
async fn read_request(socket: &mut TcpSocket<'_>, raw: &mut [u8]) -> Option<usize> {
    let mut used = 0usize;
    loop {
        match net::parse_http(&raw[..used], MAX_CMD_BODY) {
            Err(net::HttpParse::Incomplete) => {}
            // Complete or malformed: either way the caller decides what to say.
            _ => return Some(used),
        }
        if used == raw.len() {
            return None;
        }
        match socket.read(&mut raw[used..]).await {
            Ok(0) | Err(_) => return Some(used),
            Ok(n) => used += n,
        }
    }
}

async fn authorized(headers: &str) -> bool {
    let Some(value) = net::header(headers, "authorization") else {
        // No credentials yet is the normal first request from a browser, not a
        // guess, so it costs nothing.
        return false;
    };
    let mut scratch = [0u8; 192];
    let ok = match net::basic_auth_password(value, cfg::ADMIN_USER, &mut scratch) {
        Some(password) => verify_admin(password).await,
        None => false,
    };
    scratch.fill(0);

    if ok {
        AUTH_FAILURES.store(0, Ordering::Relaxed);
    } else {
        // 250 ms per consecutive failure, capped at 4 s. With at most five
        // listeners, that holds an online guesser to a crawl while a typo
        // costs the owner a fraction of a second.
        let failures = AUTH_FAILURES.fetch_add(1, Ordering::Relaxed).saturating_add(1);
        let delay = (failures.min(16) as u64) * 250;
        Timer::after(Duration::from_millis(delay)).await;
    }
    ok
}

const HTML: &str = "text/html; charset=utf-8";
const JSON: &str = "application/json";
const TEXT: &str = "text/plain; charset=utf-8";

async fn respond(
    socket: &mut TcpSocket<'_>,
    status: &str,
    content_type: &str,
    body: &[u8],
    extra: &[(&str, &str)],
) {
    let mut head = net::Buf::<768>::new();
    let _ = write!(
        head,
        "HTTP/1.1 {status}\r\n\
         Content-Type: {content_type}\r\n\
         Content-Length: {}\r\n\
         Cache-Control: no-store\r\n\
         X-Content-Type-Options: nosniff\r\n\
         X-Frame-Options: DENY\r\n\
         Referrer-Policy: no-referrer\r\n\
         Content-Security-Policy: default-src 'none'; script-src 'unsafe-inline'; \
         style-src 'unsafe-inline'; connect-src 'self'; img-src 'self'; \
         base-uri 'none'; form-action 'none'; frame-ancestors 'none'\r\n\
         Connection: close\r\n",
        body.len()
    );
    for (name, value) in extra {
        let _ = write!(head, "{name}: {value}\r\n");
    }
    let _ = head.write_str("\r\n");
    if tcp_write_all(socket, head.as_bytes()).await.is_ok() {
        let _ = tcp_write_all(socket, body).await;
    }
}

async fn tcp_write_all(socket: &mut TcpSocket<'_>, mut data: &[u8]) -> Result<(), ()> {
    while !data.is_empty() {
        match with_timeout(Duration::from_secs(5), socket.write(data)).await {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => return Err(()),
            Ok(Ok(written)) => data = &data[written..],
        }
    }
    Ok(())
}
