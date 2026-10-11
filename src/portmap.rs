//! Router port forwarding: NAT-PMP (RFC 6886) first, UPnP IGD as fallback.
//!
//! [`map_port`] does a one-shot mapping, [`unmap`] removes it best-effort, and
//! [`spawn_renewal`] keeps a mapping alive at half-lifetime and publishes the
//! latest result for the UI. The renewal task does not unmap when aborted; call
//! [`unmap`] with the last published [`Mapping`] on shutdown.
//!
//! Everything read from the network is treated as hostile: lengths are checked,
//! every await has a timeout, and nothing panics on malformed input.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tokio::time::{timeout, Instant};
use url::Url;

const NATPMP_PORT: u16 = 5351;
const NATPMP_WAITS_MS: [u64; 4] = [250, 500, 1000, 1250];
const SSDP_ADDR: &str = "239.255.255.250:1900";
const SSDP_WINDOW: Duration = Duration::from_secs(2);
const HTTP_TIMEOUT: Duration = Duration::from_secs(4);
const HTTP_MAX_BYTES: u64 = 512 * 1024;
const RETRY_AFTER_FAILURE: Duration = Duration::from_secs(60);
const DESCRIPTION: &str = "torrentide";

#[derive(Debug, Error)]
pub enum PortMapError {
    #[error("no gateway found")]
    NoGateway,
    #[error("timed out")]
    Timeout,
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("protocol: {0}")]
    Protocol(String),
    #[error("refused: {0}")]
    Refused(String),
    #[error("UPnP fault {code}: {message}")]
    Fault { code: u32, message: String },
    #[error("NAT-PMP: {natpmp}; UPnP: {upnp}")]
    Both { natpmp: Box<PortMapError>, upnp: Box<PortMapError> },
}

type Result<T> = std::result::Result<T, PortMapError>;

fn protocol(msg: impl Into<String>) -> PortMapError {
    PortMapError::Protocol(msg.into())
}

#[derive(Debug, Clone)]
enum Via {
    NatPmp(Ipv4Addr),
    Upnp { control: Url, service: String },
}

#[derive(Debug, Clone)]
pub struct Mapping {
    pub external_port: u16,
    pub external_ip: Option<IpAddr>,
    pub method: &'static str,
    pub lifetime: Duration,
    via: Via,
}

impl fmt::Display for Mapping {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "forwarded via {}, ", self.method)?;
        match self.external_ip {
            Some(ip) => write!(f, "external {ip}:{}", self.external_port),
            None => write!(f, "external {}", self.external_port),
        }
    }
}

pub async fn map_port(port: u16, lifetime: Duration) -> Result<Mapping> {
    let gateway = default_gateway().await;
    let natpmp = match gateway {
        Some(gw) => match natpmp_map(gw, port, lifetime).await {
            Ok(m) => return Ok(m),
            Err(e) => e,
        },
        None => PortMapError::NoGateway,
    };
    match upnp_map(port, lifetime).await {
        Ok(m) => Ok(m),
        Err(upnp) => Err(PortMapError::Both { natpmp: Box::new(natpmp), upnp: Box::new(upnp) }),
    }
}

pub async fn unmap(mapping: &Mapping, port: u16) {
    match &mapping.via {
        Via::NatPmp(gw) => {
            let _ = natpmp_delete(*gw, port).await;
        }
        Via::Upnp { control, service } => {
            for proto in ["TCP", "UDP"] {
                let body = soap_delete_body(service, mapping.external_port, proto);
                let _ = soap_call(control, service, "DeletePortMapping", &body).await;
            }
        }
    }
}

pub fn spawn_renewal(
    port: u16,
    lifetime: Duration,
) -> (JoinHandle<()>, watch::Receiver<Option<std::result::Result<Mapping, String>>>) {
    let (tx, rx) = watch::channel(None);
    let handle = tokio::spawn(async move {
        loop {
            let wait = match map_port(port, lifetime).await {
                Ok(m) => {
                    let wait = (m.lifetime / 2).max(Duration::from_secs(1));
                    tx.send_replace(Some(Ok(m)));
                    wait
                }
                Err(e) => {
                    tx.send_replace(Some(Err(e.to_string())));
                    RETRY_AFTER_FAILURE
                }
            };
            tokio::time::sleep(wait).await;
        }
    });
    (handle, rx)
}

async fn lan_ip(target: IpAddr) -> Result<IpAddr> {
    let sock = UdpSocket::bind("0.0.0.0:0").await?;
    sock.connect(SocketAddr::new(target, 80)).await?;
    Ok(sock.local_addr()?.ip())
}

async fn default_gateway() -> Option<Ipv4Addr> {
    #[cfg(target_os = "macos")]
    {
        let out = command_output("route", &["-n", "get", "default"]).await?;
        parse_route_get(&out)
    }
    #[cfg(target_os = "linux")]
    {
        let text = tokio::fs::read_to_string("/proc/net/route").await.ok()?;
        parse_proc_net_route(&text)
    }
    #[cfg(windows)]
    {
        let out = command_output("route", &["print", "-4", "0.0.0.0"]).await?;
        parse_route_print(&out)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
    {
        None
    }
}

#[cfg(any(target_os = "macos", windows))]
async fn command_output(program: &str, args: &[&str]) -> Option<String> {
    let out = timeout(
        Duration::from_secs(3),
        tokio::process::Command::new(program).args(args).kill_on_drop(true).output(),
    )
    .await
    .ok()?
    .ok()?;
    Some(String::from_utf8_lossy(&out.stdout).into_owned())
}

#[allow(dead_code)]
fn parse_route_get(out: &str) -> Option<Ipv4Addr> {
    out.lines().find_map(|l| l.trim().strip_prefix("gateway:")?.trim().parse().ok())
}

#[allow(dead_code)]
fn parse_proc_net_route(text: &str) -> Option<Ipv4Addr> {
    text.lines().skip(1).find_map(|l| {
        let f: Vec<&str> = l.split_whitespace().collect();
        if f.len() < 4 || f[1] != "00000000" {
            return None;
        }
        let flags = u32::from_str_radix(f[3], 16).ok()?;
        if flags & 2 == 0 {
            return None;
        }
        let gw = Ipv4Addr::from(u32::from_str_radix(f[2], 16).ok()?.to_ne_bytes());
        (!gw.is_unspecified()).then_some(gw)
    })
}

#[allow(dead_code)]
fn parse_route_print(out: &str) -> Option<Ipv4Addr> {
    out.lines().find_map(|l| {
        let f: Vec<&str> = l.split_whitespace().collect();
        if f.len() >= 3 && f[0] == "0.0.0.0" && f[1] == "0.0.0.0" {
            f[2].parse().ok()
        } else {
            None
        }
    })
}

fn natpmp_header(buf: &[u8], op: u8, min_len: usize) -> Result<()> {
    if buf.len() < min_len {
        return Err(protocol("short NAT-PMP packet"));
    }
    if buf[0] != 0 || buf[1] != 128 + op {
        return Err(protocol("unexpected NAT-PMP header"));
    }
    match u16::from_be_bytes([buf[2], buf[3]]) {
        0 => Ok(()),
        1 => Err(PortMapError::Refused("unsupported version".into())),
        2 => Err(PortMapError::Refused("not authorized".into())),
        3 => Err(PortMapError::Refused("network failure".into())),
        4 => Err(PortMapError::Refused("out of resources".into())),
        5 => Err(PortMapError::Refused("unsupported opcode".into())),
        n => Err(PortMapError::Refused(format!("result code {n}"))),
    }
}

fn natpmp_external_request() -> [u8; 2] {
    [0, 0]
}

fn natpmp_map_request(op: u8, internal: u16, external: u16, lifetime: u32) -> [u8; 12] {
    let mut b = [0u8; 12];
    b[1] = op;
    b[4..6].copy_from_slice(&internal.to_be_bytes());
    b[6..8].copy_from_slice(&external.to_be_bytes());
    b[8..12].copy_from_slice(&lifetime.to_be_bytes());
    b
}

fn parse_natpmp_external(buf: &[u8]) -> Result<Ipv4Addr> {
    natpmp_header(buf, 0, 12)?;
    Ok(Ipv4Addr::new(buf[8], buf[9], buf[10], buf[11]))
}

fn parse_natpmp_map(buf: &[u8], op: u8) -> Result<(u16, u32)> {
    natpmp_header(buf, op, 16)?;
    Ok((
        u16::from_be_bytes([buf[10], buf[11]]),
        u32::from_be_bytes([buf[12], buf[13], buf[14], buf[15]]),
    ))
}

async fn natpmp_exchange<T>(
    sock: &UdpSocket,
    req: &[u8],
    parse: impl Fn(&[u8]) -> Result<T>,
) -> Result<T> {
    let mut buf = [0u8; 64];
    for wait in NATPMP_WAITS_MS {
        sock.send(req).await?;
        let deadline = Instant::now() + Duration::from_millis(wait);
        while let Ok(n) = timeout(deadline.saturating_duration_since(Instant::now()), sock.recv(&mut buf)).await {
            match parse(&buf[..n?]) {
                Err(PortMapError::Protocol(_)) => continue,
                other => return other,
            }
        }
    }
    Err(PortMapError::Timeout)
}

async fn natpmp_socket(gateway: Ipv4Addr) -> Result<UdpSocket> {
    let sock = UdpSocket::bind("0.0.0.0:0").await?;
    sock.connect(SocketAddr::new(gateway.into(), NATPMP_PORT)).await?;
    Ok(sock)
}

fn clamp_secs(d: Duration) -> u32 {
    d.as_secs().min(u32::MAX as u64) as u32
}

async fn natpmp_map(gateway: Ipv4Addr, port: u16, lifetime: Duration) -> Result<Mapping> {
    let sock = natpmp_socket(gateway).await?;
    let ip = natpmp_exchange(&sock, &natpmp_external_request(), parse_natpmp_external).await?;
    let secs = clamp_secs(lifetime);
    let req = natpmp_map_request(2, port, port, secs);
    let (external_port, granted) = natpmp_exchange(&sock, &req, |b| parse_natpmp_map(b, 2)).await?;
    let req = natpmp_map_request(1, port, port, secs);
    let _ = natpmp_exchange(&sock, &req, |b| parse_natpmp_map(b, 1)).await;
    Ok(Mapping {
        external_port,
        external_ip: Some(IpAddr::V4(ip)).filter(|ip| !ip.is_unspecified()),
        method: "NAT-PMP",
        lifetime: Duration::from_secs(granted as u64),
        via: Via::NatPmp(gateway),
    })
}

async fn natpmp_delete(gateway: Ipv4Addr, port: u16) -> Result<()> {
    let sock = natpmp_socket(gateway).await?;
    for op in [2u8, 1] {
        let req = natpmp_map_request(op, port, 0, 0);
        natpmp_exchange(&sock, &req, |b| parse_natpmp_map(b, op)).await?;
    }
    Ok(())
}

fn ssdp_search(st: &str) -> String {
    format!(
        "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: {st}\r\n\r\n"
    )
}

fn parse_ssdp_location(resp: &str) -> Option<&str> {
    resp.lines().find_map(|l| {
        let (k, v) = l.split_once(':')?;
        (k.trim().eq_ignore_ascii_case("location")).then(|| v.trim()).filter(|v| !v.is_empty())
    })
}

async fn ssdp_discover() -> Result<Vec<(Url, IpAddr)>> {
    let sock = UdpSocket::bind("0.0.0.0:0").await?;
    for st in [
        "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
        "urn:schemas-upnp-org:service:WANIPConnection:1",
        "urn:schemas-upnp-org:service:WANPPPConnection:1",
    ] {
        sock.send_to(ssdp_search(st).as_bytes(), SSDP_ADDR).await?;
    }
    let mut found: Vec<(Url, IpAddr)> = Vec::new();
    let deadline = Instant::now() + SSDP_WINDOW;
    let mut buf = [0u8; 2048];
    while let Ok(r) = timeout(deadline.saturating_duration_since(Instant::now()), sock.recv_from(&mut buf)).await {
        let (n, from) = r?;
        let text = String::from_utf8_lossy(&buf[..n]);
        let Some(url) = parse_ssdp_location(&text).and_then(|l| Url::parse(l).ok()) else {
            continue;
        };
        let host_is_sender = url.host_str().and_then(|h| h.parse::<IpAddr>().ok()) == Some(from.ip());
        if url.scheme() == "http" && host_is_sender && !found.iter().any(|(u, _)| *u == url) {
            found.push((url, from.ip()));
        }
    }
    if found.is_empty() {
        return Err(PortMapError::Timeout);
    }
    Ok(found)
}

fn xml_elements<'a>(xml: &'a str, name: &str) -> Vec<&'a str> {
    let mut out = Vec::new();
    let mut rest = xml;
    while let Some(i) = rest.find('<') {
        rest = &rest[i + 1..];
        let Some(end) = rest.find(|c: char| c == '>' || c == '/' || c.is_whitespace()) else {
            break;
        };
        let tag = &rest[..end];
        if tag.is_empty() || tag.starts_with(['/', '!', '?']) || tag.rsplit(':').next() != Some(name) {
            continue;
        }
        let Some(gt) = rest.find('>') else { break };
        if rest[..gt].ends_with('/') {
            continue;
        }
        let body = &rest[gt + 1..];
        let close = format!("</{tag}>");
        if let Some(c) = body.find(&close) {
            out.push(body[..c].trim());
            rest = &body[c + close.len()..];
        }
    }
    out
}

fn parse_description(xml: &str, base: &Url) -> Option<(Url, String)> {
    xml_elements(xml, "service").into_iter().find_map(|svc| {
        let st = xml_elements(svc, "serviceType").into_iter().next()?;
        let wan = st.contains(":service:WANIPConnection:") || st.contains(":service:WANPPPConnection:");
        if !wan {
            return None;
        }
        let ctl = xml_elements(svc, "controlURL").into_iter().next()?;
        let url = base.join(ctl).ok()?;
        (url.scheme() == "http" && url.host_str() == base.host_str()).then(|| (url, st.to_string()))
    })
}

async fn http_request(url: &Url, method: &str, extra: &str, body: &str) -> Result<(u16, String)> {
    let host = url.host_str().ok_or_else(|| protocol("url has no host"))?;
    let port = url.port_or_known_default().unwrap_or(80);
    let target = match url.query() {
        Some(q) => format!("{}?{q}", url.path()),
        None => url.path().to_string(),
    };
    let req = format!(
        "{method} {target} HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\nContent-Length: {}\r\n{extra}\r\n{body}",
        body.len()
    );
    let fut = async {
        let ip: IpAddr = host.parse().map_err(|_| protocol("non-IP host"))?;
        let mut s = TcpStream::connect(SocketAddr::new(ip, port)).await?;
        s.write_all(req.as_bytes()).await?;
        let mut raw = Vec::new();
        (&mut s).take(HTTP_MAX_BYTES).read_to_end(&mut raw).await?;
        Ok::<_, PortMapError>(raw)
    };
    let raw = timeout(HTTP_TIMEOUT, fut).await.map_err(|_| PortMapError::Timeout)??;
    parse_http_response(&raw)
}

fn parse_http_response(raw: &[u8]) -> Result<(u16, String)> {
    let split = raw.windows(4).position(|w| w == b"\r\n\r\n").ok_or_else(|| protocol("no HTTP headers"))?;
    let head = String::from_utf8_lossy(&raw[..split]);
    let mut lines = head.lines();
    let status = lines
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u16>().ok())
        .ok_or_else(|| protocol("bad HTTP status line"))?;
    let chunked = lines.any(|l| {
        let l = l.to_ascii_lowercase();
        l.starts_with("transfer-encoding:") && l.contains("chunked")
    });
    let body = &raw[split + 4..];
    let body = if chunked { dechunk(body) } else { body.to_vec() };
    Ok((status, String::from_utf8_lossy(&body).into_owned()))
}

fn dechunk(mut b: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    while let Some(nl) = b.windows(2).position(|w| w == b"\r\n") {
        let size_txt = String::from_utf8_lossy(&b[..nl]);
        let Ok(size) = usize::from_str_radix(size_txt.split(';').next().unwrap_or("").trim(), 16) else {
            break;
        };
        b = &b[nl + 2..];
        if size == 0 || b.len() < size {
            out.extend_from_slice(&b[..b.len().min(size)]);
            break;
        }
        out.extend_from_slice(&b[..size]);
        b = b.get(size + 2..).unwrap_or(&[]);
    }
    out
}

fn soap_envelope(service: &str, action: &str, args: &str) -> String {
    format!(
        "<?xml version=\"1.0\"?>\r\n<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" \
         s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body>\
         <u:{action} xmlns:u=\"{service}\">{args}</u:{action}></s:Body></s:Envelope>"
    )
}

fn soap_add_body(service: &str, ext: u16, proto: &str, int: u16, client: IpAddr, lease: u32) -> String {
    soap_envelope(
        service,
        "AddPortMapping",
        &format!(
            "<NewRemoteHost></NewRemoteHost><NewExternalPort>{ext}</NewExternalPort>\
             <NewProtocol>{proto}</NewProtocol><NewInternalPort>{int}</NewInternalPort>\
             <NewInternalClient>{client}</NewInternalClient><NewEnabled>1</NewEnabled>\
             <NewPortMappingDescription>{DESCRIPTION}</NewPortMappingDescription>\
             <NewLeaseDuration>{lease}</NewLeaseDuration>"
        ),
    )
}

fn soap_delete_body(service: &str, ext: u16, proto: &str) -> String {
    soap_envelope(
        service,
        "DeletePortMapping",
        &format!(
            "<NewRemoteHost></NewRemoteHost><NewExternalPort>{ext}</NewExternalPort>\
             <NewProtocol>{proto}</NewProtocol>"
        ),
    )
}

fn parse_soap_response(status: u16, body: &str) -> Result<String> {
    if status == 200 {
        return Ok(body.to_string());
    }
    let code = xml_elements(body, "errorCode").first().and_then(|c| c.parse().ok());
    let message = xml_elements(body, "errorDescription").first().copied().unwrap_or("").to_string();
    match code {
        Some(code) => Err(PortMapError::Fault { code, message }),
        None => Err(PortMapError::Refused(format!("HTTP {status}"))),
    }
}

fn parse_external_ip(body: &str) -> Option<IpAddr> {
    xml_elements(body, "NewExternalIPAddress").first()?.parse().ok()
}

async fn soap_call(control: &Url, service: &str, action: &str, body: &str) -> Result<String> {
    let extra = format!(
        "Content-Type: text/xml; charset=\"utf-8\"\r\nSOAPAction: \"{service}#{action}\"\r\n"
    );
    let (status, resp) = http_request(control, "POST", &extra, body).await?;
    parse_soap_response(status, &resp)
}

async fn upnp_map(port: u16, lifetime: Duration) -> Result<Mapping> {
    let mut last = PortMapError::Timeout;
    for (location, gw) in ssdp_discover().await? {
        match upnp_map_at(&location, gw, port, lifetime).await {
            Ok(m) => return Ok(m),
            Err(e) => last = e,
        }
    }
    Err(last)
}

async fn upnp_map_at(location: &Url, gw: IpAddr, port: u16, lifetime: Duration) -> Result<Mapping> {
    let (status, xml) = http_request(location, "GET", "", "").await?;
    if status != 200 {
        return Err(PortMapError::Refused(format!("description HTTP {status}")));
    }
    let (control, service) = parse_description(&xml, location).ok_or_else(|| protocol("no WAN*Connection service"))?;
    let client = lan_ip(gw).await?;
    let mut lease = clamp_secs(lifetime);
    for proto in ["TCP", "UDP"] {
        let call = |lease| soap_call_add(&control, &service, port, proto, client, lease);
        match call(lease).await {
            Err(PortMapError::Fault { code: 725, .. }) => {
                lease = 0;
                call(lease).await?;
            }
            Err(e) if proto == "TCP" => return Err(e),
            _ => {}
        }
    }
    let external_ip = match soap_call(&control, &service, "GetExternalIPAddress", &soap_envelope(&service, "GetExternalIPAddress", "")).await {
        Ok(body) => parse_external_ip(&body),
        Err(_) => None,
    };
    Ok(Mapping {
        external_port: port,
        external_ip,
        method: "UPnP",
        lifetime: if lease == 0 { lifetime } else { Duration::from_secs(lease as u64) },
        via: Via::Upnp { control, service },
    })
}

async fn soap_call_add(control: &Url, service: &str, port: u16, proto: &str, client: IpAddr, lease: u32) -> Result<String> {
    soap_call(control, service, "AddPortMapping", &soap_add_body(service, port, proto, port, client, lease)).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn natpmp_requests() {
        assert_eq!(natpmp_external_request(), [0, 0]);
        let r = natpmp_map_request(2, 6881, 6881, 7200);
        assert_eq!(r, [0, 2, 0, 0, 0x1a, 0xe1, 0x1a, 0xe1, 0, 0, 0x1c, 0x20]);
        assert_eq!(natpmp_map_request(1, 1, 0, 0)[1], 1);
    }

    #[test]
    fn natpmp_responses() {
        let ext = [0, 128, 0, 0, 0, 0, 0, 9, 1, 2, 3, 4];
        assert_eq!(parse_natpmp_external(&ext).unwrap(), Ipv4Addr::new(1, 2, 3, 4));
        let mut map = [0u8; 16];
        map[1] = 130;
        map[10..12].copy_from_slice(&5000u16.to_be_bytes());
        map[12..16].copy_from_slice(&3600u32.to_be_bytes());
        assert_eq!(parse_natpmp_map(&map, 2).unwrap(), (5000, 3600));
        assert!(matches!(parse_natpmp_map(&map, 1), Err(PortMapError::Protocol(_))));
        map[3] = 2;
        assert!(matches!(parse_natpmp_map(&map, 2), Err(PortMapError::Refused(_))));
        for n in 0..16 {
            assert!(parse_natpmp_map(&map[..n], 2).is_err());
        }
        assert!(parse_natpmp_external(&[0xff; 12]).is_err());
        assert!(parse_natpmp_external(&[]).is_err());
    }

    #[test]
    fn ssdp_location() {
        let r = "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=120\r\nLocation: http://192.168.1.1:5000/rootDesc.xml\r\nST: x\r\n\r\n";
        assert_eq!(parse_ssdp_location(r), Some("http://192.168.1.1:5000/rootDesc.xml"));
        assert_eq!(parse_ssdp_location("HTTP/1.1 200 OK\nLOCATION:http://a/b\n\n"), Some("http://a/b"));
        assert_eq!(parse_ssdp_location("HTTP/1.1 200 OK\r\n\r\n"), None);
    }

    const DESC: &str = r#"<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0"><device><serviceList>
<service><serviceType>urn:schemas-upnp-org:service:Layer3Forwarding:1</serviceType><controlURL>/l3f</controlURL></service>
</serviceList><deviceList><device><deviceList><device><serviceList>
<service>
  <serviceType>
    urn:schemas-upnp-org:service:WANIPConnection:1
  </serviceType>
  <controlURL> /ctl/IPConn </controlURL>
</service></serviceList></device></deviceList></device></deviceList></device></root>"#;

    #[test]
    fn description_relative_and_prefixed() {
        let base = Url::parse("http://192.168.1.1:5000/rootDesc.xml").unwrap();
        let (u, s) = parse_description(DESC, &base).unwrap();
        assert_eq!(u.as_str(), "http://192.168.1.1:5000/ctl/IPConn");
        assert_eq!(s, "urn:schemas-upnp-org:service:WANIPConnection:1");

        let xml = "<d:service><d:serviceType>urn:schemas-upnp-org:service:WANPPPConnection:1</d:serviceType>\
                   <d:controlURL>http://192.168.1.1:80/ppp</d:controlURL></d:service>";
        assert_eq!(parse_description(xml, &base).unwrap().0.as_str(), "http://192.168.1.1/ppp");
        let evil = xml.replace("192.168.1.1:80", "10.9.9.9");
        assert!(parse_description(&evil, &base).is_none());
        assert!(parse_description("<service><serviceType>", &base).is_none());
    }

    #[test]
    fn soap_bodies_and_responses() {
        let svc = "urn:schemas-upnp-org:service:WANIPConnection:1";
        let b = soap_add_body(svc, 6881, "TCP", 6881, "192.168.1.5".parse().unwrap(), 7200);
        assert!(b.contains("<u:AddPortMapping xmlns:u=\"urn:schemas-upnp-org:service:WANIPConnection:1\">"));
        assert!(b.contains("<NewProtocol>TCP</NewProtocol>"));
        assert!(b.contains("<NewInternalClient>192.168.1.5</NewInternalClient>"));
        assert!(b.contains("<NewLeaseDuration>7200</NewLeaseDuration>"));
        assert!(soap_delete_body(svc, 1, "UDP").contains("DeletePortMapping"));

        let ok = "<s:Envelope><s:Body><u:GetExternalIPAddressResponse>\
                  <NewExternalIPAddress>203.0.113.7</NewExternalIPAddress></u:GetExternalIPAddressResponse></s:Body></s:Envelope>";
        let body = parse_soap_response(200, ok).unwrap();
        assert_eq!(parse_external_ip(&body), Some("203.0.113.7".parse().unwrap()));

        let fault = "<s:Envelope><s:Body><s:Fault><detail><UPnPError><errorCode>725</errorCode>\
                     <errorDescription>OnlyPermanentLeasesSupported</errorDescription></UPnPError></detail></s:Fault></s:Body></s:Envelope>";
        assert!(matches!(parse_soap_response(500, fault), Err(PortMapError::Fault { code: 725, .. })));
        assert!(matches!(parse_soap_response(500, "garbage"), Err(PortMapError::Refused(_))));
    }

    #[test]
    fn http_parsing() {
        let r = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi";
        assert_eq!(parse_http_response(r).unwrap(), (200, "hi".to_string()));
        let c = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n";
        assert_eq!(parse_http_response(c).unwrap().1, "abcde");
        assert!(parse_http_response(b"junk").is_err());
        let _ = dechunk(b"ffffffffff\r\nabc");
    }

    #[test]
    fn route_parsing() {
        let mac = "   route to: default\ndestination: default\n       mask: default\n    gateway: 192.168.1.1\n  interface: en0\n";
        assert_eq!(parse_route_get(mac), Some(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(parse_route_get("route: writing to routing socket: not in table"), None);
        let proc = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\tMTU\tWindow\tIRTT\n\
                    eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n\
                    eth0\t0001A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n";
        assert_eq!(parse_proc_net_route(proc), Some(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(parse_proc_net_route("Iface\tDestination\n"), None);
        let win = "Network Destination        Netmask          Gateway       Interface  Metric\n          0.0.0.0          0.0.0.0      192.168.1.1     192.168.1.50     25\n";
        assert_eq!(parse_route_print(win), Some(Ipv4Addr::new(192, 168, 1, 1)));
    }

    #[tokio::test]
    #[ignore]
    async fn real_router() {
        let r = map_port(6881, Duration::from_secs(120)).await;
        println!("{r:?}");
        if let Ok(m) = r {
            println!("{m}");
            unmap(&m, 6881).await;
        }
    }
}
