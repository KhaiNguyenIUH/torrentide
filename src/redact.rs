use url::Url;

pub fn url(s: &str) -> String {
    let Ok(u) = Url::parse(s.trim()) else {
        return "<redacted>".to_string();
    };
    let Some(host) = u.host_str() else {
        return "<redacted>".to_string();
    };
    match u.port() {
        Some(p) => format!("{}://{}:{}", u.scheme(), host, p),
        None => format!("{}://{}", u.scheme(), host),
    }
}

pub fn magnet(s: &str) -> String {
    let Ok(u) = Url::parse(s.trim()) else {
        return "<redacted>".to_string();
    };
    let mut parts = vec![];
    for (k, v) in u.query_pairs() {
        match k.as_ref() {
            "xt" => parts.push(format!("xt={v}")),
            "dn" => parts.push(format!("dn={v}")),
            "tr" => parts.push(format!("tr={}", url(&v))),
            _ => {}
        }
    }
    format!("magnet:?{}", parts.join("&"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_drops_everything_but_origin() {
        assert_eq!(url("http://user:pw@t.example:8080/PASSKEY/announce?k=SECRET#f"), "http://t.example:8080");
        assert_eq!(url("https://t.example/abc123/announce"), "https://t.example");
        assert_eq!(url("udp://t.example:6969/announce?passkey=zz"), "udp://t.example:6969");
        assert_eq!(url("http://[::1]:80/x/secret"), "http://[::1]");
        assert_eq!(url("not a url with secret"), "<redacted>");
        assert_eq!(url("mailto:secret@x"), "<redacted>");
    }

    #[test]
    fn magnet_keeps_xt_dn_and_redacts_trackers() {
        let m = magnet("magnet:?xt=urn:btih:abcd&dn=Name&tr=http%3A%2F%2Ft.example%2FSECRET%2Fannounce&x.pe=1.2.3.4:5&ws=http://w/SECRET");
        assert_eq!(m, "magnet:?xt=urn:btih:abcd&dn=Name&tr=http://t.example");
        assert!(!m.contains("SECRET"));
        assert_eq!(magnet("garbage"), "<redacted>");
    }
}
