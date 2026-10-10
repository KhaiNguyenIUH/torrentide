//! RSS 2.0 and Atom feeds: fetching, tolerant parsing, and the per-feed filter state.
//!
//! The parser is a small hand-rolled tokenizer rather than a full XML implementation.
//! Feeds come from arbitrary servers and are frequently sloppy, so it never fails on
//! malformed markup: it keeps the items it completed and drops the rest.

use std::collections::{HashSet, VecDeque};
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{anyhow, Result};
use url::Url;

const MAX_FEED_BYTES: usize = 2 * 1024 * 1024;
const MAX_ITEMS: usize = 2000;
const MAX_TEXT: usize = 8192;
const FETCH_TIMEOUT: Duration = Duration::from_secs(60);
const SEEN_CAP: usize = 1000;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Item {
    pub title: String,
    pub link: Option<String>,
    pub guid: Option<String>,
    /// Best torrent source: a BitTorrent enclosure, else a magnet, else a `.torrent`
    /// link, else the plain link.
    pub torrent: Option<String>,
    pub published: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct ParsedFeed {
    pub title: Option<String>,
    pub items: Vec<Item>,
}

pub async fn fetch(url: &str, allow_local: bool) -> Result<Vec<Item>> {
    let body = tokio::time::timeout(FETCH_TIMEOUT, crate::webseed::get_capped(url, MAX_FEED_BYTES, allow_local))
        .await
        .map_err(|_| anyhow!("feed fetch timed out"))??;
    Ok(parse_at(&String::from_utf8_lossy(&body), url)?.items)
}

pub fn parse(xml: &str) -> Result<ParsedFeed> {
    parse_inner(xml, None)
}

/// Like [`parse`], resolving relative links against the feed's own URL.
pub fn parse_at(xml: &str, base: &str) -> Result<ParsedFeed> {
    parse_inner(xml, Url::parse(base).ok())
}

enum Tok<'a> {
    Start { name: &'a str, attrs: Vec<(String, String)>, empty: bool },
    End,
    Text { raw: &'a str, cdata: bool },
}

fn local(name: &str) -> String {
    name.rsplit(':').next().unwrap_or(name).to_ascii_lowercase()
}

fn parse_attrs(mut s: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    loop {
        s = s.trim_start();
        let end = s.find(|c: char| c.is_whitespace() || c == '=').unwrap_or(s.len());
        if end == 0 {
            break;
        }
        let name = local(&s[..end]);
        s = s[end..].trim_start();
        let Some(rest) = s.strip_prefix('=') else {
            continue;
        };
        let rest = rest.trim_start();
        let (value, after) = match rest.chars().next() {
            Some(q @ ('"' | '\'')) => match rest[1..].find(q) {
                Some(i) => (&rest[1..1 + i], &rest[i + 2..]),
                None => (&rest[1..], ""),
            },
            _ => {
                let i = rest.find(char::is_whitespace).unwrap_or(rest.len());
                (&rest[..i], &rest[i..])
            }
        };
        out.push((name, decode(value)));
        s = after;
    }
    out
}

fn tokenize(xml: &str) -> Vec<Tok<'_>> {
    let mut toks = Vec::new();
    let mut rest = xml;
    while !rest.is_empty() {
        let Some(lt) = rest.find('<') else {
            toks.push(Tok::Text { raw: rest, cdata: false });
            break;
        };
        if lt > 0 {
            toks.push(Tok::Text { raw: &rest[..lt], cdata: false });
        }
        rest = &rest[lt..];
        if let Some(body) = rest.strip_prefix("<![CDATA[") {
            let (raw, after) = match body.find("]]>") {
                Some(i) => (&body[..i], &body[i + 3..]),
                None => (body, ""),
            };
            toks.push(Tok::Text { raw, cdata: true });
            rest = after;
        } else if let Some(body) = rest.strip_prefix("<!--") {
            rest = body.find("-->").map_or("", |i| &body[i + 3..]);
        } else if rest.starts_with("<?") || rest.starts_with("<!") {
            rest = rest.find('>').map_or("", |i| &rest[i + 1..]);
        } else if let Some(body) = rest.strip_prefix("</") {
            toks.push(Tok::End);
            rest = body.find('>').map_or("", |i| &body[i + 1..]);
        } else {
            let body = &rest[1..];
            let mut quote = None;
            let mut close = None;
            for (i, c) in body.char_indices() {
                match (quote, c) {
                    (None, '"' | '\'') => quote = Some(c),
                    (Some(q), c) if c == q => quote = None,
                    (None, '>') => {
                        close = Some(i);
                        break;
                    }
                    _ => {}
                }
            }
            let Some(close) = close else {
                break;
            };
            let mut inner = &body[..close];
            let empty = inner.ends_with('/');
            if empty {
                inner = &inner[..inner.len() - 1];
            }
            let name_end = inner.find(char::is_whitespace).unwrap_or(inner.len());
            toks.push(Tok::Start {
                name: &inner[..name_end],
                attrs: parse_attrs(&inner[name_end..]),
                empty,
            });
            rest = &body[close + 1..];
        }
    }
    toks
}

fn decode(s: &str) -> String {
    if !s.contains('&') {
        return s.to_owned();
    }
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(amp) = rest.find('&') {
        out.push_str(&rest[..amp]);
        rest = &rest[amp..];
        let decoded = rest[1..].find(';').filter(|&i| i <= 10).and_then(|i| {
            let ent = &rest[1..1 + i];
            let c = match ent {
                "amp" => '&',
                "lt" => '<',
                "gt" => '>',
                "quot" => '"',
                "apos" => '\'',
                _ => {
                    let num = ent.strip_prefix('#')?;
                    let n = match num.strip_prefix(['x', 'X']) {
                        Some(h) => u32::from_str_radix(h, 16).ok()?,
                        None => num.parse().ok()?,
                    };
                    char::from_u32(n)?
                }
            };
            Some((c, i + 2))
        });
        match decoded {
            Some((c, len)) => {
                out.push(c);
                rest = &rest[len..];
            }
            None => {
                out.push('&');
                rest = &rest[1..];
            }
        }
    }
    out.push_str(rest);
    out
}

fn attr<'a>(attrs: &'a [(String, String)], name: &str) -> Option<&'a str> {
    attrs.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
}

fn is_magnet(s: &str) -> bool {
    s.get(..7).is_some_and(|p| p.eq_ignore_ascii_case("magnet:"))
}

fn is_torrent_url(s: &str) -> bool {
    let path = s.split(['?', '#']).next().unwrap_or(s);
    path.to_ascii_lowercase().ends_with(".torrent")
}

#[derive(Default)]
struct Draft {
    title: String,
    link: Option<String>,
    guid: Option<String>,
    published: Option<String>,
    magnet: Option<String>,
    bt_enclosure: Option<String>,
}

impl Draft {
    fn finish(self) -> Item {
        let link = self.link.filter(|l| !l.is_empty());
        let guid = self.guid.filter(|g| !g.is_empty());
        let magnet = self
            .magnet
            .or_else(|| link.clone().filter(|l| is_magnet(l)))
            .or_else(|| guid.clone().filter(|g| is_magnet(g)));
        let torrent = self
            .bt_enclosure
            .or(magnet)
            .or_else(|| link.clone().filter(|l| is_torrent_url(l)))
            .or_else(|| link.clone());
        Item { title: self.title, link, guid, torrent, published: self.published }
    }
}

fn resolve(base: &Option<Url>, s: &str) -> String {
    match base {
        Some(b) if !is_magnet(s) => b.join(s).map_or_else(|_| s.to_owned(), |u| u.to_string()),
        _ => s.to_owned(),
    }
}

fn parse_inner(xml: &str, base: Option<Url>) -> Result<ParsedFeed> {
    let mut end = xml.len().min(MAX_FEED_BYTES);
    while !xml.is_char_boundary(end) {
        end -= 1;
    }
    let mut feed = ParsedFeed::default();
    let mut saw_root = false;
    let mut depth = 0usize;
    let mut item_depth = 0usize;
    let mut draft: Option<Draft> = None;
    let mut capture: Option<String> = None;
    let mut buf = String::new();
    let mut feed_title_open = false;

    for tok in tokenize(&xml[..end]) {
        match tok {
            Tok::Text { raw, cdata } => {
                if (capture.is_some() || feed_title_open) && buf.len() < MAX_TEXT {
                    if cdata {
                        buf.push_str(raw);
                    } else {
                        buf.push_str(&decode(raw));
                    }
                }
            }
            Tok::Start { name, attrs, empty } => {
                let name = local(name);
                if !empty {
                    depth += 1;
                }
                if matches!(name.as_str(), "rss" | "feed" | "channel" | "rdf") {
                    saw_root = true;
                }
                match draft.as_mut() {
                    None => {
                        if matches!(name.as_str(), "item" | "entry") && !empty {
                            draft = Some(Draft::default());
                            item_depth = depth;
                        } else if name == "title" && !empty && feed.title.is_none() {
                            feed_title_open = true;
                            buf.clear();
                        }
                    }
                    Some(d) if empty || depth == item_depth + 1 => match name.as_str() {
                        "enclosure" => {
                            if let Some(url) = attr(&attrs, "url").or_else(|| attr(&attrs, "href")) {
                                let url = resolve(&base, url.trim());
                                let bt = attr(&attrs, "type")
                                    .is_some_and(|t| t.eq_ignore_ascii_case("application/x-bittorrent"))
                                    || is_torrent_url(&url);
                                if is_magnet(&url) {
                                    d.magnet.get_or_insert(url);
                                } else if bt {
                                    d.bt_enclosure.get_or_insert(url);
                                }
                            }
                        }
                        "link" if attr(&attrs, "href").is_some() => {
                            let href = resolve(&base, attr(&attrs, "href").unwrap_or("").trim());
                            let rel = attr(&attrs, "rel").unwrap_or("alternate");
                            let bt = attr(&attrs, "type")
                                .is_some_and(|t| t.eq_ignore_ascii_case("application/x-bittorrent"));
                            if is_magnet(&href) {
                                d.magnet.get_or_insert(href);
                            } else if bt || (rel == "enclosure" && is_torrent_url(&href)) {
                                d.bt_enclosure.get_or_insert(href);
                            } else if rel == "alternate" {
                                d.link.get_or_insert(href);
                            }
                        }
                        "title" | "link" | "guid" | "id" | "pubdate" | "updated" | "published"
                        | "date" | "magneturi"
                            if !empty =>
                        {
                            capture = Some(name);
                            buf.clear();
                        }
                        _ => {}
                    },
                    Some(_) => {}
                }
            }
            Tok::End => {
                if feed_title_open && draft.is_none() {
                    let t = buf.trim();
                    if !t.is_empty() {
                        feed.title = Some(t.to_owned());
                    }
                    feed_title_open = false;
                }
                if let Some(d) = draft.as_mut() {
                    if depth == item_depth + 1 {
                        if let Some(name) = capture.take() {
                            let text = buf.trim().to_owned();
                            if !text.is_empty() {
                                match name.as_str() {
                                    "title" => d.title = text,
                                    "link" => {
                                        d.link.get_or_insert_with(|| resolve(&base, &text));
                                    }
                                    "guid" | "id" => {
                                        d.guid.get_or_insert(text);
                                    }
                                    "magneturi" => {
                                        d.magnet.get_or_insert(text);
                                    }
                                    _ => {
                                        d.published.get_or_insert(text);
                                    }
                                }
                            }
                        }
                    } else if depth == item_depth {
                        if let Some(d) = draft.take() {
                            if feed.items.len() < MAX_ITEMS {
                                feed.items.push(d.finish());
                            }
                        }
                    }
                }
                depth = depth.saturating_sub(1);
            }
        }
    }
    if !saw_root && feed.items.is_empty() {
        return Err(anyhow!("not an RSS or Atom feed"));
    }
    Ok(feed)
}

/// A subscribed feed with its filters and the items already handed out.
///
/// On the first poll `seen` is empty, so every currently matching item in the feed is
/// reported at once; with no include patterns that is the whole backlog. Callers that
/// want "only new from now on" can poll once and discard the result.
#[derive(Debug, Clone)]
pub struct FeedState {
    pub url: String,
    pub include: Vec<String>,
    pub exclude: Vec<String>,
    pub dir: Option<PathBuf>,
    seen: VecDeque<String>,
    seen_set: HashSet<String>,
}

impl FeedState {
    pub fn new(url: impl Into<String>) -> Self {
        Self::with_seen(url, std::iter::empty::<String>())
    }

    pub fn with_seen(url: impl Into<String>, seen: impl IntoIterator<Item = String>) -> Self {
        let mut state = Self {
            url: url.into(),
            include: Vec::new(),
            exclude: Vec::new(),
            dir: None,
            seen: VecDeque::new(),
            seen_set: HashSet::new(),
        };
        for key in seen {
            state.remember(key);
        }
        state
    }

    /// Oldest first, so feeding the result back into [`FeedState::with_seen`] keeps eviction order.
    pub fn seen(&self) -> impl Iterator<Item = &str> {
        self.seen.iter().map(String::as_str)
    }

    fn remember(&mut self, key: String) {
        if !self.seen_set.insert(key.clone()) {
            return;
        }
        self.seen.push_back(key);
        while self.seen.len() > SEEN_CAP {
            if let Some(old) = self.seen.pop_front() {
                self.seen_set.remove(&old);
            }
        }
    }

    fn accepts(&self, title: &str) -> bool {
        let title = title.to_lowercase();
        let hit = |p: &String| {
            let p = p.trim();
            !p.is_empty() && title.contains(&p.to_lowercase())
        };
        let wanted = !self.include.iter().any(|p| !p.trim().is_empty())
            || self.include.iter().any(hit);
        wanted && !self.exclude.iter().any(hit)
    }

    /// Returns `(title, source)` for items that pass the filters and were not reported
    /// before, and marks them seen. Items that do not match are left unseen, so editing
    /// the filters later can still pick them up while they remain in the feed.
    pub fn new_matches(&mut self, items: &[Item]) -> Vec<(String, String)> {
        let mut out = Vec::new();
        for item in items {
            let Some(source) = item.torrent.as_deref().filter(|s| !s.is_empty()) else {
                continue;
            };
            let key = item.guid.as_deref().or(item.link.as_deref()).unwrap_or(source);
            if self.seen_set.contains(key) || !self.accepts(&item.title) {
                continue;
            }
            self.remember(key.to_owned());
            out.push((item.title.clone(), source.to_owned()));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    const RSS: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!-- a comment -->
<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">
<channel>
  <title>Example &amp; Friends</title>
  <image><title>logo</title></image>
  <item>
    <title><![CDATA[Ubuntu 24.04 [amd64] & more]]></title>
    <link>https://example.com/post/1</link>
    <guid isPermaLink="false">id-1</guid>
    <pubDate>Mon, 01 Jan 2024 00:00:00 +0000</pubDate>
    <enclosure url="https://example.com/dl/1.torrent?a=1&amp;b=2" length="123" type="application/x-bittorrent"/>
  </item>
  <item>
    <title>Caf&#233; &#x41; &lt;b&gt; &quot;q&quot; &apos;s&apos;</title>
    <link>https://example.com/files/two.torrent</link>
    <guid>id-2</guid>
    <enclosure url="https://example.com/cover.jpg" type="image/jpeg"/>
  </item>
  <item>
    <title>Plain</title>
    <link>https://example.com/page3</link>
  </item>
</channel>
</rss>"#;

    #[test]
    fn rss_items() {
        let f = parse(RSS).unwrap();
        assert_eq!(f.title.as_deref(), Some("Example & Friends"));
        assert_eq!(f.items.len(), 3);
        let a = &f.items[0];
        assert_eq!(a.title, "Ubuntu 24.04 [amd64] & more");
        assert_eq!(a.guid.as_deref(), Some("id-1"));
        assert_eq!(a.published.as_deref(), Some("Mon, 01 Jan 2024 00:00:00 +0000"));
        assert_eq!(a.torrent.as_deref(), Some("https://example.com/dl/1.torrent?a=1&b=2"));
        let b = &f.items[1];
        assert_eq!(b.title, "Café A <b> \"q\" 's'");
        assert_eq!(b.torrent.as_deref(), Some("https://example.com/files/two.torrent"));
        assert_eq!(f.items[2].torrent.as_deref(), Some("https://example.com/page3"));
    }

    #[test]
    fn atom_with_relative_links() {
        let xml = r#"<feed xmlns="http://www.w3.org/2005/Atom">
<title>Atom feed</title>
<entry>
  <title>One</title>
  <id>urn:uuid:1</id>
  <updated>2024-01-01T00:00:00Z</updated>
  <link rel="alternate" href="/posts/one"/>
  <link rel="enclosure" type="application/x-bittorrent" href="dl/one.torrent"/>
</entry>
<entry>
  <title>Two</title>
  <id>urn:uuid:2</id>
  <link href="/posts/two"/>
  <link rel="enclosure" href="/dl/two.torrent"/>
</entry>
<entry>
  <title>Three</title>
  <id>urn:uuid:3</id>
  <link href="/posts/three"/>
</entry>
</feed>"#;
        let f = parse_at(xml, "https://tracker.example/feeds/main.xml").unwrap();
        assert_eq!(f.title.as_deref(), Some("Atom feed"));
        assert_eq!(f.items.len(), 3);
        assert_eq!(f.items[0].link.as_deref(), Some("https://tracker.example/posts/one"));
        assert_eq!(
            f.items[0].torrent.as_deref(),
            Some("https://tracker.example/feeds/dl/one.torrent")
        );
        assert_eq!(f.items[0].published.as_deref(), Some("2024-01-01T00:00:00Z"));
        assert_eq!(f.items[1].torrent.as_deref(), Some("https://tracker.example/dl/two.torrent"));
        assert_eq!(f.items[2].torrent.as_deref(), Some("https://tracker.example/posts/three"));
        assert_eq!(f.items[2].guid.as_deref(), Some("urn:uuid:3"));
    }

    #[test]
    fn namespaced_magnet_and_magnet_links() {
        let xml = r#"<rss xmlns:torrent="http://xmlns.ezrss.it/0.1/"><channel>
<item><title>A</title><link>https://t.example/a</link>
<torrent:magnetURI><![CDATA[magnet:?xt=urn:btih:aaaa&dn=A]]></torrent:magnetURI></item>
<item><title>B</title><link>magnet:?xt=urn:btih:bbbb&amp;dn=B</link></item>
<item><title>C</title><link>https://t.example/c</link><guid>magnet:?xt=urn:btih:cccc</guid></item>
</channel></rss>"#;
        let f = parse_at(xml, "https://t.example/rss").unwrap();
        assert_eq!(f.items[0].torrent.as_deref(), Some("magnet:?xt=urn:btih:aaaa&dn=A"));
        assert_eq!(f.items[1].torrent.as_deref(), Some("magnet:?xt=urn:btih:bbbb&dn=B"));
        assert_eq!(f.items[2].torrent.as_deref(), Some("magnet:?xt=urn:btih:cccc"));
    }

    #[test]
    fn malformed_and_truncated() {
        let cut = &RSS[..RSS.find("<item>").unwrap() + RSS[RSS.find("<item>").unwrap()..].find("</item>").unwrap() + 7 + 30];
        let f = parse(cut).unwrap();
        assert_eq!(f.items.len(), 1);

        let f = parse("<rss><channel><item><title>x</title><link>http://a/b").unwrap();
        assert!(f.items.is_empty());

        assert!(parse("").is_err());
        assert!(parse("<html><body>nope</body></html>").is_err());
        assert!(parse("<<<>>>&&&;;; <a b=\"c").is_err());
        let _ = parse("<rss><channel><item><title>&#99999999999;&#xZZ;&;&amp</title></item>");
        let _ = parse("é<rss attr='unterminated><item>");
    }

    #[test]
    fn huge_input_is_capped() {
        let one = "<item><title>t</title><link>http://a/b.torrent</link></item>\n";
        let n = 3 * 1024 * 1024 / one.len();
        let xml = format!("<rss><channel>{}</channel></rss>", one.repeat(n));
        let f = parse(&xml).unwrap();
        assert!(!f.items.is_empty() && f.items.len() <= MAX_ITEMS);
        assert!(f.items.len() < n);

        let xml = format!("<rss><channel><item><title>{}</title></item>", "é".repeat(2_000_000));
        assert!(parse(&xml).is_ok());
    }

    fn item(title: &str, guid: &str, src: &str) -> Item {
        Item {
            title: title.into(),
            guid: Some(guid.into()),
            torrent: Some(src.into()),
            ..Item::default()
        }
    }

    #[test]
    fn filters_and_dedup() {
        let items = vec![
            item("Ubuntu 24.04 amd64", "1", "http://a/1.torrent"),
            item("Ubuntu 24.04 arm64", "2", "http://a/2.torrent"),
            item("Debian 12", "3", "http://a/3.torrent"),
            Item { title: "No source".into(), guid: Some("4".into()), ..Item::default() },
        ];
        let mut f = FeedState::new("http://feed");
        f.include = vec!["UBUNTU".into(), "  ".into()];
        f.exclude = vec!["Arm64".into()];
        let got = f.new_matches(&items);
        assert_eq!(got, vec![("Ubuntu 24.04 amd64".to_string(), "http://a/1.torrent".to_string())]);
        assert!(f.new_matches(&items).is_empty());

        f.exclude.clear();
        let got = f.new_matches(&items);
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].1, "http://a/2.torrent");

        let mut all = FeedState::new("http://feed");
        assert_eq!(all.new_matches(&items).len(), 3);
    }

    #[test]
    fn dedup_key_falls_back_to_link_then_source() {
        let a = Item { title: "a".into(), link: Some("http://l".into()), torrent: Some("http://x".into()), ..Item::default() };
        let b = Item { title: "b".into(), torrent: Some("http://y".into()), ..Item::default() };
        let mut f = FeedState::new("u");
        assert_eq!(f.new_matches(&[a.clone(), a.clone(), b.clone()]).len(), 2);
        assert!(f.new_matches(&[a, b]).is_empty());
        let keys: Vec<_> = f.seen().collect();
        assert_eq!(keys, ["http://l", "http://y"]);
    }

    #[test]
    fn seen_cap_evicts_oldest_and_round_trips() {
        let mut f = FeedState::new("u");
        let items: Vec<_> = (0..SEEN_CAP + 5).map(|i| item("t", &i.to_string(), "http://s")).collect();
        assert_eq!(f.new_matches(&items).len(), SEEN_CAP + 5);
        assert_eq!(f.seen().count(), SEEN_CAP);
        assert_eq!(f.seen().next(), Some("5"));
        assert_eq!(f.new_matches(&items[..5]).len(), 5);
        assert_eq!(f.seen().count(), SEEN_CAP);

        let g = FeedState::with_seen("u", f.seen().map(str::to_owned));
        assert_eq!(g.seen().collect::<Vec<_>>(), f.seen().collect::<Vec<_>>());
    }

    async fn serve(listener: TcpListener, feed: &'static str) {
        loop {
            let Ok((mut s, _)) = listener.accept().await else { return };
            tokio::spawn(async move {
                let mut req = Vec::new();
                let mut b = [0u8; 1024];
                while !req.windows(4).any(|w| w == b"\r\n\r\n") {
                    match s.read(&mut b).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => req.extend_from_slice(&b[..n]),
                    }
                }
                let line = String::from_utf8_lossy(&req);
                let path = line.split_whitespace().nth(1).unwrap_or("").to_owned();
                let resp = match path.as_str() {
                    "/old" => "HTTP/1.1 302 Found\r\nLocation: /feeds/new.xml\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_owned(),
                    "/feeds/new.xml" => format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/rss+xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{feed}",
                        feed.len()
                    ),
                    "/big" => {
                        let head = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n";
                        let _ = s.write_all(head.as_bytes()).await;
                        let chunk = vec![b'a'; 64 * 1024];
                        for _ in 0..64 {
                            if s.write_all(format!("{:x}\r\n", chunk.len()).as_bytes()).await.is_err()
                                || s.write_all(&chunk).await.is_err()
                                || s.write_all(b"\r\n").await.is_err()
                            {
                                return;
                            }
                        }
                        return;
                    }
                    _ => "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_owned(),
                };
                let _ = s.write_all(resp.as_bytes()).await;
            });
        }
    }

    #[tokio::test]
    async fn fetch_follows_redirect_and_resolves_links() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(serve(listener, RSS_REL));
        let items = fetch(&format!("http://127.0.0.1:{port}/old"), true).await.unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].title, "Rel");
        assert_eq!(
            items[0].torrent.as_deref(),
            Some(format!("http://127.0.0.1:{port}/dl/r.torrent").as_str())
        );
        assert!(fetch(&format!("http://127.0.0.1:{port}/missing"), true).await.is_err());
        assert!(fetch(&format!("http://127.0.0.1:{port}/big"), true).await.is_err());
        assert!(fetch("ftp://x/", true).await.is_err());
    }

    const RSS_REL: &str = "<rss><channel><item><title>Rel</title><link>/dl/r.torrent</link></item></channel></rss>";

    #[test]
    fn is_magnet_survives_multibyte() {
        assert!(!is_magnet("abcdef\u{e9}"));
        assert!(is_magnet("MAGNET:?xt=x"));
        let feed = "<rss><channel><item><title>t</title><link>abcdef\u{e9}</link></item></channel></rss>";
        let _ = parse_inner(feed, None);
    }
}
