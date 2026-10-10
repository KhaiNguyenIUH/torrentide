use std::io::Read;
use std::net::{IpAddr, Ipv6Addr};
use std::path::Path;

use anyhow::{bail, Context, Result};

const MAX_FILE_SIZE: u64 = 64 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LoadStats {
    pub ranges: usize,
    pub skipped_lines: usize,
}

#[derive(Debug, Clone, Default)]
pub struct BlockList {
    v4: Vec<(u32, u32)>,
    v6: Vec<(u128, u128)>,
}

#[derive(Clone, Copy)]
enum Addr {
    V4(u32),
    V6(u128),
}

enum Parsed {
    Range(Addr, Addr),
    Allowed,
}

impl BlockList {
    pub fn len(&self) -> usize {
        self.v4.len() + self.v6.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(a) => find(&self.v4, u32::from(a)),
            IpAddr::V6(a) => match a.to_ipv4_mapped() {
                Some(m) => find(&self.v4, u32::from(m)),
                None => find(&self.v6, u128::from(a)),
            },
        }
    }

    pub fn load(path: impl AsRef<Path>) -> Result<(BlockList, LoadStats)> {
        let path = path.as_ref();
        let ctx = || format!("reading {}", path.display());
        if !std::fs::metadata(path).with_context(ctx)?.is_file() {
            bail!("block list {} is not a regular file", path.display());
        }
        let file = std::fs::File::open(path).with_context(ctx)?;
        if !file.metadata().with_context(ctx)?.is_file() {
            bail!("block list {} is not a regular file", path.display());
        }
        let mut bytes = Vec::new();
        file.take(MAX_FILE_SIZE + 1).read_to_end(&mut bytes).with_context(ctx)?;
        if bytes.len() as u64 > MAX_FILE_SIZE {
            bail!("block list {} is over the {MAX_FILE_SIZE} byte limit", path.display());
        }
        if bytes.starts_with(&[0x1f, 0x8b]) {
            bail!("block list {} is gzip-compressed; decompress it first", path.display());
        }
        Ok(Self::parse(&String::from_utf8_lossy(&bytes)))
    }

    pub fn parse(text: &str) -> (BlockList, LoadStats) {
        let mut v4 = Vec::new();
        let mut v6 = Vec::new();
        let mut skipped_lines = 0;
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
                continue;
            }
            match parse_line(line) {
                Some(Parsed::Range(Addr::V4(a), Addr::V4(b))) => v4.push((a, b)),
                Some(Parsed::Range(Addr::V6(a), Addr::V6(b))) => v6.push((a, b)),
                Some(Parsed::Range(..)) => skipped_lines += 1,
                Some(Parsed::Allowed) => {}
                None => skipped_lines += 1,
            }
        }
        let list = BlockList { v4: merge(v4), v6: merge(v6) };
        let ranges = list.len();
        (list, LoadStats { ranges, skipped_lines })
    }
}

fn find<T: Copy + Ord>(ranges: &[(T, T)], x: T) -> bool {
    let i = ranges.partition_point(|&(start, _)| start <= x);
    i > 0 && ranges[i - 1].1 >= x
}

trait Bound: Copy + Ord {
    fn succ(self) -> Self;
}

impl Bound for u32 {
    fn succ(self) -> Self {
        self.saturating_add(1)
    }
}

impl Bound for u128 {
    fn succ(self) -> Self {
        self.saturating_add(1)
    }
}

fn merge<T: Bound>(mut ranges: Vec<(T, T)>) -> Vec<(T, T)> {
    ranges.sort_unstable();
    let mut out: Vec<(T, T)> = Vec::with_capacity(ranges.len());
    for (start, end) in ranges {
        match out.last_mut() {
            Some(last) if start <= last.1.succ() => last.1 = last.1.max(end),
            _ => out.push((start, end)),
        }
    }
    out
}

fn parse_line(line: &str) -> Option<Parsed> {
    if let Some(p) = parse_range(line) {
        return Some(p);
    }
    if line.contains(',') {
        let mut fields = line.splitn(3, ',');
        if let Some(Parsed::Range(a, b)) = fields.next().and_then(parse_range) {
            return match fields.next().map(str::trim) {
                Some(level) if !level.is_empty() => match level.parse::<u32>() {
                    Ok(l) if l > 127 => Some(Parsed::Allowed),
                    Ok(_) => Some(Parsed::Range(a, b)),
                    Err(_) => None,
                },
                _ => Some(Parsed::Range(a, b)),
            };
        }
    }
    line.match_indices(':')
        .find_map(|(i, _)| parse_range(&line[i + 1..]))
}

fn parse_range(s: &str) -> Option<Parsed> {
    let s = s.trim();
    if let Some((ip, prefix)) = s.split_once('/') {
        return parse_cidr(ip.trim(), prefix.trim()).map(|(a, b)| Parsed::Range(a, b));
    }
    match s.split_once('-') {
        Some((a, b)) => match (parse_addr(a.trim())?, parse_addr(b.trim())?) {
            (Addr::V4(a), Addr::V4(b)) => Some(Parsed::Range(Addr::V4(a.min(b)), Addr::V4(a.max(b)))),
            (Addr::V6(a), Addr::V6(b)) => Some(Parsed::Range(Addr::V6(a.min(b)), Addr::V6(a.max(b)))),
            _ => None,
        },
        None => parse_addr(s).map(|a| Parsed::Range(a, a)),
    }
}

fn parse_cidr(ip: &str, prefix: &str) -> Option<(Addr, Addr)> {
    let prefix: u32 = prefix.parse().ok()?;
    match parse_addr(ip)? {
        Addr::V4(a) if prefix <= 32 => {
            let host = u32::MAX.checked_shr(prefix).unwrap_or(0);
            Some((Addr::V4(a & !host), Addr::V4(a | host)))
        }
        Addr::V6(a) if prefix <= 128 => {
            let host = u128::MAX.checked_shr(prefix).unwrap_or(0);
            Some((Addr::V6(a & !host), Addr::V6(a | host)))
        }
        _ => None,
    }
}

fn parse_addr(s: &str) -> Option<Addr> {
    if s.contains(':') {
        return s.parse::<Ipv6Addr>().ok().map(|a| Addr::V6(u128::from(a)));
    }
    let mut value = 0u32;
    let mut parts = 0;
    for part in s.split('.') {
        if part.is_empty() || part.len() > 3 || !part.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let octet: u32 = part.parse().ok()?;
        if octet > 255 {
            return None;
        }
        value = (value << 8) | octet;
        parts += 1;
        if parts > 4 {
            return None;
        }
    }
    (parts == 4).then_some(Addr::V4(value))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{Rng, SeedableRng};
    use std::net::Ipv4Addr;

    fn v4(s: &str) -> IpAddr {
        IpAddr::V4(s.parse().unwrap())
    }

    fn v6(s: &str) -> IpAddr {
        IpAddr::V6(s.parse().unwrap())
    }

    #[test]
    fn ipfilter_dat() {
        let (l, s) = BlockList::parse("001.002.003.000 - 001.002.003.255 , 000 , Evil Corp\n");
        assert_eq!((s.ranges, s.skipped_lines), (1, 0));
        assert!(l.contains(v4("1.2.3.0")) && l.contains(v4("1.2.3.255")));
        assert!(!l.contains(v4("1.2.2.255")) && !l.contains(v4("1.2.4.0")));
    }

    #[test]
    fn ipfilter_allowed_level_skipped() {
        let (l, s) = BlockList::parse("1.0.0.0 - 1.0.0.255 , 200 , ok\n2.0.0.0 - 2.0.0.255 , 127 , bad\n3.0.0.0-3.0.0.255\n");
        assert_eq!((s.ranges, s.skipped_lines), (2, 0));
        assert!(!l.contains(v4("1.0.0.5")));
        assert!(l.contains(v4("2.0.0.5")) && l.contains(v4("3.0.0.5")));
    }

    #[test]
    fn ipfilter_bad_level_counts_skipped() {
        let (l, s) = BlockList::parse("1.0.0.0 - 1.0.0.255 , abc , x\n");
        assert_eq!((l.len(), s.skipped_lines), (0, 1));
    }

    #[test]
    fn peerguardian() {
        let (l, s) = BlockList::parse("Some Org: Inc, LLC:5.6.7.0-5.6.7.255\nplain:9.9.9.9-9.9.9.9\nv6 org:a::1-a::ff\n");
        assert_eq!((s.ranges, s.skipped_lines), (3, 0));
        assert!(l.contains(v4("5.6.7.128")) && l.contains(v4("9.9.9.9")));
        assert!(l.contains(v6("a::80")) && !l.contains(v6("a::100")));
    }

    #[test]
    fn cidr_v4_v6() {
        let (l, s) = BlockList::parse("10.0.0.0/8\n1.2.3.0/24\n2001:db8::/32\n0.0.0.0/0\n");
        assert_eq!(s.skipped_lines, 0);
        assert_eq!(l.len(), 2);
        assert!(l.contains(v4("255.255.255.255")) && l.contains(v4("0.0.0.0")));
        assert!(l.contains(v6("2001:db8:ffff::1")) && !l.contains(v6("2001:db9::")));
    }

    #[test]
    fn cidr_unaligned_and_invalid() {
        let (l, s) = BlockList::parse("1.2.3.77/24\n1.2.3.4/33\n::/129\n1.2.3.4/x\n");
        assert_eq!(s.skipped_lines, 3);
        assert!(l.contains(v4("1.2.3.0")) && l.contains(v4("1.2.3.255")));
    }

    #[test]
    fn single_ips_and_v6_ranges() {
        let (l, s) = BlockList::parse("4.4.4.4\n::1\na::1 - a::ff\n");
        assert_eq!((s.ranges, s.skipped_lines), (3, 0));
        assert!(l.contains(v4("4.4.4.4")) && !l.contains(v4("4.4.4.5")));
        assert!(l.contains(v6("::1")) && l.contains(v6("a::1")) && l.contains(v6("a::ff")));
        assert!(!l.contains(v6("a::")) && !l.contains(v6("a::100")));
    }

    #[test]
    fn leading_zeros() {
        let (l, s) = BlockList::parse("001.002.003.004\n010.000.000.001\n");
        assert_eq!(s.skipped_lines, 0);
        assert!(l.contains(v4("1.2.3.4")) && l.contains(v4("10.0.0.1")));
    }

    #[test]
    fn comments_and_blanks() {
        let (l, s) = BlockList::parse("# c\n// c\n\n   \n1.1.1.1\n");
        assert_eq!((l.len(), s.skipped_lines), (1, 0));
    }

    #[test]
    fn malformed_counted() {
        let text = "garbage\n1.2.3\n1.2.3.4.5\n256.1.1.1\n1.2.3.4-\n1..2.3\n1.2.3.4 - a::1\n-\n,,\n1.1.1.1\n";
        let (l, s) = BlockList::parse(text);
        assert_eq!((l.len(), s.skipped_lines), (1, 9));
    }

    #[test]
    fn reversed_range_swapped() {
        let (l, _) = BlockList::parse("1.0.0.9 - 1.0.0.1\n");
        assert!(l.contains(v4("1.0.0.5")));
    }

    #[test]
    fn merging() {
        let (l, _) = BlockList::parse("1.0.0.0-1.0.0.10\n1.0.0.5-1.0.0.20\n1.0.0.21-1.0.0.30\n1.0.0.32-1.0.0.40\n1.0.0.0-1.0.0.2\n");
        assert_eq!(l.len(), 2);
        assert!(l.contains(v4("1.0.0.25")) && !l.contains(v4("1.0.0.31")) && l.contains(v4("1.0.0.32")));
    }

    #[test]
    fn merging_extremes_no_overflow() {
        let (l, _) = BlockList::parse("0.0.0.0-255.255.255.255\n255.255.255.0-255.255.255.255\n::/0\n");
        assert_eq!(l.len(), 2);
        assert!(l.contains(v4("255.255.255.255")) && l.contains(v6("ffff::1")));
    }

    #[test]
    fn boundaries() {
        let (l, _) = BlockList::parse("10.0.0.10-10.0.0.20\n10.0.0.30-10.0.0.40\n");
        for (ip, want) in [("10.0.0.9", false), ("10.0.0.10", true), ("10.0.0.20", true), ("10.0.0.21", false), ("10.0.0.29", false), ("10.0.0.40", true), ("10.0.0.41", false), ("0.0.0.0", false)] {
            assert_eq!(l.contains(v4(ip)), want, "{ip}");
        }
    }

    #[test]
    fn v4_mapped_v6_uses_v4_set() {
        let (l, _) = BlockList::parse("1.2.3.0/24\n");
        assert!(l.contains(v6("::ffff:1.2.3.4")));
        assert!(!l.contains(v6("::ffff:1.2.4.4")));
    }

    #[test]
    fn empty_list() {
        let (l, s) = BlockList::parse("");
        assert!(l.is_empty() && !l.contains(v4("1.1.1.1")) && !l.contains(v6("::1")));
        assert_eq!(s.skipped_lines, 0);
    }

    #[test]
    fn load_gzip_and_size_and_ok() {
        let dir = std::env::temp_dir().join(format!("torrust-bl-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let gz = dir.join("l.gz");
        std::fs::write(&gz, [0x1f, 0x8b, 8, 0, 0]).unwrap();
        let err = BlockList::load(&gz).unwrap_err().to_string();
        assert!(err.contains("gzip"), "{err}");
        let ok = dir.join("l.txt");
        std::fs::write(&ok, "1.2.3.4\nbad\n").unwrap();
        let (l, s) = BlockList::load(&ok).unwrap();
        assert_eq!((l.len(), s.skipped_lines), (1, 1));
        assert!(BlockList::load(dir.join("missing")).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn fifo_is_rejected_without_hanging() {
        let dir = std::env::temp_dir().join(format!("torrust-bl-fifo-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let fifo = dir.join("pipe");
        assert!(std::process::Command::new("mkfifo").arg(&fifo).status().unwrap().success());
        let (tx, rx) = std::sync::mpsc::channel();
        let p = fifo.clone();
        std::thread::spawn(move || {
            let _ = tx.send(BlockList::load(&p).map(|_| ()).unwrap_err().to_string());
        });
        let err = rx.recv_timeout(std::time::Duration::from_secs(5)).expect("load hung on a FIFO");
        assert!(err.contains("not a regular file"), "{err}");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn big_list_matches_naive() {
        let mut rng = rand::rngs::StdRng::seed_from_u64(7);
        let mut text = String::new();
        let mut naive: Vec<(u32, u32)> = Vec::new();
        for i in 0..200_000u32 {
            let start: u32 = rng.gen();
            let end = start.saturating_add(rng.gen_range(0..5000));
            let (a, b) = (Ipv4Addr::from(start), Ipv4Addr::from(end));
            match i % 3 {
                0 => text.push_str(&format!("{:03}.{:03}.{:03}.{:03} - {} , 000 , r{i}\n", a.octets()[0], a.octets()[1], a.octets()[2], a.octets()[3], b)),
                1 => text.push_str(&format!("r{i}:{a}-{b}\n")),
                _ => text.push_str(&format!("{a} - {b}\n")),
            }
            naive.push((start, end));
        }
        let t = std::time::Instant::now();
        let (l, s) = BlockList::parse(&text);
        assert!(t.elapsed() < std::time::Duration::from_secs(20), "{:?}", t.elapsed());
        assert_eq!(s.skipped_lines, 0);
        assert!(l.len() <= 200_000);
        let check = |x: u32| {
            let want = naive.iter().any(|&(a, b)| a <= x && x <= b);
            assert_eq!(l.contains(IpAddr::V4(Ipv4Addr::from(x))), want, "{x}");
        };
        for _ in 0..300 {
            check(rng.gen());
        }
        for k in 0..300 {
            let (a, b) = naive[k * 600];
            check(a);
            check(b);
            check(b.wrapping_add(1));
            check(a.wrapping_sub(1));
        }
    }

    #[test]
    fn cidr_host_prefix_edges() {
        let (l, s) = BlockList::parse("1.2.3.4/32\n::1/128\n10.0.0.0/31\n");
        assert_eq!(s.skipped_lines, 0);
        assert!(l.contains(v4("1.2.3.4")) && !l.contains(v4("1.2.3.5")) && !l.contains(v4("9.9.9.9")));
        assert!(l.contains(v6("::1")) && !l.contains(v6("::2")));
        assert!(l.contains(v4("10.0.0.0")) && l.contains(v4("10.0.0.1")) && !l.contains(v4("10.0.0.2")));
        let (l, _) = BlockList::parse("0.0.0.0/0\n");
        assert!(l.contains(v4("8.8.8.8")));
        let (l, _) = BlockList::parse("::/0\n");
        assert!(l.contains(v6("2001::1")));
    }
}
