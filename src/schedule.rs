//! Bandwidth scheduler: a 7x24 grid assigning a [`Slot`] to every hour of the week.
//!
//! Local time is derived from `SystemTime` plus [`Schedule::utc_offset_minutes`], which the
//! UI/session fills in (see [`system_utc_offset_minutes`] for a best-effort default).

use std::fmt;
use std::process::Command;
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum Slot {
    #[default]
    Normal,
    Limited,
    SeedOnly,
    Off,
}

impl Slot {
    fn to_char(self) -> char {
        match self {
            Slot::Normal => 'N',
            Slot::Limited => 'L',
            Slot::SeedOnly => 'S',
            Slot::Off => 'O',
        }
    }

    fn from_char(c: char) -> Option<Slot> {
        match c.to_ascii_uppercase() {
            'N' => Some(Slot::Normal),
            'L' => Some(Slot::Limited),
            'S' => Some(Slot::SeedOnly),
            'O' => Some(Slot::Off),
            _ => None,
        }
    }

    fn from_word(w: &str) -> Option<Slot> {
        match w {
            "normal" | "full" => Some(Slot::Normal),
            "limited" | "limit" => Some(Slot::Limited),
            "seedonly" | "seed" => Some(Slot::SeedOnly),
            "off" => Some(Slot::Off),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScheduleError(pub String);

impl fmt::Display for ScheduleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ScheduleError {}

fn err<T>(msg: impl Into<String>) -> Result<T, ScheduleError> {
    Err(ScheduleError(msg.into()))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Schedule {
    pub enabled: bool,
    pub grid: [[Slot; 24]; 7],
    /// Limits used in `Limited` slots, bytes/s; passed through as-is (0 keeps the caller's "unlimited" meaning).
    pub limited_down: u64,
    pub limited_up: u64,
    /// Minutes east of UTC; filled by the UI/session, e.g. from [`system_utc_offset_minutes`].
    pub utc_offset_minutes: i32,
}

impl Default for Schedule {
    fn default() -> Self {
        Schedule {
            enabled: false,
            grid: [[Slot::Normal; 24]; 7],
            limited_down: 0,
            limited_up: 0,
            utc_offset_minutes: 0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Effective {
    pub down: u64,
    pub up: u64,
    pub downloads_paused: bool,
    pub uploads_paused: bool,
}

const DAYS: [&str; 7] = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"];

impl Schedule {
    fn weekday_hour(&self, unix_secs: u64) -> (usize, usize) {
        let local = unix_secs as i64 + self.utc_offset_minutes as i64 * 60;
        let days = local.div_euclid(86_400);
        let weekday = (days + 3).rem_euclid(7) as usize;
        let hour = (local.rem_euclid(86_400) / 3600) as usize;
        (weekday, hour)
    }

    pub fn slot_at(&self, unix_secs: u64) -> Slot {
        if !self.enabled {
            return Slot::Normal;
        }
        let (d, h) = self.weekday_hour(unix_secs);
        self.grid[d][h]
    }

    pub fn effective_limits(&self, now: u64, normal_down: u64, normal_up: u64) -> Effective {
        let (mut down, mut up, mut dp, mut up_p) = (normal_down, normal_up, false, false);
        match self.slot_at(now) {
            Slot::Normal => {}
            Slot::Limited => {
                down = self.limited_down;
                up = self.limited_up;
            }
            Slot::SeedOnly => dp = true,
            Slot::Off => {
                dp = true;
                up_p = true;
            }
        }
        Effective { down, up, downloads_paused: dp, uploads_paused: up_p }
    }

    /// Unix time of the next hour boundary (within a week) whose slot differs from the current one.
    pub fn next_change(&self, now: u64) -> Option<u64> {
        let current = self.slot_at(now);
        let local = now as i64 + self.utc_offset_minutes as i64 * 60;
        let mut t = now + (3600 - local.rem_euclid(3600) as u64);
        for _ in 0..168 {
            if self.slot_at(t) != current {
                return Some(t);
            }
            t += 3600;
        }
        None
    }

    pub fn to_string_grid(&self) -> String {
        self.grid.iter().flatten().map(|s| s.to_char()).collect()
    }

    pub fn parse_grid(s: &str) -> Result<[[Slot; 24]; 7], ScheduleError> {
        let n = s.chars().count();
        if n != 168 {
            return err(format!("grid must be 168 characters, got {n}"));
        }
        let mut grid = [[Slot::Normal; 24]; 7];
        for (i, c) in s.chars().enumerate() {
            match Slot::from_char(c) {
                Some(slot) => grid[i / 24][i % 24] = slot,
                None => return err(format!("invalid grid character '{c}' at {i} (expected N/L/S/O)")),
            }
        }
        Ok(grid)
    }

    /// Applies a rule like `weekdays 09-18 limited`, `sat,sun 00-24 normal` or `mon-fri 22-06 off`.
    /// Hours are `start-end` with `end` exclusive (24 allowed); `start > end` runs past midnight into
    /// the following day. Days: names (`mon`..`sun`), ranges (`fri-mon` wraps), lists, `weekdays`,
    /// `weekend`, `all`/`daily`.
    pub fn apply_rule(&mut self, rule: &str) -> Result<(), ScheduleError> {
        let parts: Vec<String> = rule.split_whitespace().map(|p| p.to_ascii_lowercase()).collect();
        let [days, hours, slot] = parts.as_slice() else {
            return err("rule must be '<days> <HH-HH> <normal|limited|seedonly|off>'");
        };
        let days = parse_days(days)?;
        let (start, end) = parse_hours(hours)?;
        let Some(slot) = Slot::from_word(slot) else {
            return err(format!("unknown slot '{slot}' (expected normal, limited, seedonly or off)"));
        };
        for d in days {
            if start < end {
                self.grid[d][start..end].fill(slot);
            } else {
                self.grid[d][start..].fill(slot);
                self.grid[(d + 1) % 7][..end].fill(slot);
            }
        }
        Ok(())
    }
}

fn day_index(s: &str) -> Result<usize, ScheduleError> {
    const FULL: [&str; 7] = ["monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"];
    match (0..7).find(|&i| s == DAYS[i] || s == FULL[i]) {
        Some(i) => Ok(i),
        None => err(format!("unknown day '{s}'")),
    }
}

fn parse_days(s: &str) -> Result<Vec<usize>, ScheduleError> {
    match s {
        "weekdays" => return Ok((0..5).collect()),
        "weekend" | "weekends" => return Ok(vec![5, 6]),
        "all" | "daily" | "everyday" => return Ok((0..7).collect()),
        _ => {}
    }
    let mut out = Vec::new();
    for item in s.split(',') {
        match item.split_once('-') {
            Some((a, b)) => {
                let (a, b) = (day_index(a)?, day_index(b)?);
                let mut d = a;
                loop {
                    out.push(d);
                    if d == b {
                        break;
                    }
                    d = (d + 1) % 7;
                }
            }
            None => out.push(day_index(item)?),
        }
    }
    Ok(out)
}

fn parse_hours(s: &str) -> Result<(usize, usize), ScheduleError> {
    let Some((a, b)) = s.split_once('-') else {
        return err(format!("hours '{s}' must look like 09-18"));
    };
    let num = |x: &str| {
        x.parse::<usize>()
            .ok()
            .filter(|n| *n <= 24)
            .ok_or_else(|| ScheduleError(format!("invalid hour '{x}' (0-24)")))
    };
    let (start, end) = (num(a)?, num(b)?);
    if start == 24 {
        return err("start hour must be 0-23");
    }
    if start == end {
        return err(format!("empty hour range '{s}' (use 00-24 for the whole day)"));
    }
    Ok((start, end))
}

/// Parses `date +%z` output such as `+0700` or `-0130` into minutes east of UTC.
pub fn parse_date_z(s: &str) -> Option<i32> {
    let s = s.trim();
    let sign = match s.as_bytes().first()? {
        b'+' => 1,
        b'-' => -1,
        _ => return None,
    };
    let digits = &s[1..];
    if digits.len() != 4 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let h: i32 = digits[..2].parse().ok()?;
    let m: i32 = digits[2..].parse().ok()?;
    if m > 59 || h > 23 {
        return None;
    }
    Some(sign * (h * 60 + m))
}

/// Best-effort local UTC offset via `date +%z` (unix only), computed once. `None` elsewhere or on failure.
pub fn system_utc_offset_minutes() -> Option<i32> {
    static OFFSET: OnceLock<Option<i32>> = OnceLock::new();
    *OFFSET.get_or_init(|| {
        if !cfg!(unix) {
            return None;
        }
        let out = Command::new("date").arg("+%z").output().ok()?;
        if !out.status.success() {
            return None;
        }
        parse_date_z(&String::from_utf8_lossy(&out.stdout))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const MON_0000: u64 = 4 * 86_400; // 1970-01-05 00:00 UTC, a Monday

    fn sched(offset: i32) -> Schedule {
        let mut s = Schedule { enabled: true, utc_offset_minutes: offset, ..Default::default() };
        for d in 0..7 {
            for h in 0..24 {
                s.grid[d][h] = [Slot::Normal, Slot::Limited, Slot::SeedOnly, Slot::Off][(d * 24 + h) % 4];
            }
        }
        s
    }

    #[test]
    fn weekday_hour_math() {
        let s = Schedule::default();
        assert_eq!(s.weekday_hour(0), (3, 0));
        assert_eq!(s.weekday_hour(MON_0000), (0, 0));
        assert_eq!(s.weekday_hour(MON_0000 + 3600 * 5 + 59), (0, 5));
        assert_eq!(s.weekday_hour(MON_0000 - 1), (6, 23));
        let east = Schedule { utc_offset_minutes: 420, ..Default::default() };
        assert_eq!(east.weekday_hour(MON_0000 - 3600 * 8), (6, 23));
        assert_eq!(east.weekday_hour(MON_0000 - 3600 * 7), (0, 0));
        let west = Schedule { utc_offset_minutes: -300, ..Default::default() };
        assert_eq!(west.weekday_hour(MON_0000), (6, 19));
        assert_eq!(west.weekday_hour(MON_0000 + 5 * 3600), (0, 0));
        let half = Schedule { utc_offset_minutes: 330, ..Default::default() };
        assert_eq!(half.weekday_hour(MON_0000 + 1800), (0, 6));
        let neg_half = Schedule { utc_offset_minutes: -210, ..Default::default() };
        assert_eq!(neg_half.weekday_hour(MON_0000 + 3 * 3600 + 1800), (0, 0));
        assert_eq!(neg_half.weekday_hour(MON_0000 + 3 * 3600 + 1799), (6, 23));
    }

    #[test]
    fn slot_and_disabled() {
        let mut s = sched(0);
        assert_eq!(s.slot_at(MON_0000), Slot::Normal);
        assert_eq!(s.slot_at(MON_0000 + 3600), Slot::Limited);
        assert_eq!(s.slot_at(MON_0000 + 2 * 3600), Slot::SeedOnly);
        assert_eq!(s.slot_at(MON_0000 + 3 * 3600), Slot::Off);
        s.enabled = false;
        assert_eq!(s.slot_at(MON_0000 + 3 * 3600), Slot::Normal);
    }

    #[test]
    fn effective() {
        let mut s = sched(0);
        s.limited_down = 10;
        s.limited_up = 5;
        let e = |t| s.effective_limits(t, 100, 50);
        assert_eq!(e(MON_0000), Effective { down: 100, up: 50, downloads_paused: false, uploads_paused: false });
        assert_eq!(e(MON_0000 + 3600), Effective { down: 10, up: 5, downloads_paused: false, uploads_paused: false });
        assert_eq!(e(MON_0000 + 7200), Effective { down: 100, up: 50, downloads_paused: true, uploads_paused: false });
        assert_eq!(e(MON_0000 + 10800), Effective { down: 100, up: 50, downloads_paused: true, uploads_paused: true });
        let mut off = s.clone();
        off.enabled = false;
        assert_eq!(off.effective_limits(MON_0000 + 10800, 100, 50).uploads_paused, false);
    }

    #[test]
    fn next_change_cases() {
        let mut s = sched(0);
        assert_eq!(s.next_change(MON_0000 + 100), Some(MON_0000 + 3600));
        s.grid = [[Slot::Normal; 24]; 7];
        assert_eq!(s.next_change(MON_0000), None);
        s.grid[6][23] = Slot::Off;
        assert_eq!(s.next_change(MON_0000), Some(MON_0000 + 6 * 86_400 + 23 * 3600));
        assert_eq!(s.next_change(MON_0000 + 6 * 86_400 + 23 * 3600 + 5), Some(MON_0000 + 7 * 86_400));
        s.grid[0][1] = Slot::Off;
        s.utc_offset_minutes = 30;
        assert_eq!(s.next_change(MON_0000 + 10), Some(MON_0000 + 1800));
        assert_eq!(Schedule::default().next_change(MON_0000), None);
    }

    #[test]
    fn grid_round_trip_and_validation() {
        let s = sched(0);
        let text = s.to_string_grid();
        assert_eq!(text.len(), 168);
        assert_eq!(Schedule::parse_grid(&text).unwrap(), s.grid);
        assert_eq!(Schedule::parse_grid(&text.to_lowercase()).unwrap(), s.grid);
        assert!(Schedule::parse_grid("NNN").is_err());
        let bad = format!("{}X", "N".repeat(167));
        assert!(Schedule::parse_grid(&bad).unwrap_err().0.contains("'X'"));
    }

    #[test]
    fn rules() {
        let mut s = Schedule::default();
        s.apply_rule("weekdays 09-18 limited").unwrap();
        assert_eq!(s.grid[0][9], Slot::Limited);
        assert_eq!(s.grid[4][17], Slot::Limited);
        assert_eq!(s.grid[4][18], Slot::Normal);
        assert_eq!(s.grid[5][9], Slot::Normal);
        s.apply_rule("Sat,Sun 00-24 off").unwrap();
        assert!(s.grid[5].iter().chain(&s.grid[6]).all(|x| *x == Slot::Off));
        s.apply_rule("mon-wed,fri 01-03 seed").unwrap();
        assert_eq!(s.grid[2][2], Slot::SeedOnly);
        assert_eq!(s.grid[3][2], Slot::Normal);
        assert_eq!(s.grid[4][1], Slot::SeedOnly);
        let mut w = Schedule::default();
        w.apply_rule("sun 22-06 off").unwrap();
        assert_eq!(w.grid[6][21], Slot::Normal);
        assert_eq!(w.grid[6][23], Slot::Off);
        assert_eq!(w.grid[0][5], Slot::Off);
        assert_eq!(w.grid[0][6], Slot::Normal);
        w.apply_rule("fri-mon 00-01 limited").unwrap();
        assert_eq!(w.grid[6][0], Slot::Limited);
        assert_eq!(w.grid[0][0], Slot::Limited);
        assert_eq!(w.grid[2][0], Slot::Normal);
        w.apply_rule("monday 00-24 normal").unwrap();
        assert_eq!(w.grid[0][5], Slot::Normal);
    }

    #[test]
    fn rule_errors() {
        let mut s = Schedule::default();
        for bad in [
            "", "mon 09-18", "funday 09-18 off", "mon 9 off", "mon 09-25 off", "mon 24-02 off",
            "mon 05-05 off", "mon 09-18 slow", "mon 0a-18 off", "mon 09-18 off extra",
        ] {
            assert!(s.apply_rule(bad).is_err(), "{bad}");
        }
        assert_eq!(s, Schedule::default());
    }

    #[test]
    fn date_z() {
        assert_eq!(parse_date_z("+0700\n"), Some(420));
        assert_eq!(parse_date_z("-0130"), Some(-90));
        assert_eq!(parse_date_z("+0000"), Some(0));
        assert_eq!(parse_date_z("+0545"), Some(345));
        for bad in ["", "0700", "+07", "+07:00", "+0760", "abcd", "+2500"] {
            assert_eq!(parse_date_z(bad), None, "{bad}");
        }
    }
}
