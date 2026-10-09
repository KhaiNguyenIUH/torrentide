//! Token-bucket rate limiting shared by many connections.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::time::Instant;

struct Bucket {
    tokens: f64,
    last: Instant,
}

/// Token bucket shared by many connections. Rate 0 means unlimited.
///
/// Callers are charged immediately and may drive the bucket into debt; they
/// then sleep until the debt is repaid. That lets a block larger than one
/// second's worth of tokens through at tiny rates, and serialises concurrent
/// callers fairly.
pub struct RateLimiter {
    rate: AtomicU64,
    bucket: Mutex<Bucket>,
}

impl RateLimiter {
    pub fn new(bytes_per_sec: u64) -> Arc<Self> {
        Arc::new(RateLimiter {
            rate: AtomicU64::new(bytes_per_sec),
            bucket: Mutex::new(Bucket {
                tokens: 0.0,
                last: Instant::now(),
            }),
        })
    }

    pub fn set_rate(&self, bytes_per_sec: u64) {
        self.rate.store(bytes_per_sec, Ordering::Relaxed);
    }

    pub fn rate(&self) -> u64 {
        self.rate.load(Ordering::Relaxed)
    }

    pub async fn acquire(&self, bytes: usize) {
        let rate = self.rate();
        if rate == 0 {
            return;
        }
        let wait = {
            let mut b = self.bucket.lock().unwrap();
            let now = Instant::now();
            let refill = now.duration_since(b.last).as_secs_f64() * rate as f64;
            // Idle time banks at most one second's worth of burst.
            b.tokens = (b.tokens + refill).min(rate as f64) - bytes as f64;
            b.last = now;
            if b.tokens < 0.0 {
                Duration::from_secs_f64(-b.tokens / rate as f64)
            } else {
                Duration::ZERO
            }
        };
        if !wait.is_zero() {
            tokio::time::sleep(wait).await;
        }
    }
}

/// The limiters one connection must respect (global plus its torrent's).
#[derive(Clone, Default)]
pub struct Limits {
    pub down: Vec<Arc<RateLimiter>>,
    pub up: Vec<Arc<RateLimiter>>,
}

impl Limits {
    pub async fn acquire_down(&self, bytes: usize) {
        for l in &self.down {
            l.acquire(bytes).await;
        }
    }

    pub async fn acquire_up(&self, bytes: usize) {
        for l in &self.up {
            l.acquire(bytes).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn acquire_takes_bytes_over_rate_seconds() {
        let l = RateLimiter::new(1000);
        let start = Instant::now();
        for _ in 0..4 {
            l.acquire(500).await;
        }
        let e = start.elapsed().as_secs_f64();
        assert!((e - 2.0).abs() < 0.05, "elapsed {e}");
    }

    #[tokio::test(start_paused = true)]
    async fn block_larger_than_a_second_still_passes() {
        let l = RateLimiter::new(1000);
        let start = Instant::now();
        l.acquire(16 * 1024).await;
        assert!(start.elapsed().as_secs_f64() > 16.0);
    }

    #[tokio::test(start_paused = true)]
    async fn zero_rate_never_waits_and_set_rate_applies() {
        let l = RateLimiter::new(0);
        let start = Instant::now();
        l.acquire(1 << 30).await;
        assert_eq!(start.elapsed(), Duration::ZERO);

        l.set_rate(100);
        assert_eq!(l.rate(), 100);
        l.acquire(200).await;
        assert!((start.elapsed().as_secs_f64() - 2.0).abs() < 0.05);

        l.set_rate(0);
        let t = Instant::now();
        l.acquire(1 << 30).await;
        assert_eq!(t.elapsed(), Duration::ZERO);
    }
}
