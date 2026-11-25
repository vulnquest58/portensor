use std::sync::Mutex;
use std::time::Duration;

use tokio::time::Instant;

/// A global token bucket shared by every scan worker.
#[derive(Debug)]
pub struct RateLimiter {
    bucket: Option<Mutex<Bucket>>,
}

#[derive(Debug)]
struct Bucket {
    rate: f64,
    burst: f64,
    tokens: f64,
    last: Instant,
}

impl RateLimiter {
    pub fn new(rate: u64) -> Self {
        if rate == 0 {
            return Self { bucket: None };
        }

        let rate = rate as f64;
        let burst = (rate / 10.0).clamp(1.0, 1_000.0);
        Self {
            bucket: Some(Mutex::new(Bucket {
                rate,
                burst,
                tokens: burst,
                last: Instant::now(),
            })),
        }
    }

    pub fn is_unlimited(&self) -> bool {
        self.bucket.is_none()
    }

    pub fn set_rate(&self, rate: u64) {
        let Some(bucket) = &self.bucket else {
            return;
        };
        let mut bucket = bucket.lock().expect("rate limiter lock poisoned");
        bucket.refill();
        bucket.rate = rate as f64;
        bucket.burst = (rate as f64 / 10.0).clamp(1.0, 1_000.0);
        bucket.tokens = bucket.tokens.min(bucket.burst);
    }

    pub async fn acquire(&self) {
        let Some(bucket) = &self.bucket else {
            return;
        };

        loop {
            let wait = {
                let mut bucket = bucket.lock().expect("rate limiter lock poisoned");
                bucket.refill();
                if bucket.tokens >= 1.0 {
                    bucket.tokens -= 1.0;
                    return;
                }
                Duration::from_secs_f64((1.0 - bucket.tokens) / bucket.rate)
            };
            tokio::time::sleep(wait).await;
        }
    }

    /// Synchronous counterpart used by the blocking connect-only worker pool.
    pub fn acquire_blocking(&self) {
        let Some(bucket) = &self.bucket else {
            return;
        };

        loop {
            let wait = {
                let mut bucket = bucket.lock().expect("rate limiter lock poisoned");
                bucket.refill();
                if bucket.tokens >= 1.0 {
                    bucket.tokens -= 1.0;
                    return;
                }
                Duration::from_secs_f64((1.0 - bucket.tokens) / bucket.rate)
            };
            std::thread::sleep(wait);
        }
    }
}

impl Bucket {
    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.rate).min(self.burst);
        self.last = now;
    }
}

/// Target feedback observed by the adaptive rate controller.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TargetFeedback {
    /// A normal completion (`open`, `closed`, or `unfiltered`).
    Healthy,
    /// A probe timed out or was classified as filtered.
    Timeout,
    /// The target or path returned an ICMP error / address-unreachable result.
    Unreachable,
    /// The handshake completed but the peer stayed mute (tarpit-like behavior).
    Tarpit,
}

const ADAPTIVE_WINDOW: u64 = 500;
const TIMEOUT_PRESSURE_RATIO: f64 = 0.25;
const TIMEOUT_HEALTHY_RATIO: f64 = 0.05;
const UNREACHABLE_PRESSURE_RATIO: f64 = 0.05;
const TARPIT_PRESSURE_RATIO: f64 = 0.50;
const TARPIT_HEALTHY_RATIO: f64 = 0.10;
const TARPIT_PRESSURE_MIN: u64 = 32;

/// Adaptive target-politeness controller for connect scans.
///
/// Observes completed probes in fixed-size windows and adjusts the rate:
/// - Filtered/timeout ratios above 25% halve the rate.
/// - ICMP-error/unreachable ratios at or above 5% halve the rate.
/// - Tarpit-like handshake-silent bursts (at least 50% of a 500-probe window
///   and at least 32 probes) halve the rate.
/// - A window is healthy only with fewer than 5% timeouts, no unreachable
///   feedback, and fewer than 10% tarpit-like results; healthy windows increase
///   the rate by 25% up to the configured ceiling.
/// - Otherwise the rate is held constant.
///
/// The controller is not thread-safe; it lives in the scan receiver loop.
#[derive(Debug)]
pub struct AdaptiveRate {
    window: u64,
    observed: u64,
    timeouts: u64,
    unreachable: u64,
    tarpits: u64,
    current: u64,
    floor: u64,
    ceiling: u64,
}

impl AdaptiveRate {
    pub fn new(ceiling: u64, floor: u64) -> Self {
        let ceiling = ceiling.max(1);
        let floor = floor.clamp(1, ceiling);
        Self {
            window: ADAPTIVE_WINDOW,
            observed: 0,
            timeouts: 0,
            unreachable: 0,
            tarpits: 0,
            current: ceiling,
            floor,
            ceiling,
        }
    }

    pub fn current_rate(&self) -> u64 {
        self.current
    }

    /// Record one probe result. Returns the new rate when it changes.
    pub fn observe(&mut self, feedback: TargetFeedback) -> Option<u64> {
        self.observed += 1;
        match feedback {
            TargetFeedback::Healthy => {}
            TargetFeedback::Timeout => self.timeouts += 1,
            TargetFeedback::Unreachable => self.unreachable += 1,
            TargetFeedback::Tarpit => self.tarpits += 1,
        }
        if self.observed < self.window {
            return None;
        }

        let observed = self.observed as f64;
        let timeout_ratio = self.timeouts as f64 / observed;
        let unreachable_ratio = self.unreachable as f64 / observed;
        let tarpit_ratio = self.tarpits as f64 / observed;
        let pressure = timeout_ratio > TIMEOUT_PRESSURE_RATIO
            || unreachable_ratio >= UNREACHABLE_PRESSURE_RATIO
            || (self.tarpits >= TARPIT_PRESSURE_MIN && tarpit_ratio >= TARPIT_PRESSURE_RATIO);
        let healthy = timeout_ratio < TIMEOUT_HEALTHY_RATIO
            && self.unreachable == 0
            && tarpit_ratio < TARPIT_HEALTHY_RATIO;
        let new_rate = if pressure {
            (self.current as f64 * 0.5).max(self.floor as f64) as u64
        } else if healthy {
            (self.current as f64 * 1.25).min(self.ceiling as f64) as u64
        } else {
            self.current
        };
        self.observed = 0;
        self.timeouts = 0;
        self.unreachable = 0;
        self.tarpits = 0;
        if new_rate != self.current {
            self.current = new_rate;
            Some(new_rate)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_rate_is_unlimited() {
        assert!(RateLimiter::new(0).is_unlimited());
        assert!(!RateLimiter::new(1).is_unlimited());
    }

    #[tokio::test]
    async fn zero_rate_never_yields() {
        let limiter = RateLimiter::new(0);
        let start = Instant::now();
        for _ in 0..10_000 {
            limiter.acquire().await;
        }
        assert!(start.elapsed() < Duration::from_secs(1));
    }

    #[tokio::test]
    async fn limited_rate_consumes_the_burst_first() {
        let limiter = RateLimiter::new(100);
        let start = Instant::now();
        for _ in 0..10 {
            limiter.acquire().await;
        }
        assert!(start.elapsed() < Duration::from_millis(100));
    }

    #[test]
    fn adaptive_rate_halves_on_heavy_timeouts() {
        let mut adaptive = AdaptiveRate::new(1000, 100);
        adaptive.current = 500;
        for _ in 0..374 {
            assert_eq!(adaptive.observe(TargetFeedback::Healthy), None);
        }
        for _ in 0..125 {
            assert_eq!(adaptive.observe(TargetFeedback::Timeout), None);
        }
        assert_eq!(adaptive.observe(TargetFeedback::Timeout), Some(250));
    }

    #[test]
    fn adaptive_rate_increases_on_low_timeouts() {
        let mut adaptive = AdaptiveRate::new(1000, 100);
        adaptive.current = 500;
        for _ in 0..499 {
            assert_eq!(adaptive.observe(TargetFeedback::Healthy), None);
        }
        assert_eq!(adaptive.observe(TargetFeedback::Healthy), Some(625));
    }

    #[test]
    fn adaptive_rate_halves_on_icmp_pressure() {
        let mut adaptive = AdaptiveRate::new(1000, 100);
        adaptive.current = 500;
        for _ in 0..475 {
            assert_eq!(adaptive.observe(TargetFeedback::Healthy), None);
        }
        for _ in 0..24 {
            assert_eq!(adaptive.observe(TargetFeedback::Unreachable), None);
        }
        assert_eq!(adaptive.observe(TargetFeedback::Unreachable), Some(250));
    }

    #[test]
    fn sparse_icmp_pressure_holds_the_rate_without_increasing() {
        let mut adaptive = AdaptiveRate::new(1000, 100);
        adaptive.current = 500;
        for _ in 0..499 {
            assert_eq!(adaptive.observe(TargetFeedback::Healthy), None);
        }
        assert_eq!(adaptive.observe(TargetFeedback::Unreachable), None);
        assert_eq!(adaptive.current_rate(), 500);
    }

    #[test]
    fn adaptive_rate_halves_on_tarpit_burst() {
        let mut adaptive = AdaptiveRate::new(1000, 100);
        adaptive.current = 500;
        for _ in 0..250 {
            assert_eq!(adaptive.observe(TargetFeedback::Healthy), None);
        }
        for _ in 0..249 {
            assert_eq!(adaptive.observe(TargetFeedback::Tarpit), None);
        }
        assert_eq!(adaptive.observe(TargetFeedback::Tarpit), Some(250));
    }

    #[test]
    fn adaptive_floor_never_exceeds_the_configured_ceiling() {
        let adaptive = AdaptiveRate::new(50, 100);
        assert_eq!(adaptive.current_rate(), 50);
    }
}
