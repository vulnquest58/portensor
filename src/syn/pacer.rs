//! Lightweight token-bucket pacing shared by raw probe engines.

use std::time::{Duration, Instant};

/// Token bucket used to pace raw probe batches.
pub(super) struct Pacer {
    rate_pps: u64,
    tokens: f64,
    last: Instant,
}

impl Pacer {
    pub(super) fn new(rate_pps: u64) -> Self {
        Self {
            rate_pps,
            tokens: if rate_pps > 0 {
                (rate_pps as f64 / 10.0).clamp(1.0, 1000.0)
            } else {
                0.0
            },
            last: Instant::now(),
        }
    }

    pub(super) fn wait_for_batch(&mut self, batch_count: usize) {
        if self.rate_pps == 0 || batch_count == 0 {
            return;
        }

        let rate = self.rate_pps as f64;
        let burst = (rate / 10.0).clamp(1.0, 1000.0);
        let mut remaining = batch_count as f64;

        while remaining > 0.0 {
            let cost = remaining.min(burst);
            loop {
                let now = Instant::now();
                let elapsed = now.duration_since(self.last).as_secs_f64();
                self.last = now;
                self.tokens = (self.tokens + elapsed * rate).min(burst);

                if self.tokens >= cost {
                    self.tokens -= cost;
                    break;
                }

                let needed = cost - self.tokens;
                let sleep_secs = needed / rate;
                std::thread::sleep(Duration::from_secs_f64(sleep_secs));
            }
            remaining -= cost;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pacer_handles_batches_larger_than_the_burst() {
        let mut pacer = Pacer::new(1000);
        let started = Instant::now();
        pacer.wait_for_batch(101);
        assert!(started.elapsed() < Duration::from_millis(100));
    }
}
