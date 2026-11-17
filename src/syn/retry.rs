//! Per-probe retransmission scheduling for raw SYN scans.
//!
//! A probe is retried when its own per-host retransmission window expires,
//! instead of waiting for a whole transmit pass to finish and then waiting the
//! global timeout. Entries stay in the queue until their deadline even when no
//! further retry is allowed, so the queue also bounds how long the scanner
//! waits for the final response.

use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::time::{Duration, Instant};

use crate::rtt::RttEstimator;

/// Smallest window used after an RTT sample has been observed.
pub(super) const MIN_RTO: Duration = Duration::from_millis(200);

/// One scheduled outcome check for a probe.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) struct Retry<K> {
    /// When the probe should be considered lost if no response is recorded.
    pub deadline: Instant,
    /// Target and destination port identifying the probe.
    pub key: K,
    /// Source port used by the most recent transmission.
    pub src_port: u16,
    /// Attempt that was last transmitted for this probe.
    pub attempt: u32,
}

/// Min-heap of probes ordered by their retransmission deadline.
#[derive(Debug)]
pub(super) struct RetryQueue<K> {
    heap: BinaryHeap<Reverse<Retry<K>>>,
}

impl<K: Ord> RetryQueue<K> {
    pub(super) fn new() -> Self {
        Self {
            heap: BinaryHeap::new(),
        }
    }

    pub(super) fn schedule(&mut self, retry: Retry<K>) {
        self.heap.push(Reverse(retry));
    }

    pub(super) fn pop_due(&mut self, now: Instant) -> Option<Retry<K>> {
        let next = self.heap.peek()?;
        if next.0.deadline > now {
            return None;
        }
        self.heap.pop().map(|entry| entry.0)
    }

    pub(super) fn peek(&self) -> Option<&Retry<K>> {
        self.heap.peek().map(|entry| &entry.0)
    }

    pub(super) fn pop(&mut self) -> Option<Retry<K>> {
        self.heap.pop().map(|entry| entry.0)
    }

    pub(super) fn next_deadline(&self) -> Option<Instant> {
        self.heap.peek().map(|entry| entry.0.deadline)
    }

    pub(super) fn is_empty(&self) -> bool {
        self.heap.is_empty()
    }

    pub(super) fn clear(&mut self) {
        self.heap.clear();
    }
}

/// Per-host retransmission window.
///
/// Hosts without an RTT sample use the scan's timeout ceiling. Once a sample
/// exists, RFC 6298 SRTT/RTTVAR governs the window, bounded below by
/// [`MIN_RTO`] so a retransmission is not sent before a normal reply.
pub(super) fn retry_window(estimator: Option<&RttEstimator>, maximum: Duration) -> Duration {
    match estimator {
        Some(estimator) => estimator.timeout(MIN_RTO, maximum),
        None => maximum,
    }
}

/// Advances a retransmission to a fresh source port in the scan's range.
///
/// Fresh ports keep every retransmission a distinct SYN to the target stack;
/// reusing the original port lets a server coalesce duplicates and rely on its
/// own delayed SYN-ACK retransmission, which can outlast the scan window.
pub(super) fn next_source_port(current: u16, low: u16, probes: u64, range_len: u64) -> u16 {
    low + (((u64::from(current - low) + probes) % range_len) as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deadlines_pop_in_order() {
        let now = Instant::now();
        let mut queue = RetryQueue::new();
        queue.schedule(Retry {
            deadline: now + Duration::from_millis(30),
            key: (1_u8, 80_u16),
            src_port: 61000,
            attempt: 0,
        });
        queue.schedule(Retry {
            deadline: now + Duration::from_millis(10),
            key: (1_u8, 81_u16),
            src_port: 61001,
            attempt: 0,
        });
        queue.schedule(Retry {
            deadline: now + Duration::from_millis(20),
            key: (1_u8, 82_u16),
            src_port: 61002,
            attempt: 0,
        });

        assert_eq!(
            queue
                .pop_due(now + Duration::from_millis(15))
                .map(|r| r.key),
            Some((1_u8, 81_u16))
        );
        assert_eq!(
            queue
                .pop_due(now + Duration::from_millis(25))
                .map(|r| r.key),
            Some((1_u8, 82_u16))
        );
        assert_eq!(
            queue
                .pop_due(now + Duration::from_millis(25))
                .map(|r| r.key),
            None
        );
        assert_eq!(
            queue
                .pop_due(now + Duration::from_millis(30))
                .map(|r| r.key),
            Some((1_u8, 80_u16))
        );
    }

    #[test]
    fn retry_window_waits_for_a_sample() {
        let maximum = Duration::from_millis(900);
        assert_eq!(retry_window(None, maximum), maximum);

        let mut estimator = RttEstimator::new();
        estimator.observe(Duration::from_millis(4));
        assert_eq!(retry_window(Some(&estimator), maximum), MIN_RTO);
    }

    #[test]
    fn retry_source_ports_advance_and_wrap() {
        assert_eq!(next_source_port(61000, 61000, 20, 1000), 61020);
        assert_eq!(next_source_port(61990, 61000, 20, 1000), 61010);
        assert_ne!(next_source_port(61000, 61000, 20, 1000), 61000);
    }
}
