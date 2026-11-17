use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::fingerprint::OsGuess;
use crate::service::{Detection, ServiceInfo};

/// The result of probing one TCP port.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum PortState {
    Open,
    #[default]
    Closed,
    Filtered,
    Unfiltered,
    Silent,
    Unreachable,
    Error,
}

impl PortState {
    pub const ALL: [Self; 7] = [
        Self::Open,
        Self::Closed,
        Self::Filtered,
        Self::Unfiltered,
        Self::Silent,
        Self::Unreachable,
        Self::Error,
    ];

    pub const fn bit(self) -> u8 {
        match self {
            Self::Open => 1 << 0,
            Self::Closed => 1 << 1,
            Self::Filtered => 1 << 2,
            Self::Unfiltered => 1 << 3,
            Self::Silent => 1 << 4,
            Self::Unreachable => 1 << 5,
            Self::Error => 1 << 6,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Closed => "closed",
            Self::Filtered => "filtered",
            Self::Unfiltered => "unfiltered",
            Self::Silent => "silent",
            Self::Unreachable => "unreachable",
            Self::Error => "error",
        }
    }
}

impl fmt::Display for PortState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A compact set of port states used for retention and output filtering.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StateSet(u8);

impl StateSet {
    pub const fn empty() -> Self {
        Self(0)
    }

    pub const fn open() -> Self {
        Self(PortState::Open.bit())
    }

    pub const fn unfiltered() -> Self {
        Self(PortState::Unfiltered.bit())
    }

    pub const fn all() -> Self {
        Self(
            PortState::Open.bit()
                | PortState::Closed.bit()
                | PortState::Filtered.bit()
                | PortState::Unfiltered.bit()
                | PortState::Silent.bit()
                | PortState::Unreachable.bit()
                | PortState::Error.bit(),
        )
    }

    pub const fn contains(self, state: PortState) -> bool {
        self.0 & state.bit() != 0
    }

    pub fn insert(&mut self, state: PortState) {
        self.0 |= state.bit();
    }

    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

/// Counts for every state, including states not retained for display.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
pub struct StateCounts {
    pub open: u64,
    pub closed: u64,
    pub filtered: u64,
    pub unfiltered: u64,
    pub silent: u64,
    pub unreachable: u64,
    pub error: u64,
}

impl StateCounts {
    pub fn add(&mut self, state: PortState) {
        match state {
            PortState::Open => self.open += 1,
            PortState::Closed => self.closed += 1,
            PortState::Filtered => self.filtered += 1,
            PortState::Unfiltered => self.unfiltered += 1,
            PortState::Silent => self.silent += 1,
            PortState::Unreachable => self.unreachable += 1,
            PortState::Error => self.error += 1,
        }
    }

    pub fn add_other(&mut self, other: Self) {
        self.open += other.open;
        self.closed += other.closed;
        self.filtered += other.filtered;
        self.unfiltered += other.unfiltered;
        self.silent += other.silent;
        self.unreachable += other.unreachable;
        self.error += other.error;
    }

    pub fn remove(&mut self, state: PortState) {
        match state {
            PortState::Open => self.open = self.open.saturating_sub(1),
            PortState::Closed => self.closed = self.closed.saturating_sub(1),
            PortState::Filtered => self.filtered = self.filtered.saturating_sub(1),
            PortState::Unfiltered => self.unfiltered = self.unfiltered.saturating_sub(1),
            PortState::Silent => self.silent = self.silent.saturating_sub(1),
            PortState::Unreachable => self.unreachable = self.unreachable.saturating_sub(1),
            PortState::Error => self.error = self.error.saturating_sub(1),
        }
    }

    pub const fn total(self) -> u64 {
        self.open
            + self.closed
            + self.filtered
            + self.unfiltered
            + self.silent
            + self.unreachable
            + self.error
    }
}

/// One probe result.
#[derive(Clone, Debug)]
pub struct PortResult {
    pub host: IpAddr,
    pub port: u16,
    pub state: PortState,
    pub latency: Duration,
    pub detail: Option<String>,
    pub service: Option<ServiceInfo>,
    pub banner: Option<String>,
    /// Confidence in this result, 0.0–1.0. Set by the accuracy scoring engine.
    pub confidence: Option<f32>,
    /// Evidence string detailing why this result and confidence were reached.
    pub evidence: Option<String>,
    /// Offline CVE advisories correlated with the detected service.
    pub advisories: Vec<crate::advisory::AdvisoryMatch>,
    /// TLS metadata captured during an optional post-scan handshake.
    pub tls: Option<crate::tls::TlsInfo>,
    /// RDP NLA identity captured for Remote Desktop endpoints.
    pub rdp: Option<crate::rdp::RdpInfo>,
    /// Findings reported by script plugins after service detection.
    pub script_findings: Vec<crate::script::PluginFinding>,
}

impl PortResult {
    pub fn new(host: IpAddr, port: u16, state: PortState, latency: Duration) -> Self {
        Self {
            host,
            port,
            state,
            latency,
            detail: None,
            service: None,
            banner: None,
            confidence: None,
            evidence: None,
            advisories: Vec::new(),
            tls: None,
            rdp: None,
            script_findings: Vec::new(),
        }
    }

    pub fn with_evidence(mut self, evidence: impl Into<String>) -> Self {
        self.evidence = Some(evidence.into());
        self
    }

    /// True when verification completed a TCP handshake but the peer reset
    /// after data was sent. Such ports are open but hostile to the plaintext
    /// probe (common for TLS listeners on non-standard ports).
    pub(crate) fn reset_during_verification(&self) -> bool {
        if self.state != PortState::Closed {
            return false;
        }
        self.detail.as_deref().is_some_and(|detail| {
            let detail = detail.to_ascii_lowercase();
            detail.contains("connection closed during verification")
                && (detail.contains("reset")
                    || detail.contains("broken pipe")
                    || detail.contains("aborted"))
        })
    }

    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    pub fn with_detection(mut self, detection: Detection) -> Self {
        self.service = detection.service;
        self.banner = detection.banner;
        self
    }

    /// Attach a confidence score (0.0–1.0).  Values outside that range are clamped.
    pub fn with_confidence(mut self, confidence: f32) -> Self {
        self.confidence = Some(confidence.clamp(0.0, 1.0));
        self
    }
}

/// Per-host scan progress used to persist multi-target resume state.
#[derive(Clone, Debug, Default)]
pub struct HostProgress {
    /// Ports probed against this host (every outcome).
    pub ports_scanned: Vec<u16>,
    /// State counts restricted to the probes above.
    pub counts: StateCounts,
}

/// The complete scanner output, excluding presentation choices.
#[derive(Clone, Debug)]
pub struct ScanReport {
    pub targets: usize,
    pub ports: usize,
    pub jobs: u64,
    pub workers: usize,
    pub elapsed: Duration,
    pub counts: StateCounts,
    pub results: Vec<PortResult>,
    /// OS fingerprint results, keyed by host IP. Populated only when
    /// `--os` is passed. Empty if OS detection was not requested or failed.
    pub os_fingerprints: HashMap<IpAddr, OsGuess>,
    /// Ports actually probed by this scan.  Used to persist accurate resume
    /// state even when interrupted midway through a randomized scan.
    pub probed_ports: Vec<u16>,
    /// Probe progress per host, keyed by host IP. Populated by the connect
    /// scanner; enables per-target `--save-state`/`--resume` bookkeeping.
    pub host_progress: HashMap<IpAddr, HostProgress>,
    /// True when the scan was interrupted (Ctrl-C) before all probes completed.
    /// Partial results are still valid but may be incomplete.
    pub partial: bool,
    /// Defense and middlebox discrepancy observations (reclassified verification drops, etc.).
    pub defense_observations: Vec<PortResult>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unfiltered_state_round_trips_and_sets_the_exclusive_bit() {
        let encoded = serde_json::to_string(&PortState::Unfiltered).unwrap();
        assert_eq!(encoded, "\"unfiltered\"");
        assert_eq!(PortState::Unfiltered.as_str(), "unfiltered");
        assert_eq!(PortState::ALL.len(), 7);

        let bits: u8 = PortState::ALL.iter().map(|state| state.bit()).sum();
        assert_eq!(bits, 0b0111_1111);

        let set = StateSet::all();
        assert!(set.contains(PortState::Unfiltered));
        assert!(StateSet::unfiltered().contains(PortState::Unfiltered));
        assert!(!StateSet::open().contains(PortState::Unfiltered));
    }

    #[test]
    fn state_counts_track_unfiltered_results() {
        let mut counts = StateCounts::default();
        counts.add(PortState::Unfiltered);
        counts.add(PortState::Unfiltered);
        counts.add(PortState::Closed);
        assert_eq!(counts.unfiltered, 2);
        assert_eq!(counts.total(), 3);

        counts.remove(PortState::Unfiltered);
        assert_eq!(counts.unfiltered, 1);
        counts.remove(PortState::Unfiltered);
        counts.remove(PortState::Unfiltered);
        assert_eq!(counts.unfiltered, 0);

        let json = serde_json::to_value(counts).unwrap();
        assert_eq!(json["unfiltered"], 0);
    }

    #[test]
    fn add_other_merges_every_state_including_unfiltered() {
        let mut left = StateCounts {
            open: 1,
            closed: 2,
            ..StateCounts::default()
        };
        let right = StateCounts {
            filtered: 3,
            unfiltered: 4,
            silent: 5,
            unreachable: 6,
            error: 7,
            ..StateCounts::default()
        };
        left.add_other(right);
        assert_eq!(
            left,
            StateCounts {
                open: 1,
                closed: 2,
                filtered: 3,
                unfiltered: 4,
                silent: 5,
                unreachable: 6,
                error: 7,
            }
        );
    }
}
