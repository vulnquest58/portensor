//! Raw SYN packet scanning engine.
//!
//! Linux uses high-speed `AF_PACKET` sockets with kernel BPF filtering.
//! Windows uses a dynamically loaded Npcap/WinPcap (`wpcap.dll`) backend so
//! the normal release binary does not need a packet-capture SDK at build time.

use crate::error::AppError;
use crate::model::{ScanReport, StateSet};
use crate::scanner::ProgressCallback;

/// Default IPv4 TTL and IPv6 hop limit for raw probes.
pub const DEFAULT_PROBE_TTL: u8 = 64;

pub mod aimd;
pub mod cookie;
mod pacer;
pub mod packet;
pub mod permute;
#[cfg(target_os = "linux")]
mod retry;
mod source_port;

#[cfg(target_os = "linux")]
pub mod engine;
#[cfg(target_os = "linux")]
pub mod filter;
#[cfg(target_os = "linux")]
pub mod route;
#[cfg(target_os = "linux")]
pub(crate) mod v4raw;
#[cfg(target_os = "linux")]
pub(crate) mod v6;
#[cfg(target_os = "windows")]
mod win;

pub use aimd::{AimdConfig, AimdController, AimdFeedback};
pub use cookie::CookieKey;
pub use packet::{
    ParsedFrame, build_syn_frame, fragment_syn_frame, ip_checksum, parse_frame, tcp_checksum,
};
pub use permute::BlackRock;

#[cfg(target_os = "linux")]
pub use filter::{attach_filter, build_filter};
#[cfg(target_os = "linux")]
pub use route::{
    RouteInfo, SynError, arp_resolve, default_route, iface_index, iface_ip, iface_mac,
};

/// Raw probe mode: SYN discovery or ACK firewall mapping.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ProbeMode {
    #[default]
    Syn,
    Ack,
}

/// Configuration options for a raw SYN/ACK scan.
#[derive(Clone, Debug)]
pub struct SynScanOptions {
    /// Target IP addresses to scan.
    pub targets: Vec<std::net::IpAddr>,
    /// Target TCP ports to probe on each host.
    pub ports: Vec<u16>,
    /// Probe type.
    pub mode: ProbeMode,
    /// Initial transmit rate in packets per second (0 means unlimited).
    pub rate_pps: u64,
    /// Rate used for retransmission passes (0 means `rate_pps / 4`).
    pub retry_rate_pps: u64,
    /// Source port range used by the scanner `(min, max)`.
    pub sport_range: (u16, u16),
    /// Milliseconds to wait after the last transmitted probe before declaring quiet ports filtered.
    pub timeout_ms: u64,
    /// Number of frames to batch per send call.
    pub batch_size: usize,
    /// Number of retransmission passes for probes that received no response.
    pub retries: u32,
    /// Set of port states to retain in the resulting report.
    pub retain: StateSet,
    /// Enable AIMD adaptive rate control. Has no effect when `rate_pps == 0`.
    pub aimd: bool,
    /// AIMD minimum rate floor in packets per second.
    pub aimd_min_pps: u64,
    /// Per-host SYN-open count at which the raw engine treats the target as a
    /// tarpit/SYN-proxy farm and forces AIMD backoff. 0 disables.
    pub anomaly_threshold: u32,
    /// Maximum random delay inserted before each packet batch, in milliseconds.
    pub jitter_ms: u64,
    /// Spoofed source addresses for decoy probes (IPv4 only).
    pub decoys: Vec<std::net::Ipv4Addr>,
    /// Maximum IPv4 payload bytes per fragment (multiple of 8). `None` disables.
    pub fragment_size: Option<usize>,
    /// IPv4 TTL / IPv6 hop limit for raw probes.
    pub ttl: u8,
}

impl Default for SynScanOptions {
    fn default() -> Self {
        Self {
            targets: Vec::new(),
            ports: Vec::new(),
            mode: ProbeMode::Syn,
            rate_pps: 0,
            retry_rate_pps: 0,
            sport_range: (61000, 61999),
            timeout_ms: 1000,
            batch_size: 4096,
            retries: 2,
            retain: StateSet::all(),
            aimd: true,
            aimd_min_pps: 100,
            anomaly_threshold: 1000,
            jitter_ms: 0,
            decoys: Vec::new(),
            fragment_size: None,
            ttl: DEFAULT_PROBE_TTL,
        }
    }
}

/// Returns true when any host has at least `threshold` SYN-open results.
/// The raw AIMD loop uses this as a mid-scan tarpit/SYN-proxy signal.
#[cfg(any(target_os = "linux", target_os = "windows"))]
fn has_high_density_open(
    responses: &std::collections::HashMap<
        (std::net::Ipv4Addr, u16),
        (crate::model::PortState, std::time::Duration),
    >,
    threshold: u32,
) -> bool {
    if threshold == 0 {
        return false;
    }
    let mut counts: std::collections::HashMap<std::net::Ipv4Addr, u32> =
        std::collections::HashMap::new();
    for (&(host, _), &(state, _)) in responses {
        if state != crate::model::PortState::Open {
            continue;
        }
        let count = counts.entry(host).or_default();
        *count += 1;
        if *count >= threshold {
            return true;
        }
    }
    false
}

#[cfg(all(test, any(target_os = "linux", target_os = "windows")))]
mod tests {
    use super::*;
    use crate::model::PortState;
    use std::collections::HashMap;
    use std::net::Ipv4Addr;
    use std::time::Duration;

    fn responses(
        host: Ipv4Addr,
        ports: std::ops::Range<u16>,
        state: PortState,
    ) -> HashMap<(Ipv4Addr, u16), (PortState, Duration)> {
        ports
            .map(|port| ((host, port), (state, Duration::ZERO)))
            .collect()
    }

    #[test]
    fn high_density_open_detection_is_per_host_and_thresholded() {
        let first = Ipv4Addr::new(10, 0, 0, 1);
        let second = Ipv4Addr::new(10, 0, 0, 2);
        let mut map = responses(first, 1..1000, PortState::Open);
        assert!(!has_high_density_open(&map, 1000));

        map.extend(responses(second, 1..999, PortState::Open));
        assert!(!has_high_density_open(&map, 1000));

        map.insert((first, 1000), (PortState::Open, Duration::ZERO));
        assert!(has_high_density_open(&map, 1000));
    }

    #[test]
    fn high_density_open_detection_ignores_non_open_states_and_disabled_threshold() {
        let host = Ipv4Addr::new(10, 0, 0, 1);
        let map = responses(host, 1..2000, PortState::Closed);
        assert!(!has_high_density_open(&map, 1000));
        assert!(!has_high_density_open(
            &responses(host, 1..2000, PortState::Open),
            0
        ));
    }
}

/// Checks whether raw probing is available on this platform.
pub fn check_raw_privilege() -> Result<(), AppError> {
    #[cfg(target_os = "linux")]
    {
        engine::check_raw_privilege()
    }
    #[cfg(target_os = "windows")]
    {
        win::check_raw_privilege()
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        Err(AppError::usage(
            "raw SYN scanning requires Linux or Windows with Npcap",
        ))
    }
}

/// Executes a raw SYN/ACK scan.
pub fn syn_scan(
    opts: SynScanOptions,
    progress: Option<ProgressCallback>,
) -> Result<ScanReport, AppError> {
    #[cfg(target_os = "linux")]
    {
        engine::syn_scan(opts, progress)
    }
    #[cfg(target_os = "windows")]
    {
        win::syn_scan(opts, progress)
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows")))]
    {
        let _ = (opts, progress);
        Err(AppError::usage(
            "raw SYN scanning requires Linux or Windows with Npcap",
        ))
    }
}

#[cfg(target_os = "windows")]
pub(crate) fn route_summary() -> Result<String, String> {
    win::route_summary()
}
