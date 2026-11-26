use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use tokio::net::{TcpSocket, TcpStream};

use crate::classify::{FailureKind, classify_kind};
use crate::discovery::socket_addr;
use crate::error::AppError;
#[cfg(test)]
use crate::model::StateSet;
use crate::model::{PortResult, PortState, ScanReport};
use crate::rate::RateLimiter;
use crate::scanner::{self, ProgressCallback, ScanOptions};

pub async fn verify_syn_open(
    report: &mut ScanReport,
    options: &ScanOptions,
    progress: Option<ProgressCallback>,
) -> Result<(), AppError> {
    let candidates: Vec<(IpAddr, u16)> = report
        .results
        .iter()
        .filter(|result| result.state == PortState::Open)
        .map(|result| (result.host, result.port))
        .collect();

    verify_syn_open_candidates(report, &candidates, options, progress).await
}

/// Verify a specific subset of candidates (used when anomaly detection has
/// already filtered the full open list down to a manageable sample).
pub async fn verify_syn_open_candidates(
    report: &mut ScanReport,
    candidates: &[(IpAddr, u16)],
    options: &ScanOptions,
    progress: Option<ProgressCallback>,
) -> Result<(), AppError> {
    if candidates.is_empty() {
        return Ok(());
    }

    let verified = scanner::verify_candidates(candidates, options, progress).await?;
    merge_verification(report, verified, options);
    Ok(())
}

fn merge_verification(report: &mut ScanReport, verified: Vec<PortResult>, options: &ScanOptions) {
    for result in verified {
        let Some(index) = report.results.iter().position(|existing| {
            existing.host == result.host
                && existing.port == result.port
                && existing.state == PortState::Open
        }) else {
            continue;
        };

        let inconclusive = matches!(
            result.state,
            PortState::Filtered | PortState::Unreachable | PortState::Error
        );
        if result.state != PortState::Open {
            report.defense_observations.push(result.clone());
        }
        if inconclusive {
            if let Some(existing) = report.results.get_mut(index) {
                let detail = result.detail.as_deref().unwrap_or("no response");
                existing.detail = Some(format!(
                    "SYN-ACK observed; verification inconclusive: {detail}"
                ));
            }
            continue;
        }

        report.counts.remove(PortState::Open);
        report.counts.add(result.state);

        let retain = options.retains(&result);
        if retain {
            report.results[index] = result;
        } else {
            report.results.remove(index);
        }
    }
}

/// Re-verify open results that point at this machine.
///
/// A scan whose target is the local host completes inside the kernel, so two
/// of the scanner's own in-flight connections can pair up (TCP simultaneous
/// open) and be reported as listeners that do not exist.  The recheck walks
/// the open set one connection at a time — a lone connection cannot pair with
/// anything — and reclassifies every open that now refuses to connect.
/// Remote targets are skipped entirely: they cannot produce the artifact and
/// re-probing them would double the traffic the user asked for.
pub async fn recheck_local_opens(report: &mut ScanReport, options: &ScanOptions) {
    if options.shutdown.load(Ordering::Relaxed) {
        return;
    }

    let candidates: Vec<(IpAddr, u16)> = report
        .results
        .iter()
        .filter(|result| result.state == PortState::Open && is_local_target(result.host))
        .map(|result| (result.host, result.port))
        .collect();
    if candidates.is_empty() {
        return;
    }

    // Concurrent rechecks are safe when no source port can also be a target.
    // Two scanner sockets only pair by simultaneous open when one socket's
    // source port equals another's destination port. Binding the recheck
    // source to a port outside the open-candidate set makes that impossible,
    // so the whole open set can be rechecked in parallel instead of paying a
    // full loss-driven timeout for every listener sequentially.
    let forbidden: Arc<HashSet<u16>> = Arc::new(candidates.iter().map(|(_, port)| *port).collect());
    let candidates = Arc::new(candidates);
    let limiter = Arc::new(RateLimiter::new(options.rate));
    let next = Arc::new(AtomicU64::new(0));
    let workers = candidates.len().clamp(1, 32);
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..workers {
        let candidates = Arc::clone(&candidates);
        let forbidden = Arc::clone(&forbidden);
        let limiter = Arc::clone(&limiter);
        let next = Arc::clone(&next);
        let shutdown = Arc::clone(&options.shutdown);
        let timeout = options.timeout;
        tasks.spawn(async move {
            let mut refused = Vec::new();
            loop {
                if shutdown.load(Ordering::Relaxed) {
                    break;
                }
                let index = next.fetch_add(1, Ordering::Relaxed) as usize;
                let Some(&(host, port)) = candidates.get(index) else {
                    break;
                };
                limiter.acquire().await;
                let started = Instant::now();
                let attempt =
                    tokio::time::timeout(timeout, recheck_connect(host, port, &forbidden)).await;
                let elapsed = started.elapsed();
                let refused_state = matches!(
                    &attempt,
                    Ok(Err(error)) if classify_kind(error) == FailureKind::Closed
                );
                if refused_state {
                    refused.push((host, port, elapsed));
                }
            }
            refused
        });
    }

    let mut rejected = Vec::new();
    while let Some(joined) = tasks.join_next().await {
        let Ok(refused) = joined else {
            continue;
        };
        for (host, port, elapsed) in refused {
            rejected.push(
                PortResult::new(host, port, PortState::Closed, elapsed).with_detail(
                    "connection refused on recheck; the initial open was a loopback \
                     simultaneous open or a listener that has since stopped",
                ),
            );
        }
    }

    if !rejected.is_empty() {
        merge_verification(report, rejected, options);
    }
}

async fn recheck_connect(
    host: IpAddr,
    port: u16,
    forbidden: &HashSet<u16>,
) -> std::io::Result<TcpStream> {
    let address = socket_addr(host, port);
    for _ in 0..64 {
        let (socket, bind) = if host.is_ipv4() {
            (
                TcpSocket::new_v4()?,
                SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            )
        } else {
            (
                TcpSocket::new_v6()?,
                SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
            )
        };
        socket.bind(bind)?;
        if forbidden.contains(&socket.local_addr()?.port()) {
            continue;
        }
        return socket.connect(address).await;
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AddrNotAvailable,
        "no safe source port for local open recheck",
    ))
}
/// True when `ip` addresses this machine, i.e. a scan against it can finish
/// inside the kernel and pair up two of our own connections.
fn is_local_target(ip: IpAddr) -> bool {
    if ip.is_loopback() {
        return true;
    }
    // A UDP connect() sends no packets; it only resolves the route, so the
    // socket's local address equals the target exactly when the target is
    // one of this machine's own addresses.
    let bind = if ip.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" };
    let Ok(socket) = std::net::UdpSocket::bind(bind) else {
        return false;
    };
    if socket.connect(SocketAddr::new(ip, 53)).is_err() {
        return false;
    }
    socket.local_addr().is_ok_and(|addr| addr.ip() == ip)
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;
    use std::time::Duration;

    use super::*;
    use crate::model::StateCounts;

    fn host() -> IpAddr {
        "10.77.0.2".parse().unwrap()
    }

    fn local_host() -> IpAddr {
        "127.0.0.1".parse().unwrap()
    }

    fn options(retain: StateSet) -> ScanOptions {
        ScanOptions {
            timeout: Duration::from_secs(1),
            probe_timeout: Duration::from_millis(100),
            rate: 0,
            workers: 4,
            retries: 0,
            randomize: false,
            connect_only: false,
            service_detection: true,
            retain,
            retain_silent_ports: Vec::new(),
            retain_reset_closed: false,
            jitter: Duration::ZERO,
            rate_auto: false,
            host_concurrency: 0,
            shutdown: Arc::new(AtomicBool::new(false)),
        }
    }

    fn local_open_report(port: u16) -> ScanReport {
        ScanReport {
            targets: 1,
            ports: 1,
            jobs: 1,
            workers: 1,
            elapsed: Duration::from_millis(1),
            counts: StateCounts {
                open: 1,
                ..StateCounts::default()
            },
            results: vec![PortResult::new(
                local_host(),
                port,
                PortState::Open,
                Duration::from_micros(100),
            )],
            os_fingerprints: std::collections::HashMap::new(),
            probed_ports: vec![port],
            host_progress: Default::default(),
            partial: false,
            defense_observations: Vec::new(),
        }
    }

    fn dead_port() -> u16 {
        // Bind and drop so nothing listens when the recheck runs.
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        listener.local_addr().unwrap().port()
    }

    fn report() -> ScanReport {
        ScanReport {
            targets: 1,
            ports: 3,
            jobs: 3,
            workers: 2,
            elapsed: Duration::from_millis(100),
            counts: StateCounts {
                open: 3,
                ..StateCounts::default()
            },
            results: vec![
                PortResult::new(host(), 80, PortState::Open, Duration::from_millis(1)),
                PortResult::new(host(), 9000, PortState::Open, Duration::from_millis(1)),
                PortResult::new(host(), 9003, PortState::Open, Duration::from_millis(1)),
            ],
            os_fingerprints: std::collections::HashMap::new(),
            probed_ports: vec![80, 9000, 9003],
            host_progress: Default::default(),
            partial: false,
            defense_observations: Vec::new(),
        }
    }

    #[test]
    fn reclassifies_false_open_candidates_and_updates_counts() {
        let mut report = report();
        let verified = vec![
            PortResult::new(host(), 80, PortState::Open, Duration::from_millis(2)),
            PortResult::new(host(), 9000, PortState::Silent, Duration::from_millis(300)),
            PortResult::new(host(), 9003, PortState::Closed, Duration::from_millis(1)),
        ];

        merge_verification(&mut report, verified, &options(StateSet::all()));

        assert_eq!(report.counts.open, 1);
        assert_eq!(report.counts.silent, 1);
        assert_eq!(report.counts.closed, 1);
        assert_eq!(report.results.len(), 3);
        assert!(
            report
                .results
                .iter()
                .any(|result| { result.port == 9000 && result.state == PortState::Silent })
        );
    }

    #[test]
    fn inconclusive_verification_keeps_the_syn_ack_open_result() {
        let mut report = report();
        let verified = vec![
            PortResult::new(host(), 9000, PortState::Filtered, Duration::from_secs(1))
                .with_detail("connect timed out after 1000ms"),
        ];

        merge_verification(&mut report, verified, &options(StateSet::open()));

        assert_eq!(report.counts.open, 3);
        assert_eq!(report.counts.filtered, 0);
        let kept = report
            .results
            .iter()
            .find(|result| result.port == 9000)
            .expect("SYN-ACK-backed open result is retained");
        assert_eq!(kept.state, PortState::Open);
        assert!(
            kept.detail
                .as_deref()
                .is_some_and(|detail| detail.contains("verification inconclusive"))
        );
        assert_eq!(report.defense_observations.len(), 1);
    }

    #[test]
    fn drops_reclassified_results_that_are_not_retained() {
        let mut report = report();
        let verified = vec![PortResult::new(
            host(),
            9000,
            PortState::Silent,
            Duration::from_millis(300),
        )];

        merge_verification(&mut report, verified, &options(StateSet::open()));

        assert_eq!(report.counts.open, 2);
        assert_eq!(report.counts.silent, 1);
        assert!(report.results.iter().all(|result| result.port != 9000));
    }

    #[test]
    fn local_target_detection_covers_loopback_and_rejects_remote() {
        assert!(is_local_target("127.0.0.1".parse().unwrap()));
        assert!(is_local_target("127.9.9.9".parse().unwrap()));
        assert!(is_local_target("::1".parse().unwrap()));
        assert!(!is_local_target("192.0.2.1".parse().unwrap()));
        assert!(!is_local_target("198.51.100.7".parse().unwrap()));
    }

    #[tokio::test]
    async fn recheck_reclassifies_local_opens_that_refuse() {
        let port = dead_port();
        let mut report = local_open_report(port);

        recheck_local_opens(&mut report, &options(StateSet::open())).await;

        assert_eq!(report.counts.open, 0);
        assert_eq!(report.counts.closed, 1);
        assert!(report.results.is_empty());
        assert_eq!(report.probed_ports, vec![port]);
    }

    #[tokio::test]
    async fn recheck_keeps_local_listeners_that_still_accept() {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let mut report = local_open_report(port);
        report.results[0].banner = Some("hello".to_string());

        recheck_local_opens(&mut report, &options(StateSet::open())).await;

        assert_eq!(report.counts.open, 1);
        assert_eq!(report.results.len(), 1);
        assert_eq!(report.results[0].state, PortState::Open);
        assert_eq!(report.results[0].banner.as_deref(), Some("hello"));
    }

    #[tokio::test]
    async fn recheck_leaves_remote_targets_untouched() {
        let mut report = ScanReport {
            targets: 1,
            ports: 1,
            jobs: 1,
            workers: 1,
            elapsed: Duration::from_millis(1),
            counts: StateCounts {
                open: 1,
                ..StateCounts::default()
            },
            results: vec![PortResult::new(
                "192.0.2.1".parse().unwrap(),
                80,
                PortState::Open,
                Duration::from_micros(100),
            )],
            os_fingerprints: std::collections::HashMap::new(),
            probed_ports: vec![80],
            host_progress: Default::default(),
            partial: false,
            defense_observations: Vec::new(),
        };

        recheck_local_opens(&mut report, &options(StateSet::open())).await;

        assert_eq!(report.counts.open, 1);
        assert_eq!(report.results.len(), 1);
        assert_eq!(report.results[0].state, PortState::Open);
    }

    #[tokio::test]
    async fn recheck_retains_reclassified_opens_when_all_states_are_kept() {
        let port = dead_port();
        let mut report = local_open_report(port);

        recheck_local_opens(&mut report, &options(StateSet::all())).await;

        assert_eq!(report.counts.open, 0);
        assert_eq!(report.counts.closed, 1);
        assert_eq!(report.results.len(), 1);
        assert_eq!(report.results[0].state, PortState::Closed);
        assert!(report.results[0].detail.is_some());
    }

    #[tokio::test]
    async fn recheck_keeps_listeners_and_rejects_multiple_dead_ports() {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let live = listener.local_addr().unwrap().port();
        let first = dead_port();
        let second = dead_port();
        let mut report = local_open_report(live);
        report.counts.open = 3;
        report.results = vec![
            PortResult::new(
                local_host(),
                live,
                PortState::Open,
                Duration::from_micros(100),
            ),
            PortResult::new(
                local_host(),
                first,
                PortState::Open,
                Duration::from_micros(100),
            ),
            PortResult::new(
                local_host(),
                second,
                PortState::Open,
                Duration::from_micros(100),
            ),
        ];
        report.probed_ports = vec![live, first, second];

        recheck_local_opens(&mut report, &options(StateSet::open())).await;

        assert_eq!(report.counts.open, 1);
        assert_eq!(report.counts.closed, 2);
        assert_eq!(report.results.len(), 1);
        assert_eq!(report.results[0].port, live);
    }

    #[tokio::test]
    async fn recheck_source_port_is_outside_the_candidate_set() {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let forbidden = HashSet::from([port]);

        let stream = recheck_connect(local_host(), port, &forbidden)
            .await
            .unwrap();

        assert_ne!(stream.local_addr().unwrap().port(), port);
    }

    #[tokio::test]
    async fn recheck_skips_probing_after_shutdown() {
        let port = dead_port();
        let mut report = local_open_report(port);
        let scan_options = options(StateSet::open());
        scan_options.shutdown.store(true, Ordering::Relaxed);

        recheck_local_opens(&mut report, &scan_options).await;

        assert_eq!(report.counts.open, 1);
        assert_eq!(report.results.len(), 1);
    }
}
