use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_channel::Sender;
use rand::Rng;
use rand::seq::SliceRandom;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use crate::accuracy;
use crate::classify::{Failure, FailureKind, classify_io_error, classify_kind};
use crate::diag::{self, Level};
use crate::discovery::socket_addr;
use crate::error::AppError;
use crate::limits::worker_count;
use crate::model::{HostProgress, PortResult, PortState, ScanReport, StateCounts, StateSet};
use crate::rate::{AdaptiveRate, RateLimiter, TargetFeedback};
use crate::rtt::RttEstimator;
use crate::service;

const MIN_CONNECT_TIMEOUT: Duration = Duration::from_millis(1_500);
/// Upper bound on application-level timeout retries per port. Each retry can
/// cost a full connect timeout, so a high `--retries` value must not turn a
/// filtered port into a multi-second delay.
const MAX_TIMEOUT_RETRIES: u32 = 3;
/// Verification reconnects are bounded separately from connect retries. A
/// silent tarpit looks identical to a lost banner, so an aggressive profile
/// must not turn every tarpit into many full probe windows.
const MAX_VERIFICATION_RETRIES: u32 = 2;
const SERVICE_BANNER_LIMIT: usize = 1024;
const SERVICE_BANNER_IDLE: Duration = Duration::from_millis(50);
const SERVICE_BANNER_GRACE: Duration = Duration::from_millis(100);
/// How long to wait for a reply to the generic HTTP probe before trying the
/// next protocol-native probe. Bounded so silent peers do not consume the
/// whole probe timeout on the first probe.
const SERVICE_BANNER_HTTP_WAIT: Duration = Duration::from_millis(300);
/// Probes buffered per channel message.  Delivering every result as its own
/// message costs a cross-thread wakeup per probe and capped scan throughput at
/// roughly a third of the raw connect rate; batching trades a little buffering
/// for far fewer wakeups.
const RESULT_BATCH: usize = 64;
/// Upper bound on buffered batches so a stalled receiver cannot pin memory.
const MAX_BATCHED_MESSAGES: usize = 256;
/// Flush a partially filled batch after this long so slow, low-worker scans
/// still deliver progress and counts promptly.
const BATCH_FLUSH_INTERVAL: Duration = Duration::from_millis(50);

fn batch_channel_capacity(workers: usize) -> usize {
    workers.clamp(4, MAX_BATCHED_MESSAGES)
}

#[derive(Clone, Debug, Default)]
pub struct ProgressEvent {
    pub state: Option<PortState>,
    pub result: Option<PortResult>,
}

impl ProgressEvent {
    pub const fn state(state: PortState) -> Self {
        Self {
            state: Some(state),
            result: None,
        }
    }

    pub const fn result(state: PortState) -> Self {
        Self {
            state: Some(state),
            result: None,
        }
    }

    pub fn with_result(result: PortResult) -> Self {
        Self {
            state: Some(result.state),
            result: Some(result),
        }
    }
}

pub type ProgressCallback = Arc<dyn Fn(ProgressEvent) + Send + Sync>;

#[derive(Clone, Debug)]
pub struct ScanOptions {
    pub timeout: Duration,
    pub probe_timeout: Duration,
    pub rate: u64,
    pub workers: usize,
    pub retries: u32,
    pub randomize: bool,
    pub connect_only: bool,
    pub service_detection: bool,
    pub retain: StateSet,
    /// Ports whose `Silent` results must be kept for post-scan identification
    /// (for example RDP, which never sends an unsolicited banner).
    pub retain_silent_ports: Vec<u16>,
    /// Keep ports that completed a handshake but reset after the probe so TLS
    /// inspection can decide whether they are an HTTPS listener.
    pub retain_reset_closed: bool,
    /// Maximum random delay before each probe. Zero disables jitter.
    pub jitter: Duration,
    /// Enable adaptive rate control for connect scans.
    pub rate_auto: bool,
    /// Maximum concurrent connect attempts per target host (0 = unlimited).
    pub host_concurrency: usize,
    /// When set to `true` by an external signal handler, workers stop picking
    /// new jobs and the scan returns a partial report instead of an error.
    pub shutdown: Arc<AtomicBool>,
}

fn target_feedback(state: PortState, port: u16) -> TargetFeedback {
    match state {
        PortState::Filtered => TargetFeedback::Timeout,
        PortState::Unreachable => TargetFeedback::Unreachable,
        PortState::Silent if !accuracy::is_known_binary_port(port) => TargetFeedback::Tarpit,
        _ => TargetFeedback::Healthy,
    }
}

impl ScanOptions {
    pub(crate) fn retains(&self, result: &PortResult) -> bool {
        self.retain.contains(result.state)
            || (result.state == PortState::Silent
                && self.retain_silent_ports.contains(&result.port))
            || (self.retain_reset_closed && result.reset_during_verification())
    }
}

struct Shared {
    targets: Vec<IpAddr>,
    ports: Vec<u16>,
    options: ScanOptions,
    limiter: RateLimiter,
    rtt: Vec<Mutex<RttEstimator>>,
    /// Responses that prove the host is reachable. Used to distinguish an
    /// isolated dropped SYN from a host where every probe is filtered.
    healthy: Vec<AtomicU64>,
    /// Timeout attempts observed per target, including attempts that are
    /// retried. This keeps timeout retries proportional to observed loss.
    timeouts: Vec<AtomicU64>,
    host_gates: Vec<Semaphore>,
    jobs: u64,
}

pub async fn scan(
    targets: &[IpAddr],
    ports: &[u16],
    options: &ScanOptions,
    progress: Option<ProgressCallback>,
) -> Result<ScanReport, AppError> {
    if targets.is_empty() || ports.is_empty() {
        return Err(AppError::usage(
            "scan needs at least one target and one port",
        ));
    }

    let started = Instant::now();
    let mut targets = targets.to_vec();
    let mut ports = ports.to_vec();
    if options.randomize {
        let mut rng = rand::thread_rng();
        targets.shuffle(&mut rng);
        ports.shuffle(&mut rng);
    }

    let jobs = (targets.len() as u64)
        .checked_mul(ports.len() as u64)
        .ok_or_else(|| AppError::usage("target/port combination count overflowed"))?;
    let workers = worker_count(options.workers, jobs);
    let rtt = (0..targets.len())
        .map(|_| Mutex::new(RttEstimator::new()))
        .collect();
    let healthy = (0..targets.len()).map(|_| AtomicU64::new(0)).collect();
    let timeouts = (0..targets.len()).map(|_| AtomicU64::new(0)).collect();
    let host_gates = if options.host_concurrency > 0 {
        (0..targets.len())
            .map(|_| Semaphore::new(options.host_concurrency))
            .collect()
    } else {
        Vec::new()
    };

    let shared = Arc::new(Shared {
        targets,
        ports,
        options: options.clone(),
        limiter: RateLimiter::new(options.rate),
        rtt,
        healthy,
        timeouts,
        host_gates,
        jobs,
    });
    let next = Arc::new(AtomicU64::new(0));
    let (sender, receiver) =
        async_channel::bounded::<Vec<PortResult>>(batch_channel_capacity(workers));

    let mut adaptive = if options.rate_auto && options.rate > 0 {
        let floor = (options.rate / 10).max(1);
        Some(AdaptiveRate::new(options.rate, floor))
    } else {
        None
    };

    let mut tasks = JoinSet::new();
    // Verification pool: banner waits and active probes run outside the
    // connect workers so slow-to-banner ports cannot throttle the connect
    // pipeline (a worker slot is no longer occupied for the whole
    // connect + verify sequence). Verification is pure IO-wait, so the pool
    // is sized larger than the connect pool to absorb bursts of silent
    // or slow-banner ports.
    let verifier_count = workers.saturating_mul(4).clamp(16, 1024);
    let (ver_tx, ver_rx) =
        async_channel::bounded::<VerifyJob>(verifier_count.saturating_mul(2).max(64));
    for _ in 0..verifier_count {
        let ver_rx = ver_rx.clone();
        let sender = sender.clone();
        let shared = Arc::clone(&shared);
        tasks.spawn(async move {
            run_verifier(ver_rx, sender, shared).await;
        });
    }
    for _ in 0..workers {
        let shared = Arc::clone(&shared);
        let next = Arc::clone(&next);
        let sender = sender.clone();
        let ver_tx = ver_tx.clone();
        tasks.spawn(async move {
            run_worker(shared, next, sender, ver_tx).await;
        });
    }
    drop(sender);
    drop(ver_tx);

    let mut counts = StateCounts::default();
    let mut results = Vec::new();
    let mut probed_ports = Vec::new();
    let mut host_progress: HashMap<IpAddr, HostProgress> = HashMap::new();
    while let Ok(batch) = receiver.recv().await {
        for result in batch {
            if let Some(adaptive) = adaptive.as_mut()
                && let Some(new_rate) = adaptive.observe(target_feedback(result.state, result.port))
            {
                shared.limiter.set_rate(new_rate);
            }
            counts.add(result.state);
            probed_ports.push(result.port);
            let state = result.state;
            let host_entry = host_progress.entry(result.host).or_default();
            host_entry.ports_scanned.push(result.port);
            host_entry.counts.add(state);
            let retained = options.retains(&result);
            let res_clone = if retained { Some(result.clone()) } else { None };
            if retained {
                results.push(result);
            }
            if let Some(progress) = &progress {
                progress(ProgressEvent {
                    state: Some(state),
                    result: res_clone,
                });
            }
        }
    }

    while let Some(joined) = tasks.join_next().await {
        joined.map_err(|error| AppError::runtime(format!("scan worker failed: {error}")))?;
    }

    if counts.total() != jobs {
        // If the shutdown flag was set (Ctrl-C), return a partial report
        // instead of an error so the caller can still display results.
        let cancelled = shared.options.shutdown.load(Ordering::Relaxed);
        if !cancelled {
            return Err(AppError::runtime(format!(
                "scan incomplete: {} of {jobs} probes completed",
                counts.total()
            )));
        }
        return Ok(ScanReport {
            targets: shared.targets.len(),
            ports: shared.ports.len(),
            jobs,
            workers,
            elapsed: started.elapsed(),
            counts,
            results,
            os_fingerprints: std::collections::HashMap::new(),
            probed_ports,
            host_progress,
            partial: true,
            defense_observations: Vec::new(),
        });
    }

    Ok(ScanReport {
        targets: shared.targets.len(),
        ports: shared.ports.len(),
        jobs,
        workers,
        elapsed: started.elapsed(),
        counts,
        results,
        os_fingerprints: std::collections::HashMap::new(),
        probed_ports,
        host_progress,
        partial: false,
        defense_observations: Vec::new(),
    })
}

pub async fn verify_candidates(
    candidates: &[(IpAddr, u16)],
    options: &ScanOptions,
    progress: Option<ProgressCallback>,
) -> Result<Vec<PortResult>, AppError> {
    if candidates.is_empty() {
        return Ok(Vec::new());
    }

    let jobs = candidates.len() as u64;
    let workers = worker_count(options.workers, jobs);
    let candidates = Arc::new(candidates.to_vec());
    let options = Arc::new(options.clone());
    let limiter = Arc::new(RateLimiter::new(options.rate));
    let gates: Arc<HashMap<IpAddr, Semaphore>> = Arc::new(if options.host_concurrency > 0 {
        let mut gates = HashMap::new();
        for (host, _) in candidates.iter() {
            gates
                .entry(*host)
                .or_insert_with(|| Semaphore::new(options.host_concurrency));
        }
        gates
    } else {
        HashMap::new()
    });
    let next = Arc::new(AtomicU64::new(0));
    let (sender, receiver) =
        async_channel::bounded::<PortResult>(workers.saturating_mul(2).max(64));

    let mut tasks = JoinSet::new();
    for _ in 0..workers {
        let candidates = Arc::clone(&candidates);
        let options = Arc::clone(&options);
        let limiter = Arc::clone(&limiter);
        let gates = Arc::clone(&gates);
        let next = Arc::clone(&next);
        let sender = sender.clone();
        tasks.spawn(async move {
            loop {
                let index = next.fetch_add(1, Ordering::Relaxed);
                if index >= jobs {
                    break;
                }
                let (host, port) = candidates[index as usize];
                let _permit = match gates.get(&host) {
                    Some(gate) => Some(
                        gate.acquire()
                            .await
                            .expect("host concurrency gate stays open"),
                    ),
                    None => None,
                };
                let result = verify_candidate(&options, &limiter, host, port).await;
                if sender.send(result).await.is_err() {
                    break;
                }
            }
        });
    }
    drop(sender);

    let mut results = Vec::with_capacity(candidates.len());
    while let Ok(result) = receiver.recv().await {
        if let Some(progress) = &progress {
            progress(ProgressEvent::with_result(result.clone()));
        }
        results.push(result);
    }

    while let Some(joined) = tasks.join_next().await {
        joined
            .map_err(|error| AppError::runtime(format!("verification worker failed: {error}")))?;
    }

    Ok(results)
}

/// Ranks how strongly a verification outcome proves the port has a listener.
///
/// A completed handshake is direct evidence; a timeout on a later attempt is
/// merely absence of a reply (packet loss looks identical to filtering), so it
/// must never overwrite stronger evidence gathered by an earlier attempt.
fn evidence_rank(state: PortState) -> u8 {
    match state {
        PortState::Open => 3,
        PortState::Silent => 2,
        PortState::Closed => 1,
        PortState::Filtered | PortState::Unfiltered | PortState::Unreachable | PortState::Error => {
            0
        }
    }
}

fn prefer_best_evidence(best: Option<PortResult>, latest: PortResult) -> PortResult {
    match best {
        Some(best) if evidence_rank(best.state) > evidence_rank(latest.state) => best,
        _ => latest,
    }
}

async fn verify_candidate(
    options: &ScanOptions,
    limiter: &RateLimiter,
    host: IpAddr,
    port: u16,
) -> PortResult {
    let address = socket_addr(host, port);
    // Match the connect-scan path: a shorter ceiling than the kernel's first
    // SYN retransmit (~1s) cannot tell a lossy SYN from a filtered port.
    let timeout = options.timeout.max(MIN_CONNECT_TIMEOUT);
    let mut attempt = 0u32;
    let mut timeout_attempts = 0u32;
    let mut verify_attempts = 0u32;
    let mut best: Option<PortResult> = None;

    loop {
        limiter.acquire().await;
        apply_jitter(options.jitter).await;
        let started = Instant::now();
        let outcome = tokio::time::timeout(timeout, TcpStream::connect(address)).await;
        let elapsed = started.elapsed();

        match outcome {
            Err(_) => {
                if timeout_attempts < options.retries.min(MAX_TIMEOUT_RETRIES) {
                    timeout_attempts += 1;
                    attempt += 1;
                    tokio::time::sleep(retry_delay(attempt)).await;
                    continue;
                }
                let failure = Failure::timed_out(timeout);
                let result = PortResult::new(host, port, failure.kind.state(), elapsed)
                    .with_detail(failure.detail);
                return prefer_best_evidence(best, result);
            }
            Ok(Err(error)) => {
                let failure = classify_io_error(&error);
                if failure.kind.retryable() && attempt < options.retries {
                    attempt += 1;
                    tokio::time::sleep(retry_delay(attempt)).await;
                    continue;
                }
                let result = PortResult::new(host, port, failure.kind.state(), elapsed)
                    .with_detail(failure.detail);
                return prefer_best_evidence(best, result);
            }
            Ok(Ok(stream)) => {
                let result = verify_service(
                    stream,
                    host,
                    port,
                    elapsed,
                    options.probe_timeout,
                    options.service_detection,
                )
                .await;
                // Retry inconclusive verifications: no listener evidence
                // (closed/silent) or a port that accepted but produced no
                // service identity yet. The latter covers flaky services that
                // drop the first probe after the handshake (RSC-BUG-001 made
                // that case Open instead of Silent).
                let ambiguous = matches!(result.state, PortState::Closed | PortState::Silent)
                    || (result.state == PortState::Open && result.service.is_none());
                if ambiguous && verify_attempts < options.retries.min(MAX_VERIFICATION_RETRIES) {
                    best = Some(prefer_best_evidence(best, result));
                    verify_attempts += 1;
                    attempt += 1;
                    tokio::time::sleep(retry_delay(attempt)).await;
                    continue;
                }
                return prefer_best_evidence(best, result);
            }
        }
    }
}

async fn run_worker(
    shared: Arc<Shared>,
    next: Arc<AtomicU64>,
    sender: Sender<Vec<PortResult>>,
    verifier: Sender<VerifyJob>,
) {
    let port_count = shared.ports.len() as u64;
    let mut batch: Vec<PortResult> = Vec::with_capacity(RESULT_BATCH);
    let mut last_flush = Instant::now();

    loop {
        // Honour graceful-shutdown request (Ctrl-C via signal handler).
        if shared.options.shutdown.load(Ordering::Relaxed) {
            break;
        }

        let index = next.fetch_add(1, Ordering::Relaxed);
        if index >= shared.jobs {
            break;
        }

        let target_index = (index / port_count) as usize;
        let port_index = (index % port_count) as usize;
        let target = shared.targets[target_index];
        let port = shared.ports[port_index];
        match probe(&shared, target_index, target, port).await {
            ProbeOutcome::Result(result) => {
                batch.push(*result);
                let flush = batch.len() >= RESULT_BATCH
                    || (!batch.is_empty() && last_flush.elapsed() >= BATCH_FLUSH_INTERVAL);
                if flush {
                    last_flush = Instant::now();
                    let pending = std::mem::replace(&mut batch, Vec::with_capacity(RESULT_BATCH));
                    if sender.send(pending).await.is_err() {
                        break;
                    }
                }
            }
            ProbeOutcome::Verify(job) => {
                // Hand the connected stream to the verification pool; the
                // worker immediately continues with the next probe.
                if verifier.send(job).await.is_err() {
                    break;
                }
            }
        }
    }

    if !batch.is_empty() {
        // Deliver results collected before a shutdown or end-of-scan break so
        // the report's counts stay consistent with the probes actually sent.
        let _ = sender.send(batch).await;
    }
}

/// A connected stream waiting for banner/verification work.
struct VerifyJob {
    stream: TcpStream,
    target_index: usize,
    host: IpAddr,
    port: u16,
    latency: Duration,
}

enum ProbeOutcome {
    Result(Box<PortResult>),
    Verify(VerifyJob),
}

/// Consumes connected streams from the verification queue and emits the
/// banner-verified results into the same result channel as the workers.
async fn run_verifier(
    ver_rx: async_channel::Receiver<VerifyJob>,
    sender: Sender<Vec<PortResult>>,
    shared: Arc<Shared>,
) {
    let mut batch: Vec<PortResult> = Vec::with_capacity(RESULT_BATCH);
    let mut last_flush = Instant::now();
    while let Ok(job) = ver_rx.recv().await {
        let result = verify_connected(&shared, job).await;
        batch.push(result);
        let flush = batch.len() >= RESULT_BATCH
            || (!batch.is_empty() && last_flush.elapsed() >= BATCH_FLUSH_INTERVAL);
        if flush {
            last_flush = Instant::now();
            let pending = std::mem::replace(&mut batch, Vec::with_capacity(RESULT_BATCH));
            if sender.send(pending).await.is_err() {
                break;
            }
        }
    }
    if !batch.is_empty() {
        let _ = sender.send(batch).await;
    }
}

fn verification_is_ambiguous(result: &PortResult) -> bool {
    matches!(result.state, PortState::Closed | PortState::Silent)
        || (result.state == PortState::Open && result.service.is_none())
}

/// Verify an accepted connection, reconnecting when the peer accepted the
/// handshake but the banner was lost. Packet loss after a successful handshake
/// otherwise turns a live service into `Silent`.
async fn verify_connected(shared: &Shared, job: VerifyJob) -> PortResult {
    let mut attempt = 0u32;
    let mut best: Option<PortResult> = None;
    let mut stream = Some(job.stream);

    loop {
        let result = verify_service(
            stream.take().expect("verification stream is present"),
            job.host,
            job.port,
            job.latency,
            shared.options.probe_timeout,
            shared.options.service_detection,
        )
        .await;

        if verification_is_ambiguous(&result)
            && attempt < shared.options.retries.min(MAX_VERIFICATION_RETRIES)
        {
            diag::event(
                Level::Debug,
                "verification_retry",
                &[
                    ("target", serde_json::json!(job.host.to_string())),
                    ("port", serde_json::json!(job.port)),
                    ("attempt", serde_json::json!(attempt + 1)),
                    ("state", serde_json::json!(result.state.as_str())),
                ],
            );
            best = Some(prefer_best_evidence(best, result));
            attempt += 1;
            tokio::time::sleep(retry_delay(attempt)).await;
            match reconnect_for_verification(shared, job.target_index, job.host, job.port).await {
                Ok(new_stream) => {
                    stream = Some(new_stream);
                }
                Err(result) => return prefer_best_evidence(best, *result),
            }
            continue;
        }

        return prefer_best_evidence(best, result);
    }
}

async fn reconnect_for_verification(
    shared: &Shared,
    target_index: usize,
    host: IpAddr,
    port: u16,
) -> Result<TcpStream, Box<PortResult>> {
    let address = socket_addr(host, port);
    let mut attempt = 0u32;
    loop {
        shared.limiter.acquire().await;
        apply_jitter(shared.options.jitter).await;
        let _host_permit = match shared.host_gates.get(target_index) {
            Some(gate) => Some(
                gate.acquire()
                    .await
                    .expect("host concurrency gate stays open"),
            ),
            None => None,
        };
        let timeout = current_timeout(shared, target_index);
        let started = Instant::now();
        let outcome = tokio::time::timeout(timeout, TcpStream::connect(address)).await;
        let elapsed = started.elapsed();
        match outcome {
            Ok(Ok(stream)) => {
                record_sample(shared, target_index, elapsed);
                return Ok(stream);
            }
            Ok(Err(error)) => {
                let kind = classify_kind(&error);
                if kind.retryable() && attempt < shared.options.retries {
                    attempt += 1;
                    tokio::time::sleep(retry_delay(attempt)).await;
                    continue;
                }
                let state = kind.state();
                return Err(Box::new(result_with_detail(
                    shared,
                    state,
                    host,
                    port,
                    elapsed,
                    || classify_io_error(&error).detail,
                )));
            }
            Err(_) => {
                shared.timeouts[target_index].fetch_add(1, Ordering::Relaxed);
                if attempt < shared.options.retries.min(MAX_TIMEOUT_RETRIES) {
                    attempt += 1;
                    tokio::time::sleep(retry_delay(attempt)).await;
                    continue;
                }
                record_timeout(shared, target_index);
                return Err(Box::new(result_with_detail(
                    shared,
                    FailureKind::Filtered.state(),
                    host,
                    port,
                    elapsed,
                    || Failure::timed_out(timeout).detail,
                )));
            }
        }
    }
}

async fn apply_jitter(jitter: Duration) {
    if jitter.is_zero() {
        return;
    }
    let max_millis = jitter.as_millis().min(u128::from(u64::MAX)) as u64;
    let delay = rand::thread_rng().gen_range(0..=max_millis);
    if delay > 0 {
        tokio::time::sleep(Duration::from_millis(delay)).await;
    }
}

async fn probe(shared: &Shared, target_index: usize, host: IpAddr, port: u16) -> ProbeOutcome {
    let address = socket_addr(host, port);
    let mut attempt = 0u32;
    let mut timeout_attempts = 0u32;

    loop {
        shared.limiter.acquire().await;
        apply_jitter(shared.options.jitter).await;
        let _host_permit = match shared.host_gates.get(target_index) {
            Some(gate) => Some(
                gate.acquire()
                    .await
                    .expect("host concurrency gate stays open"),
            ),
            None => None,
        };
        let timeout = current_timeout(shared, target_index);
        let attempt_started = Instant::now();
        let outcome = tokio::time::timeout(timeout, TcpStream::connect(address)).await;
        let elapsed = attempt_started.elapsed();

        match outcome {
            Err(_) => {
                let timeout_count =
                    shared.timeouts[target_index].fetch_add(1, Ordering::Relaxed) + 1;
                let healthy = shared.healthy[target_index].load(Ordering::Relaxed);
                if should_retry_timeout(
                    healthy,
                    timeout_count,
                    timeout_attempts,
                    shared.options.retries,
                ) {
                    diag::event(
                        Level::Debug,
                        "timeout_retry",
                        &[
                            ("target", serde_json::json!(host.to_string())),
                            ("port", serde_json::json!(port)),
                            ("attempt", serde_json::json!(attempt + 1)),
                            ("healthy", serde_json::json!(healthy)),
                            ("timeouts", serde_json::json!(timeout_count)),
                        ],
                    );
                    timeout_attempts += 1;
                    attempt += 1;
                    tokio::time::sleep(retry_delay(attempt)).await;
                    continue;
                }
                record_timeout(shared, target_index);
                return ProbeOutcome::Result(Box::new(result_with_detail(
                    shared,
                    FailureKind::Filtered.state(),
                    host,
                    port,
                    elapsed,
                    || Failure::timed_out(timeout).detail,
                )));
            }
            Ok(Err(error)) => {
                let kind = classify_kind(&error);
                if kind.retryable() && attempt < shared.options.retries {
                    attempt += 1;
                    tokio::time::sleep(retry_delay(attempt)).await;
                    continue;
                }
                if kind == FailureKind::Closed {
                    record_sample(shared, target_index, elapsed);
                }
                let state = kind.state();
                return ProbeOutcome::Result(Box::new(result_with_detail(
                    shared,
                    state,
                    host,
                    port,
                    elapsed,
                    || classify_io_error(&error).detail,
                )));
            }
            Ok(Ok(stream)) => {
                record_sample(shared, target_index, elapsed);
                if shared.options.connect_only {
                    return ProbeOutcome::Result(Box::new(PortResult::new(
                        host,
                        port,
                        PortState::Open,
                        elapsed,
                    )));
                }
                return ProbeOutcome::Verify(VerifyJob {
                    stream,
                    target_index,
                    host,
                    port,
                    latency: elapsed,
                });
            }
        }
    }
}

fn current_timeout(shared: &Shared, target_index: usize) -> Duration {
    let maximum = shared.options.timeout.max(MIN_CONNECT_TIMEOUT);
    shared.rtt[target_index]
        .lock()
        .expect("RTT estimator lock poisoned")
        .timeout(MIN_CONNECT_TIMEOUT, maximum)
}

/// Retry a timed-out connect only while the host is demonstrably responding and
/// timeouts are not the dominant outcome.
///
/// A lost SYN and a filtered port look identical in isolation. Retrying every
/// timeout triples the cost of scanning a filtered host, so the policy uses
/// per-target evidence: if other probes are producing handshakes or refusals,
/// timeouts are likely packet loss and worth retrying. If timeouts dominate,
/// they are probably filtering. The first timeout is retried even without a
/// healthy sample, which covers low-worker scans and a host whose only live
/// port lost the first SYN.
fn should_retry_timeout(healthy: u64, timeouts: u64, timeout_attempts: u32, retries: u32) -> bool {
    if timeout_attempts >= retries.min(MAX_TIMEOUT_RETRIES) {
        return false;
    }
    if healthy == 0 {
        return timeouts == 1;
    }
    timeouts <= healthy
}

/// Build a result, allocating its detail string only when the state will be
/// retained.  Closed probes dominate scan volume and are dropped unless they
/// were requested, so the hot path skips one `String` allocation per probe.
fn result_with_detail(
    shared: &Shared,
    state: PortState,
    host: IpAddr,
    port: u16,
    latency: Duration,
    detail: impl FnOnce() -> String,
) -> PortResult {
    let result = PortResult::new(host, port, state, latency);
    if shared.options.retain.contains(state) {
        result.with_detail(detail())
    } else {
        result
    }
}

fn record_sample(shared: &Shared, target_index: usize, sample: Duration) {
    shared.healthy[target_index].fetch_add(1, Ordering::Relaxed);
    shared.rtt[target_index]
        .lock()
        .expect("RTT estimator lock poisoned")
        .observe(sample);
}

fn record_timeout(shared: &Shared, target_index: usize) {
    shared.rtt[target_index]
        .lock()
        .expect("RTT estimator lock poisoned")
        .on_timeout();
}

fn retry_delay(attempt: u32) -> Duration {
    let millis = 10u64.saturating_mul(1u64 << attempt.min(6));
    Duration::from_millis(millis.min(500))
}

async fn verify_service(
    stream: TcpStream,
    host: IpAddr,
    port: u16,
    latency: Duration,
    probe_timeout: Duration,
    service_detection: bool,
) -> PortResult {
    if service_detection {
        return verify_and_inspect(stream, host, port, latency, probe_timeout).await;
    }

    verify_first_byte(stream, host, port, latency, probe_timeout).await
}

async fn verify_first_byte(
    mut stream: TcpStream,
    host: IpAddr,
    port: u16,
    latency: Duration,
    probe_timeout: Duration,
) -> PortResult {
    let mut buffer = [0u8; 1];
    match tokio::time::timeout(probe_timeout, stream.read(&mut buffer)).await {
        Err(_) => PortResult::new(host, port, PortState::Silent, latency).with_detail(format!(
            "handshake succeeded but no banner arrived within {}ms",
            probe_timeout.as_millis()
        )),
        Ok(Ok(0)) => PortResult::new(host, port, PortState::Open, latency),
        Ok(Ok(_)) => PortResult::new(host, port, PortState::Open, latency),
        Ok(Err(error)) => {
            let failure = classify_io_error(&error);
            PortResult::new(host, port, failure.kind.state(), latency).with_detail(format!(
                "connection closed during verification: {}",
                failure.detail
            ))
        }
    }
}

enum ReadOutcome {
    Data,
    Timeout,
    Eof,
    Error(std::io::Error),
}

enum ReadLoopOutcome {
    Data,
    Closed,
    Error(std::io::Error),
}

async fn read_chunk(stream: &mut TcpStream, banner: &mut Vec<u8>, until: Instant) -> ReadOutcome {
    let remaining = until.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return ReadOutcome::Timeout;
    }
    let capacity = SERVICE_BANNER_LIMIT.saturating_sub(banner.len());
    if capacity == 0 {
        return ReadOutcome::Data;
    }

    let mut chunk = [0u8; 1024];
    match tokio::time::timeout(remaining, stream.read(&mut chunk)).await {
        Err(_) => ReadOutcome::Timeout,
        Ok(Ok(0)) => ReadOutcome::Eof,
        Ok(Ok(read)) => {
            banner.extend_from_slice(&chunk[..read.min(capacity)]);
            ReadOutcome::Data
        }
        Ok(Err(error)) => ReadOutcome::Error(error),
    }
}

async fn collect_banner(
    stream: &mut TcpStream,
    banner: &mut Vec<u8>,
    empty_window: Duration,
    deadline: Instant,
) -> ReadLoopOutcome {
    while Instant::now() < deadline && banner.len() < SERVICE_BANNER_LIMIT {
        let until = if banner.is_empty() {
            (Instant::now() + empty_window).min(deadline)
        } else {
            (Instant::now() + SERVICE_BANNER_IDLE).min(deadline)
        };
        match read_chunk(stream, banner, until).await {
            ReadOutcome::Data => {}
            ReadOutcome::Timeout => break,
            ReadOutcome::Eof => return ReadLoopOutcome::Closed,
            ReadOutcome::Error(error) => return ReadLoopOutcome::Error(error),
        }
    }
    ReadLoopOutcome::Data
}

async fn verify_and_inspect(
    mut stream: TcpStream,
    host: IpAddr,
    port: u16,
    latency: Duration,
    probe_timeout: Duration,
) -> PortResult {
    let started = Instant::now();
    let deadline = started + probe_timeout;
    let grace_end = started + (probe_timeout / 2).min(SERVICE_BANNER_GRACE);
    let mut banner = Vec::new();
    let mut closed = false;

    match read_chunk(&mut stream, &mut banner, grace_end).await {
        ReadOutcome::Data | ReadOutcome::Timeout => {}
        ReadOutcome::Eof => closed = true,
        ReadOutcome::Error(error) => {
            return verification_failure(host, port, latency, error, false);
        }
    }

    // Services such as SMB, MongoDB, Redis, and memcached wait for a
    // protocol-native request. Probe those ports first so their replies (and
    // version strings) are not masked by the generic HTTP probe. Port 445
    // advertises multiple SMB dialects, so a probe sequence may be needed.
    if banner.is_empty() && !closed && Instant::now() < deadline {
        for probe in service::active_probes(port) {
            if !banner.is_empty() || closed || Instant::now() >= deadline {
                break;
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            let _ = tokio::time::timeout(remaining, stream.write_all(&probe)).await;
            match collect_banner(&mut stream, &mut banner, SERVICE_BANNER_HTTP_WAIT, deadline).await
            {
                ReadLoopOutcome::Data => {}
                ReadLoopOutcome::Closed => {
                    closed = true;
                    break;
                }
                ReadLoopOutcome::Error(error) => {
                    return verification_failure(host, port, latency, error, true);
                }
            }
        }
    }

    let now = Instant::now();
    if banner.is_empty() && !closed && now < deadline && port != crate::rdp::RDP_PORT {
        let probe = service::http_probe(host);
        let remaining = deadline.saturating_duration_since(now);
        let _ = tokio::time::timeout(remaining, stream.write_all(&probe)).await;
        match collect_banner(&mut stream, &mut banner, SERVICE_BANNER_HTTP_WAIT, deadline).await {
            ReadLoopOutcome::Data => {}
            ReadLoopOutcome::Closed => closed = true,
            ReadLoopOutcome::Error(error) => {
                return verification_failure(host, port, latency, error, true);
            }
        }
    }

    // Drain remaining chunks: the peer may split its banner across reads.
    if !closed && !banner.is_empty() && banner.len() < SERVICE_BANNER_LIMIT {
        match collect_banner(&mut stream, &mut banner, SERVICE_BANNER_IDLE, deadline).await {
            ReadLoopOutcome::Data => {}
            ReadLoopOutcome::Closed => closed = true,
            ReadLoopOutcome::Error(_) => closed = true,
        }
    }

    if banner.is_empty() && !closed {
        return silent_result(host, port, latency, probe_timeout);
    }

    let detection = service::inspect(port, &banner);
    PortResult::new(host, port, PortState::Open, latency).with_detection(detection)
}

fn verification_failure(
    host: IpAddr,
    port: u16,
    latency: Duration,
    error: std::io::Error,
    probe_sent: bool,
) -> PortResult {
    let failure = classify_io_error(&error);

    // FIX RSC-BUG-001: A reset or abort received AFTER a successful TCP handshake
    // and AFTER we sent a probe payload means the port IS open - the listener
    // accepted the connection and then rejected our specific payload. That is
    // distinct from a RST-to-SYN during connect() itself, which correctly maps
    // to Closed via classify_kind() on the connect() error.
    //
    // A reset BEFORE any payload is different: an idle established connection
    // that the peer kills outright is what a SYN-proxy with no backend does
    // (and what firewalls that reset unknown clients do). The port answered
    // the handshake but refuses to carry a session, so it must not be reported
    // open; the Closed reclassification also feeds SYN-proxy detection
    // (src/defense.rs).
    let (state, detail) = if failure.kind == FailureKind::Closed {
        if probe_sent {
            (
                PortState::Open,
                format!(
                    "port accepted connection; probe rejected by listener or upstream filter ({})",
                    failure.detail
                ),
            )
        } else {
            (
                PortState::Closed,
                format!(
                    "connection reset right after the handshake and before any probe payload \
                     was sent (middlebox refusal or listener that resets idle sessions: {})",
                    failure.detail
                ),
            )
        }
    } else {
        (failure.kind.state(), failure.detail)
    };

    PortResult::new(host, port, state, latency).with_detail(detail)
}

fn silent_result(
    host: IpAddr,
    port: u16,
    latency: Duration,
    probe_timeout: Duration,
) -> PortResult {
    PortResult::new(host, port, PortState::Silent, latency).with_detail(format!(
        "handshake succeeded but no banner arrived within {}ms",
        probe_timeout.as_millis()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn options(connect_only: bool) -> ScanOptions {
        ScanOptions {
            timeout: Duration::from_secs(1),
            probe_timeout: Duration::from_millis(100),
            rate: 0,
            workers: 4,
            retries: 0,
            randomize: false,
            connect_only,
            service_detection: true,
            retain: StateSet::all(),
            retain_silent_ports: Vec::new(),
            retain_reset_closed: false,
            jitter: Duration::ZERO,
            rate_auto: false,
            host_concurrency: 0,
            shutdown: Arc::new(AtomicBool::new(false)),
        }
    }

    #[test]
    fn timeout_retries_are_bounded_and_loss_aware() {
        assert!(
            should_retry_timeout(0, 1, 0, 2),
            "an isolated first timeout may be a dropped SYN"
        );
        assert!(
            !should_retry_timeout(0, 2, 0, 2),
            "a host that only times out must not pay for extra attempts"
        );
        assert!(
            should_retry_timeout(18, 1, 0, 2),
            "one timeout among healthy responses looks like loss"
        );
        assert!(
            should_retry_timeout(18, 18, 1, 2),
            "a timeout share up to half is still treated as loss"
        );
        assert!(
            !should_retry_timeout(2, 3, 0, 2),
            "timeout-heavy hosts are assumed to filter"
        );
        assert!(
            !should_retry_timeout(18, 0, 3, 10),
            "the timeout retry budget overrides a large --retries value"
        );
    }

    #[test]
    fn target_feedback_distinguishes_pressure_from_normal_results() {
        assert_eq!(
            target_feedback(PortState::Filtered, 80),
            TargetFeedback::Timeout
        );
        assert_eq!(
            target_feedback(PortState::Unreachable, 80),
            TargetFeedback::Unreachable
        );
        assert_eq!(
            target_feedback(PortState::Silent, 9000),
            TargetFeedback::Tarpit
        );
        assert_eq!(
            target_feedback(PortState::Silent, 5432),
            TargetFeedback::Healthy,
            "expected-silent client-first services are not tarpit evidence"
        );
        assert_eq!(
            target_feedback(PortState::Open, 80),
            TargetFeedback::Healthy
        );
        assert_eq!(
            target_feedback(PortState::Closed, 80),
            TargetFeedback::Healthy
        );
    }

    #[test]
    fn retains_silent_rdp_and_reset_closed_candidates() {
        let mut options = options(false);
        options.retain = StateSet::open();
        options.retain_silent_ports = vec![3389];
        options.retain_reset_closed = true;

        assert!(options.retains(&PortResult::new(
            host(),
            3389,
            PortState::Silent,
            Duration::ZERO
        )));
        assert!(!options.retains(&PortResult::new(
            host(),
            5900,
            PortState::Silent,
            Duration::ZERO
        )));

        let reset = PortResult::new(host(), 4443, PortState::Closed, Duration::ZERO).with_detail(
            "connection closed during verification: Connection reset by peer (os error 104)",
        );
        assert!(options.retains(&reset));

        let refused = PortResult::new(host(), 4444, PortState::Closed, Duration::ZERO)
            .with_detail("connection closed during verification: Connection refused");
        assert!(!options.retains(&refused));
    }

    fn host() -> IpAddr {
        "127.0.0.1".parse().unwrap()
    }

    async fn banner_server() -> (u16, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            socket.write_all(b"hello\n").await.unwrap();
        });
        (port, task)
    }

    async fn http_server() -> (u16, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nServer: rayscan-lab\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
        });
        (port, task)
    }

    async fn request_driven_http_server() -> (u16, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut chunk = [0u8; 1024];
            loop {
                let read = socket.read(&mut chunk).await.unwrap();
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&chunk[..read]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            socket
                .write_all(
                    b"HTTP/1.0 200 OK\r\nServer: request-lab/2.0\r\nContent-Length: 0\r\n\r\n",
                )
                .await
                .unwrap();
        });
        (port, task)
    }

    async fn split_banner_server() -> (u16, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            socket.write_all(b"HTTP/1.1 200 OK\r\n").await.unwrap();
            tokio::time::sleep(Duration::from_millis(10)).await;
            socket
                .write_all(b"Server: split-lab/1.2\r\n\r\n")
                .await
                .unwrap();
        });
        (port, task)
    }

    async fn silent_server() -> (u16, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(2)).await;
            drop(socket);
        });
        (port, task)
    }

    async fn flaky_http_server() -> (u16, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            let (first, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_millis(300)).await;
            drop(first);
            let (mut second, _) = listener.accept().await.unwrap();
            second
                .write_all(b"HTTP/1.1 200 OK\r\nServer: retry-lab\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
            let mut drain = [0u8; 128];
            let _ = tokio::time::timeout(Duration::from_millis(500), second.read(&mut drain)).await;
        });
        (port, task)
    }

    async fn unused_port() -> u16 {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        listener.local_addr().unwrap().port()
    }

    /// Server that accepts the connection and immediately closes it. Models a
    /// listener (or SYN-proxy) that admits the handshake and drops the probe.
    async fn accept_then_close_server() -> (u16, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            // The scanner re-connects during verification; keep answering.
            while let Ok((socket, _)) = listener.accept().await {
                drop(socket);
            }
        });
        (port, task)
    }

    /// Accepts exactly one connection, closes it, then stops listening so any
    /// later verification attempt is refused. Models a listener that answers
    /// the first probe and is unreachable (or lossy) afterwards.
    async fn close_once_server() -> (u16, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            drop(socket);
            drop(listener);
        });
        (port, task)
    }

    #[test]
    fn best_evidence_prefers_stronger_states() {
        let open = PortResult::new(host(), 80, PortState::Open, Duration::ZERO);
        let silent = PortResult::new(host(), 80, PortState::Silent, Duration::ZERO);
        let filtered = PortResult::new(host(), 80, PortState::Filtered, Duration::ZERO);
        let closed = PortResult::new(host(), 80, PortState::Closed, Duration::ZERO);

        assert_eq!(
            prefer_best_evidence(Some(open.clone()), filtered.clone()).state,
            PortState::Open
        );
        assert_eq!(
            prefer_best_evidence(Some(silent.clone()), filtered.clone()).state,
            PortState::Silent
        );
        assert_eq!(
            prefer_best_evidence(Some(closed), filtered.clone()).state,
            PortState::Closed
        );
        assert_eq!(
            prefer_best_evidence(Some(filtered), open.clone()).state,
            PortState::Open
        );
        assert_eq!(prefer_best_evidence(None, open).state, PortState::Open);
    }

    #[test]
    fn reset_after_probe_payload_is_classified_open() {
        // RSC-BUG-001 regression: a reset that arrives after the handshake and
        // after our probe payload means the listener accepted the connection
        // and rejected the payload — never Closed.
        let error = std::io::Error::from(std::io::ErrorKind::ConnectionReset);
        let result = verification_failure(host(), 88, Duration::from_millis(5), error, true);
        assert_eq!(
            result.state,
            PortState::Open,
            "a reset after a delivered probe proves the port accepted the connection"
        );
    }

    #[test]
    fn post_handshake_abort_and_broken_pipe_are_open() {
        for kind in [
            std::io::ErrorKind::ConnectionReset,
            std::io::ErrorKind::ConnectionAborted,
            std::io::ErrorKind::BrokenPipe,
        ] {
            let error = std::io::Error::from(kind);
            let result = verification_failure(host(), 445, Duration::from_millis(5), error, true);
            assert_eq!(result.state, PortState::Open, "kind {kind:?}");
        }
    }

    #[test]
    fn reset_before_probe_payload_is_not_open() {
        // SYN-proxy with no backend (or a firewall that resets unknown
        // clients): the handshake completes, then the peer kills the idle
        // connection before any payload. That is not usable openness, and the
        // Closed reclassification is what feeds SYN-proxy detection.
        let error = std::io::Error::from(std::io::ErrorKind::ConnectionReset);
        let result = verification_failure(host(), 9003, Duration::from_millis(5), error, false);
        assert_eq!(result.state, PortState::Closed);
    }

    #[tokio::test]
    async fn peer_close_after_accept_is_open() {
        // A listener that accepts and immediately closes (EOF after the
        // handshake) must be Open, not Silent and not Closed.
        let (port, server) = accept_then_close_server().await;
        let report = scan(&[host()], &[port], &options(false), None)
            .await
            .unwrap();
        server.abort();

        assert_eq!(report.counts.open, 1);
        assert_eq!(report.results[0].state, PortState::Open);
    }

    #[tokio::test]
    async fn detects_open_and_closed_ports() {
        let (open_port, server) = banner_server().await;
        let closed_port = unused_port().await;

        let report = scan(&[host()], &[open_port, closed_port], &options(false), None)
            .await
            .unwrap();

        server.await.unwrap();
        assert_eq!(report.counts.open, 1);
        assert_eq!(report.counts.closed, 1);
        let open = report
            .results
            .iter()
            .find(|result| result.port == open_port)
            .unwrap();
        assert_eq!(open.state, PortState::Open);
        assert!(open.service.is_none());
        assert_eq!(open.banner.as_deref(), Some("hello"));
    }

    #[tokio::test]
    async fn host_concurrency_cap_scans_multiple_ports() {
        let (open_port, server) = banner_server().await;
        let closed_port = unused_port().await;
        let mut options = options(false);
        options.host_concurrency = 1;

        let report = scan(&[host()], &[open_port, closed_port], &options, None)
            .await
            .unwrap();
        server.abort();

        assert_eq!(report.counts.open, 1);
        assert_eq!(report.counts.closed, 1);
    }

    #[tokio::test]
    async fn detects_http_service_and_product() {
        let (port, server) = http_server().await;
        let report = scan(&[host()], &[port], &options(false), None)
            .await
            .unwrap();
        server.await.unwrap();

        let open = &report.results[0];
        assert_eq!(open.state, PortState::Open);
        let service = open.service.as_ref().unwrap();
        assert_eq!(service.name, "http");
        assert_eq!(service.product.as_deref(), Some("rayscan-lab"));
        assert_eq!(open.banner.as_deref(), Some("HTTP/1.1 200 OK"));
    }

    #[tokio::test]
    async fn probes_a_service_that_waits_for_a_request() {
        let (port, server) = request_driven_http_server().await;
        let mut options = options(false);
        options.probe_timeout = Duration::from_millis(300);

        let report = scan(&[host()], &[port], &options, None).await.unwrap();
        server.await.unwrap();

        let open = &report.results[0];
        assert_eq!(open.state, PortState::Open);
        let service = open.service.as_ref().unwrap();
        assert_eq!(service.name, "http");
        assert_eq!(service.product.as_deref(), Some("request-lab"));
        assert_eq!(service.version.as_deref(), Some("2.0"));
    }

    #[tokio::test]
    async fn collects_a_banner_split_across_reads() {
        let (port, server) = split_banner_server().await;
        let report = scan(&[host()], &[port], &options(false), None)
            .await
            .unwrap();
        server.await.unwrap();

        let service = report.results[0].service.as_ref().unwrap();
        assert_eq!(service.name, "http");
        assert_eq!(service.product.as_deref(), Some("split-lab"));
        assert_eq!(service.version.as_deref(), Some("1.2"));
    }

    #[tokio::test]
    async fn service_detection_can_be_disabled() {
        let (port, server) = http_server().await;
        let mut options = options(false);
        options.service_detection = false;

        let report = scan(&[host()], &[port], &options, None).await.unwrap();
        server.await.unwrap();

        let open = &report.results[0];
        assert_eq!(open.state, PortState::Open);
        assert!(open.service.is_none());
        assert!(open.banner.is_none());
    }

    #[tokio::test]
    async fn silent_handshake_is_not_reported_open() {
        let (port, server) = silent_server().await;
        let report = scan(&[host()], &[port], &options(false), None)
            .await
            .unwrap();
        server.abort();

        assert_eq!(report.counts.silent, 1);
        assert_eq!(report.counts.open, 0);
        assert_eq!(report.results[0].state, PortState::Silent);
    }

    #[tokio::test]
    async fn connect_only_reports_a_silent_handshake_as_open() {
        let (port, server) = silent_server().await;
        let report = scan(&[host()], &[port], &options(true), None)
            .await
            .unwrap();
        server.abort();

        assert_eq!(report.counts.open, 1);
        assert_eq!(report.results[0].state, PortState::Open);
    }

    #[tokio::test]
    async fn connect_scan_retries_when_the_banner_is_lost() {
        let (port, server) = flaky_http_server().await;
        let mut options = options(false);
        options.retries = 2;
        options.probe_timeout = Duration::from_millis(500);

        let report = scan(&[host()], &[port], &options, None).await.unwrap();
        server.abort();

        assert_eq!(report.counts.open, 1);
        let open = report
            .results
            .iter()
            .find(|result| result.port == port)
            .unwrap();
        assert_eq!(open.state, PortState::Open);
        assert_eq!(
            open.service
                .as_ref()
                .and_then(|service| service.product.as_deref()),
            Some("retry-lab")
        );
    }

    #[tokio::test]
    async fn verification_retries_an_ambiguous_silent_candidate() {
        let (port, server) = flaky_http_server().await;
        let mut options = options(false);
        options.probe_timeout = Duration::from_millis(500);
        options.retries = 1;

        let results = verify_candidates(&[(host(), port)], &options, None)
            .await
            .unwrap();
        server.await.unwrap();

        let result = &results[0];
        assert_eq!(result.state, PortState::Open);
        assert_eq!(
            result.service.as_ref().unwrap().product.as_deref(),
            Some("retry-lab")
        );
    }

    #[tokio::test]
    async fn verification_keeps_stronger_evidence_when_a_retry_fails() {
        // Regression for lossy paths: the first attempt completes the
        // handshake (immediate close = open listener), then the retry cannot
        // connect at all. The loss on the retry must not demote the port.
        let (port, server) = close_once_server().await;
        let mut options = options(false);
        options.retries = 1;

        let limiter = RateLimiter::new(0);
        let result = verify_candidate(&options, &limiter, host(), port).await;
        server.await.unwrap();

        assert_eq!(result.state, PortState::Open);
    }

    #[tokio::test]
    async fn verify_candidates_keeps_open_and_reclassifies_silent() {
        let (open_port, server) = banner_server().await;
        let (silent_port, silent) = silent_server().await;
        let candidates = [(host(), open_port), (host(), silent_port)];
        let mut options = options(false);
        options.host_concurrency = 1;

        let results = verify_candidates(&candidates, &options, None)
            .await
            .unwrap();

        server.await.unwrap();
        silent.abort();

        let open = results.iter().find(|r| r.port == open_port).unwrap();
        let silent = results.iter().find(|r| r.port == silent_port).unwrap();
        assert_eq!(open.state, PortState::Open);
        assert_eq!(silent.state, PortState::Silent);
    }

    #[tokio::test]
    async fn progress_callback_runs_once_per_probe() {
        let (open_port, server) = banner_server().await;
        let closed_port = unused_port().await;
        let ticks = Arc::new(AtomicU64::new(0));
        let callback = {
            let ticks = Arc::clone(&ticks);
            Arc::new(move |_event: ProgressEvent| {
                ticks.fetch_add(1, Ordering::Relaxed);
            }) as ProgressCallback
        };

        scan(
            &[host()],
            &[open_port, closed_port],
            &options(false),
            Some(callback),
        )
        .await
        .unwrap();
        server.await.unwrap();

        assert_eq!(ticks.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn reports_every_probe_across_batch_boundaries() {
        // One worker over 200 probes forces several mid-scan batch flushes plus
        // the final partial batch, so a dropped tail or miscounted batch shows
        // up immediately.
        let mut ports = Vec::with_capacity(200);
        for _ in 0..200 {
            let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
            ports.push(listener.local_addr().unwrap().port());
            drop(listener);
        }
        let mut scan_options = options(false);
        scan_options.workers = 1;
        let ticks = Arc::new(AtomicU64::new(0));
        let callback = {
            let ticks = Arc::clone(&ticks);
            Arc::new(move |_event: ProgressEvent| {
                ticks.fetch_add(1, Ordering::Relaxed);
            }) as ProgressCallback
        };

        let report = scan(&[host()], &ports, &scan_options, Some(callback))
            .await
            .unwrap();

        assert_eq!(report.counts.total(), 200);
        assert_eq!(report.probed_ports.len(), 200);
        assert_eq!(report.results.len(), 200);
        assert_eq!(ticks.load(Ordering::Relaxed), 200);
    }
}
