//! Coordinator for polling workers and push agents.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum::extract::{DefaultBodyLimit, Request, State};
use axum::http::StatusCode;
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tokio::sync::{Notify, watch};

use super::{
    Capabilities, ClaimRequest, ClaimResponse, HeartbeatRequest, JobAssignment, ResultRequest,
    bearer, build_jobs, constant_time_eq, is_loopback_listen, normalize_base, post_json,
    resolve_token, validate_report, write_report,
};
use crate::cli::DistributedServeArgs;
use crate::error::AppError;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Pull,
    Push,
}

impl Mode {
    fn as_str(self) -> &'static str {
        match self {
            Self::Pull => "pull",
            Self::Push => "push",
        }
    }
}

#[derive(Clone, Debug)]
enum JobStatus {
    Pending,
    Running {
        worker: String,
        lease_until: Instant,
    },
    Done,
    Failed,
}

struct Job {
    id: usize,
    shard_index: usize,
    shard_count: usize,
    args: Vec<String>,
    requires_raw: bool,
    timeout_secs: u64,
    attempts: u32,
    status: JobStatus,
    report: Option<Value>,
    error: Option<String>,
    elapsed_ms: u64,
    worker: Option<String>,
}

struct WorkerInfo {
    name: String,
    last_seen: Instant,
}

struct Core {
    jobs: Vec<Job>,
    workers: BTreeMap<String, WorkerInfo>,
    finishing: bool,
    complete: bool,
    report: Option<Value>,
    merge_error: Option<String>,
    discarded: u64,
}

pub struct Coordinator {
    token: String,
    core: Mutex<Core>,
    notify: Notify,
    complete_tx: watch::Sender<bool>,
    out: PathBuf,
    lease: Duration,
    max_attempts: u32,
    mode: Mode,
    started: Instant,
}

enum ClaimOutcome {
    Job(JobAssignment),
    Complete,
    Wait,
}

struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }

    fn conflict(message: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, message)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(json!({ "error": self.message }))).into_response()
    }
}

impl Coordinator {
    fn new(
        token: String,
        jobs: Vec<super::PlannedJob>,
        out: PathBuf,
        lease: Duration,
        max_attempts: u32,
        mode: Mode,
    ) -> Self {
        let (complete_tx, _) = watch::channel(false);
        let jobs = jobs
            .into_iter()
            .enumerate()
            .map(|(id, job)| Job {
                id,
                shard_index: job.shard_index,
                shard_count: job.shard_count,
                args: job.args,
                requires_raw: job.requires_raw,
                timeout_secs: job.timeout_secs,
                attempts: 0,
                status: JobStatus::Pending,
                report: None,
                error: None,
                elapsed_ms: 0,
                worker: None,
            })
            .collect();
        Self {
            token,
            core: Mutex::new(Core {
                jobs,
                workers: BTreeMap::new(),
                finishing: false,
                complete: false,
                report: None,
                merge_error: None,
                discarded: 0,
            }),
            notify: Notify::new(),
            complete_tx,
            out,
            lease,
            max_attempts,
            mode,
            started: Instant::now(),
        }
    }

    fn is_complete(&self) -> bool {
        self.core.lock().unwrap().complete
    }

    fn claim(&self, worker_id: &str, name: &str, capabilities: &Capabilities) -> ClaimOutcome {
        let now = Instant::now();
        let mut core = self.core.lock().unwrap();
        core.workers
            .entry(worker_id.to_string())
            .and_modify(|worker| {
                worker.last_seen = now;
                worker.name = name.to_string();
            })
            .or_insert_with(|| WorkerInfo {
                name: name.to_string(),
                last_seen: now,
            });
        self.prune(&mut core, now);
        if core.complete {
            return ClaimOutcome::Complete;
        }
        if core
            .jobs
            .iter()
            .all(|job| matches!(job.status, JobStatus::Done | JobStatus::Failed))
        {
            return ClaimOutcome::Complete;
        }
        let position = core.jobs.iter().position(|job| {
            matches!(job.status, JobStatus::Pending) && (!job.requires_raw || capabilities.syn)
        });
        let Some(position) = position else {
            return ClaimOutcome::Wait;
        };
        let job = &mut core.jobs[position];
        job.attempts += 1;
        job.worker = Some(worker_id.to_string());
        job.status = JobStatus::Running {
            worker: worker_id.to_string(),
            lease_until: now + self.lease,
        };
        ClaimOutcome::Job(JobAssignment {
            job_id: job.id,
            shard_index: job.shard_index,
            shard_count: job.shard_count,
            args: job.args.clone(),
            timeout_secs: job.timeout_secs,
            lease_secs: self.lease.as_secs(),
        })
    }

    fn claim_push(&self, index: usize, agent_url: &str) -> Option<JobAssignment> {
        let worker_id = format!("push-agent-{index}");
        match self.claim(&worker_id, agent_url, &Capabilities { syn: true }) {
            ClaimOutcome::Job(job) => Some(job),
            ClaimOutcome::Complete | ClaimOutcome::Wait => None,
        }
    }

    fn prune(&self, core: &mut Core, now: Instant) {
        for job in &mut core.jobs {
            let expired = matches!(
                &job.status,
                JobStatus::Running { lease_until, .. } if *lease_until <= now
            );
            if !expired {
                continue;
            }
            job.worker = None;
            if job.attempts >= self.max_attempts {
                job.status = JobStatus::Failed;
                job.error = Some(format!("lease expired after {} attempt(s)", job.attempts));
            } else {
                job.status = JobStatus::Pending;
            }
        }
    }

    fn heartbeat(&self, worker_id: &str, job_id: usize) -> bool {
        let now = Instant::now();
        let mut core = self.core.lock().unwrap();
        if let Some(worker) = core.workers.get_mut(worker_id) {
            worker.last_seen = now;
        }
        let Some(job) = core.jobs.iter_mut().find(|job| job.id == job_id) else {
            return false;
        };
        match &mut job.status {
            JobStatus::Running {
                worker,
                lease_until,
            } if worker == worker_id => {
                *lease_until = now + self.lease;
                true
            }
            JobStatus::Done | JobStatus::Failed => true,
            _ => false,
        }
    }

    fn submit(&self, request: &ResultRequest) -> Result<(), String> {
        let core = &mut *self.core.lock().unwrap();
        let job = core
            .jobs
            .iter_mut()
            .find(|job| job.id == request.job_id)
            .ok_or_else(|| format!("unknown job {}", request.job_id))?;
        match &job.status {
            JobStatus::Running { worker, .. } if worker == &request.worker_id => {}
            JobStatus::Done | JobStatus::Failed => return Ok(()),
            JobStatus::Running { worker, .. } => {
                return Err(format!(
                    "job {} is leased to worker {worker}",
                    request.job_id
                ));
            }
            JobStatus::Pending => {
                if request.report.is_none() {
                    return Err(format!(
                        "job {} is not leased to worker {}",
                        request.job_id, request.worker_id
                    ));
                }
            }
        }

        if let Some(report) = &request.report {
            validate_report(report)?;
            job.report = Some(report.clone());
            job.error = None;
            job.elapsed_ms = request.elapsed_ms;
            job.status = JobStatus::Done;
            job.worker = Some(request.worker_id.clone());
            return Ok(());
        }
        if let Some(error) = &request.error {
            job.error = Some(error.clone());
            job.elapsed_ms = request.elapsed_ms;
            job.report = None;
            job.worker = None;
            if job.attempts >= self.max_attempts {
                job.status = JobStatus::Failed;
            } else {
                job.status = JobStatus::Pending;
            }
            return Ok(());
        }
        Err("result must contain either a report or an error".to_string())
    }

    fn discard(&self) {
        self.core.lock().unwrap().discarded += 1;
    }

    async fn maintain(&self) {
        {
            let now = Instant::now();
            let mut core = self.core.lock().unwrap();
            self.prune(&mut core, now);
        }
        self.notify.notify_waiters();
        self.maybe_finish().await;
    }

    async fn maybe_finish(&self) {
        {
            let core = self.core.lock().unwrap();
            if core.complete
                || core.finishing
                || !core
                    .jobs
                    .iter()
                    .all(|job| matches!(job.status, JobStatus::Done | JobStatus::Failed))
            {
                return;
            }
        }
        let reports: Vec<Value> = {
            let mut core = self.core.lock().unwrap();
            if core.finishing || core.complete {
                return;
            }
            core.finishing = true;
            core.jobs
                .iter()
                .filter_map(|job| job.report.clone())
                .collect()
        };
        let merged = tokio::task::spawn_blocking(move || merge_reports(reports))
            .await
            .unwrap_or_else(|error| {
                Err(AppError::runtime(format!(
                    "distributed merge task failed: {error}"
                )))
            });
        {
            let mut core = self.core.lock().unwrap();
            core.finishing = false;
            core.complete = true;
            match merged {
                Ok(value) => {
                    let text = match serde_json::to_string_pretty(&value) {
                        Ok(mut text) => {
                            text.push('\n');
                            text
                        }
                        Err(error) => {
                            core.merge_error =
                                Some(format!("cannot encode merged report: {error}"));
                            String::new()
                        }
                    };
                    if !text.is_empty()
                        && let Err(error) = write_report(&self.out, &text)
                    {
                        core.merge_error = Some(error.to_string());
                    }
                    core.report = Some(value);
                }
                Err(error) => {
                    core.merge_error = Some(error.to_string());
                }
            }
        }
        let _ = self.complete_tx.send(true);
        self.notify.notify_waiters();
    }

    fn status_value(&self) -> Value {
        let core = self.core.lock().unwrap();
        let now = Instant::now();
        let mut pending = 0;
        let mut running = 0;
        let mut done = 0;
        let mut failed = 0;
        let mut elapsed = 0u64;
        for job in &core.jobs {
            elapsed += job.elapsed_ms;
            match job.status {
                JobStatus::Pending => pending += 1,
                JobStatus::Running { .. } => running += 1,
                JobStatus::Done => done += 1,
                JobStatus::Failed => failed += 1,
            }
        }
        let workers: Vec<Value> = core
            .workers
            .iter()
            .map(|(id, worker)| {
                let current = core.jobs.iter().find(|job| {
                    matches!(&job.status, JobStatus::Running { worker: owner, .. } if owner == id)
                });
                json!({
                    "id": id,
                    "name": worker.name,
                    "last_seen_ms": now.duration_since(worker.last_seen).as_millis() as u64,
                    "job_id": current.map(|job| job.id),
                    "shard_index": current.map(|job| job.shard_index),
                })
            })
            .collect();
        json!({
            "state": if core.complete { "complete" } else { "running" },
            "mode": self.mode.as_str(),
            "jobs": {
                "total": core.jobs.len(),
                "pending": pending,
                "running": running,
                "done": done,
                "failed": failed,
            },
            "workers": workers,
            "elapsed_ms": self.started.elapsed().as_millis() as u64,
            "reported_elapsed_ms": elapsed,
            "discarded_results": core.discarded,
            "out": self.out.display().to_string(),
            "error": core.merge_error,
        })
    }

    fn failure_summary(&self) -> (usize, usize, u64, Option<String>, bool) {
        let core = self.core.lock().unwrap();
        let done = core
            .jobs
            .iter()
            .filter(|job| matches!(job.status, JobStatus::Done))
            .count();
        let failed = core
            .jobs
            .iter()
            .filter(|job| matches!(job.status, JobStatus::Failed))
            .count();
        (
            done,
            failed,
            core.discarded,
            core.merge_error.clone(),
            core.report.is_some(),
        )
    }
}

fn merge_reports(reports: Vec<Value>) -> Result<Value, AppError> {
    if reports.is_empty() {
        return Err(AppError::runtime("no shard reports were produced"));
    }
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    let workspace =
        std::env::temp_dir().join(format!("rayscan-merge-{}-{stamp}", std::process::id()));
    std::fs::create_dir_all(&workspace).map_err(|error| {
        AppError::runtime(format!(
            "cannot create merge workspace {}: {error}",
            workspace.display()
        ))
    })?;
    let mut paths = Vec::with_capacity(reports.len());
    for (index, report) in reports.iter().enumerate() {
        let path = workspace.join(format!("shard-{index}.json"));
        std::fs::write(
            &path,
            serde_json::to_vec_pretty(report).map_err(|error| {
                AppError::runtime(format!("cannot encode shard report: {error}"))
            })?,
        )
        .map_err(|error| AppError::runtime(format!("cannot write {}: {error}", path.display())))?;
        paths.push(path);
    }
    let merged = crate::merge::merge_files(&paths, false);
    let _ = std::fs::remove_dir_all(&workspace);
    let text = merged?;
    serde_json::from_str(&text)
        .map_err(|error| AppError::runtime(format!("cannot parse merged report: {error}")))
}

pub async fn serve(args: DistributedServeArgs) -> Result<(), AppError> {
    let token = resolve_token(args.token)?;
    let jobs = build_jobs(&args.scan_args, args.shards, args.job_timeout_secs)?;
    let lease = Duration::from_secs(args.lease_secs.clamp(5, 86_400));
    let agents: Vec<String> = args
        .agents
        .iter()
        .map(|agent| normalize_base(agent))
        .collect::<Result<_, _>>()?;
    let mode = if agents.is_empty() {
        Mode::Pull
    } else {
        Mode::Push
    };
    let coordinator = Arc::new(Coordinator::new(
        token,
        jobs,
        args.out.clone(),
        lease,
        args.max_attempts.max(1),
        mode,
    ));

    let app = Router::new()
        .route("/v1/claim", post(claim_handler))
        .route("/v1/heartbeat", post(heartbeat_handler))
        .route("/v1/result", post(result_handler))
        .route("/v1/status", get(status_handler))
        .route("/v1/report", get(report_handler))
        .route("/v1/healthz", get(health_handler))
        .with_state(coordinator.clone())
        .layer(DefaultBodyLimit::max(256 * 1024 * 1024))
        .layer(middleware::from_fn_with_state(
            coordinator.clone(),
            authorize,
        ));

    let listener = TcpListener::bind(&args.listen)
        .await
        .map_err(|error| AppError::runtime(format!("cannot listen on {}: {error}", args.listen)))?;
    if !is_loopback_listen(&args.listen) {
        eprintln!(
            "[distributed] warning: {} is not a loopback address; the bearer token travels over \
             plaintext HTTP. Terminate TLS in front of the coordinator or use a trusted network.",
            args.listen
        );
    }
    eprintln!(
        "[distributed] coordinator on http://{}/ ({} shard jobs, mode={})",
        args.listen,
        coordinator.core.lock().unwrap().jobs.len(),
        mode.as_str()
    );

    if mode == Mode::Push {
        for (index, agent) in agents.into_iter().enumerate() {
            spawn_push_loop(coordinator.clone(), index, agent);
        }
    }

    let maintenance = coordinator.clone();
    tokio::spawn(async move {
        loop {
            if maintenance.is_complete() {
                break;
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
            maintenance.maintain().await;
        }
    });

    let shutdown = coordinator.clone();
    let mut complete_rx = coordinator.complete_tx.subscribe();
    let serve_result = axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            loop {
                if *complete_rx.borrow() {
                    return;
                }
                tokio::select! {
                    changed = complete_rx.changed() => {
                        if changed.is_err() {
                            return;
                        }
                    }
                    _ = tokio::signal::ctrl_c() => return,
                }
            }
        })
        .await;
    serve_result.map_err(|error| AppError::runtime(format!("coordinator failed: {error}")))?;

    if !shutdown.is_complete() {
        eprintln!("[distributed] stopped before all shards completed");
        return Ok(());
    }
    let (done, failed, discarded, merge_error, report_ready) = shutdown.failure_summary();
    eprintln!(
        "[distributed] complete: {done} shard(s) done, {failed} failed, {discarded} stale result(s) discarded"
    );
    if let Some(error) = merge_error {
        return Err(AppError::runtime(format!(
            "cannot merge shard reports: {error}"
        )));
    }
    if failed > 0 {
        return Err(AppError::runtime(format!(
            "{failed} shard(s) failed; partial report written to {}",
            args.out.display()
        )));
    }
    if report_ready {
        eprintln!("[distributed] wrote {}", args.out.display());
    }
    Ok(())
}

fn spawn_push_loop(coordinator: Arc<Coordinator>, index: usize, agent: String) {
    tokio::spawn(async move {
        let agent = match normalize_base(&agent) {
            Ok(agent) => agent,
            Err(error) => {
                eprintln!("[distributed] agent {index}: {error}");
                return;
            }
        };
        let worker_id = format!("push-agent-{index}");
        loop {
            if coordinator.is_complete() {
                break;
            }
            let assignment = coordinator.claim_push(index, &agent);
            let Some(job) = assignment else {
                if coordinator.is_complete() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
                continue;
            };
            let job_id = job.job_id;
            let timeout = Duration::from_secs(job.timeout_secs.saturating_add(60).max(60));
            let token = coordinator.token.clone();
            let agent_url = agent.clone();
            let body = json!({ "job": job });
            let response = tokio::task::spawn_blocking(move || {
                post_json(&agent_url, &token, "/v1/execute", &body, timeout)
            })
            .await;
            let mut stale = false;
            match response {
                Ok(Ok(value)) => {
                    if let Some(report) = value.get("report") {
                        let request = ResultRequest {
                            worker_id: worker_id.clone(),
                            job_id,
                            report: Some(report.clone()),
                            error: None,
                            elapsed_ms: value
                                .get("elapsed_ms")
                                .and_then(Value::as_u64)
                                .unwrap_or(0),
                        };
                        if coordinator.submit(&request).is_err() {
                            stale = true;
                        }
                    } else {
                        let request = ResultRequest {
                            worker_id: worker_id.clone(),
                            job_id,
                            report: None,
                            error: Some("agent returned no report".to_string()),
                            elapsed_ms: 0,
                        };
                        if coordinator.submit(&request).is_err() {
                            stale = true;
                        }
                    }
                }
                Ok(Err(error)) => {
                    let request = ResultRequest {
                        worker_id: worker_id.clone(),
                        job_id,
                        report: None,
                        error: Some(error),
                        elapsed_ms: 0,
                    };
                    if coordinator.submit(&request).is_err() {
                        stale = true;
                    }
                }
                Err(error) => {
                    let request = ResultRequest {
                        worker_id: worker_id.clone(),
                        job_id,
                        report: None,
                        error: Some(format!("push task failed: {error}")),
                        elapsed_ms: 0,
                    };
                    if coordinator.submit(&request).is_err() {
                        stale = true;
                    }
                }
            }
            if stale {
                coordinator.discard();
            }
            coordinator.maintain().await;
        }
    });
}

async fn authorize(
    State(coordinator): State<Arc<Coordinator>>,
    request: Request,
    next: Next,
) -> Response {
    match bearer(request.headers()) {
        Some(token) if constant_time_eq(&coordinator.token, token) => next.run(request).await,
        _ => ApiError::new(StatusCode::UNAUTHORIZED, "invalid or missing bearer token")
            .into_response(),
    }
}

async fn health_handler() -> Json<Value> {
    Json(json!({ "ok": true }))
}

async fn claim_handler(
    State(coordinator): State<Arc<Coordinator>>,
    Json(request): Json<ClaimRequest>,
) -> Result<Json<ClaimResponse>, ApiError> {
    if coordinator.mode == Mode::Push {
        return Err(ApiError::conflict(
            "coordinator is in push mode; use a push agent instead of a polling worker",
        ));
    }
    if request.worker_id.trim().is_empty() || request.worker_id.len() > 256 {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            "worker_id must be between 1 and 256 characters",
        ));
    }
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        match coordinator.claim(&request.worker_id, &request.name, &request.capabilities) {
            ClaimOutcome::Job(job) => {
                return Ok(Json(ClaimResponse {
                    job: Some(job),
                    complete: false,
                }));
            }
            ClaimOutcome::Complete => {
                coordinator.maybe_finish().await;
                return Ok(Json(ClaimResponse {
                    job: None,
                    complete: true,
                }));
            }
            ClaimOutcome::Wait => {}
        }
        if coordinator.is_complete() {
            return Ok(Json(ClaimResponse {
                job: None,
                complete: true,
            }));
        }
        if Instant::now() >= deadline {
            return Ok(Json(ClaimResponse {
                job: None,
                complete: coordinator.is_complete(),
            }));
        }
        let _ = tokio::time::timeout(Duration::from_secs(1), coordinator.notify.notified()).await;
    }
}

async fn heartbeat_handler(
    State(coordinator): State<Arc<Coordinator>>,
    Json(request): Json<HeartbeatRequest>,
) -> Result<Json<Value>, ApiError> {
    if coordinator.heartbeat(&request.worker_id, request.job_id) {
        Ok(Json(json!({ "ok": true })))
    } else {
        Err(ApiError::conflict(format!(
            "job {} is not leased to worker {}",
            request.job_id, request.worker_id
        )))
    }
}

async fn result_handler(
    State(coordinator): State<Arc<Coordinator>>,
    Json(request): Json<ResultRequest>,
) -> Result<Json<Value>, ApiError> {
    match coordinator.submit(&request) {
        Ok(()) => {
            coordinator.maintain().await;
            Ok(Json(json!({
                "accepted": true,
                "complete": coordinator.is_complete(),
            })))
        }
        Err(error) => Err(ApiError::conflict(error)),
    }
}

async fn status_handler(State(coordinator): State<Arc<Coordinator>>) -> Json<Value> {
    Json(coordinator.status_value())
}

async fn report_handler(State(coordinator): State<Arc<Coordinator>>) -> Response {
    let core = coordinator.core.lock().unwrap();
    if core.complete {
        match &core.report {
            Some(report) => Json(report.clone()).into_response(),
            None => ApiError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                core.merge_error
                    .clone()
                    .unwrap_or_else(|| "no merged report is available".to_string()),
            )
            .into_response(),
        }
    } else {
        drop(core);
        (StatusCode::CONFLICT, Json(coordinator.status_value())).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::distributed::PlannedJob;

    fn job(index: usize, requires_raw: bool) -> PlannedJob {
        PlannedJob {
            shard_index: index,
            shard_count: 2,
            args: vec!["scan".into(), "--target".into(), "127.0.0.1".into()],
            requires_raw,
            timeout_secs: 60,
        }
    }

    fn report(port: u16) -> Value {
        json!({
            "target": "127.0.0.1",
            "targets": 1,
            "ports": 1,
            "open": [{
                "host": "127.0.0.1",
                "port": port,
                "state": "open",
                "confidence": 95
            }],
            "summary": {
                "open": 1,
                "closed": 0,
                "filtered": 0,
                "silent": 0,
                "unreachable": 0,
                "error": 0
            }
        })
    }

    fn coordinator(jobs: Vec<PlannedJob>) -> (Coordinator, PathBuf) {
        let out = std::env::temp_dir().join(format!(
            "rayscan-coordinator-test-{}-{}.json",
            std::process::id(),
            rand::random::<u64>()
        ));
        (
            Coordinator::new(
                "test-token-0123456789".to_string(),
                jobs,
                out.clone(),
                Duration::from_secs(30),
                2,
                Mode::Pull,
            ),
            out,
        )
    }

    #[test]
    fn raw_jobs_wait_for_capable_workers() {
        let (coordinator, _) = coordinator(vec![job(0, true), job(1, false)]);
        let no_raw = Capabilities { syn: false };
        let ClaimOutcome::Job(assignment) = coordinator.claim("worker-a", "a", &no_raw) else {
            panic!("expected the non-raw job");
        };
        assert_eq!(assignment.shard_index, 1);
        assert!(matches!(
            coordinator.claim("worker-a", "a", &no_raw),
            ClaimOutcome::Wait
        ));
        let raw = Capabilities { syn: true };
        assert!(matches!(
            coordinator.claim("worker-b", "b", &raw),
            ClaimOutcome::Job(_)
        ));
    }

    #[test]
    fn failed_jobs_are_requeued_then_completed() {
        let (coordinator, _) = coordinator(vec![job(0, false)]);
        let ClaimOutcome::Job(assignment) =
            coordinator.claim("worker-a", "a", &Capabilities::default())
        else {
            panic!("expected a job");
        };
        let request = ResultRequest {
            worker_id: "worker-a".into(),
            job_id: assignment.job_id,
            report: None,
            error: Some("boom".into()),
            elapsed_ms: 5,
        };
        coordinator.submit(&request).unwrap();
        let ClaimOutcome::Job(assignment) =
            coordinator.claim("worker-b", "b", &Capabilities::default())
        else {
            panic!("expected a retry");
        };
        let request = ResultRequest {
            worker_id: "worker-b".into(),
            job_id: assignment.job_id,
            report: Some(report(80)),
            error: None,
            elapsed_ms: 10,
        };
        coordinator.submit(&request).unwrap();
        assert!(
            coordinator
                .core
                .lock()
                .unwrap()
                .jobs
                .iter()
                .all(|job| matches!(job.status, JobStatus::Done))
        );
    }

    #[test]
    fn duplicate_results_are_idempotent() {
        let (coordinator, _) = coordinator(vec![job(0, false)]);
        let ClaimOutcome::Job(assignment) =
            coordinator.claim("worker-a", "a", &Capabilities::default())
        else {
            panic!("expected a job");
        };
        let request = ResultRequest {
            worker_id: "worker-a".into(),
            job_id: assignment.job_id,
            report: Some(report(443)),
            error: None,
            elapsed_ms: 10,
        };
        coordinator.submit(&request).unwrap();
        coordinator.submit(&request).unwrap();
    }

    #[tokio::test]
    async fn completed_shards_merge_and_write_report() {
        let (coordinator, out) = coordinator(vec![job(0, false)]);
        let ClaimOutcome::Job(assignment) =
            coordinator.claim("worker-a", "a", &Capabilities::default())
        else {
            panic!("expected a job");
        };
        let request = ResultRequest {
            worker_id: "worker-a".into(),
            job_id: assignment.job_id,
            report: Some(report(80)),
            error: None,
            elapsed_ms: 10,
        };
        coordinator.submit(&request).unwrap();
        coordinator.maintain().await;
        assert!(coordinator.is_complete());
        let merged: Value = serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
        assert_eq!(merged["open"].as_array().unwrap().len(), 1);
        assert_eq!(merged["open"][0]["port"], 80);
        let _ = std::fs::remove_file(out);
    }

    #[test]
    fn reports_must_be_objects() {
        let (coordinator, _) = coordinator(vec![job(0, false)]);
        let ClaimOutcome::Job(assignment) =
            coordinator.claim("worker-a", "a", &Capabilities::default())
        else {
            panic!("expected a job");
        };
        let request = ResultRequest {
            worker_id: "worker-a".into(),
            job_id: assignment.job_id,
            report: Some(json!([1, 2, 3])),
            error: None,
            elapsed_ms: 1,
        };
        assert!(coordinator.submit(&request).is_err());
    }
}
