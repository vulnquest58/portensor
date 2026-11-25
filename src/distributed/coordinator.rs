//! Coordinator for polling workers and push agents.

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum::extract::{DefaultBodyLimit, Request, State};
use axum::http::{StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;
use tokio::sync::{Notify, Semaphore, watch};

use super::tls::{self, ClientTls, TlsListener};
use super::{
    Capabilities, ClaimRequest, ClaimResponse, HeartbeatRequest, JobAssignment, ResultRequest,
    bearer, build_jobs, constant_time_eq, is_loopback_listen, normalize_base, post_json,
    resolve_token, validate_report,
};
use crate::cli::DistributedServeArgs;
use crate::diag::{self, Level};
use crate::error::AppError;

/// Bound simultaneous control-plane requests. Long-poll claims, result
/// uploads, status checks, and report downloads all share this budget.
const MAX_INFLIGHT_REQUESTS: usize = 128;
const STATE_SCHEMA_VERSION: u32 = 1;
const SPLIT_AFTER_MS: u64 = 2_000;
const MAX_SPLIT_PARTS: usize = 8;

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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum JobStatus {
    Pending,
    Running {
        worker: String,
        lease_expires_unix_ms: u64,
    },
    Done,
    Failed,
    Superseded,
}

#[derive(Clone)]
struct Job {
    id: usize,
    shard_index: usize,
    shard_count: usize,
    args: Vec<String>,
    args_digest: String,
    requires_raw: bool,
    timeout_secs: u64,
    attempts: u32,
    status: JobStatus,
    report: Option<Value>,
    result_digest: Option<String>,
    result_path: Option<PathBuf>,
    error: Option<String>,
    elapsed_ms: u64,
    worker: Option<String>,
    started_unix_ms: Option<u64>,
    parent_job_id: Option<usize>,
    work_part: Option<(u32, u32)>,
}

#[derive(Clone)]
struct WorkerInfo {
    name: String,
    last_seen: Instant,
}

#[derive(Clone)]
struct Core {
    jobs: Vec<Job>,
    workers: BTreeMap<String, WorkerInfo>,
    run_id: String,
    coordinator_id: String,
    restart_count: u64,
    finishing: bool,
    complete: bool,
    ready: bool,
    report: Option<Value>,
    report_digest: Option<String>,
    merge_error: Option<String>,
    storage_error: Option<String>,
    discarded: u64,
    expired_leases: u64,
    duplicate_results: u64,
    merge_failures: u64,
}

pub struct Coordinator {
    token: String,
    core: Mutex<Core>,
    requests: Arc<Semaphore>,
    notify: Notify,
    complete_tx: watch::Sender<bool>,
    out: PathBuf,
    store: StateStore,
    lease: Duration,
    max_attempts: u32,
    mode: Mode,
    started: Instant,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum PersistedStatus {
    Pending,
    Running,
    Done,
    Failed,
    Superseded,
}

#[derive(Clone, Copy, Serialize, Deserialize)]
struct PersistedUnit {
    index: u32,
    count: u32,
}

#[derive(Clone, Serialize, Deserialize)]
struct PersistedJob {
    id: usize,
    shard_index: usize,
    shard_count: usize,
    args_digest: String,
    status: PersistedStatus,
    worker: Option<String>,
    lease_expires_unix_ms: Option<u64>,
    #[serde(default)]
    started_unix_ms: Option<u64>,
    #[serde(default)]
    parent_job_id: Option<usize>,
    #[serde(default)]
    unit: Option<PersistedUnit>,
    attempts: u32,
    result_digest: Option<String>,
    result_path: Option<PathBuf>,
    error: Option<String>,
    elapsed_ms: u64,
}

#[derive(Clone, Serialize, Deserialize)]
struct PersistedReport {
    path: PathBuf,
    digest: Option<String>,
    ready: bool,
}

#[derive(Clone, Serialize, Deserialize)]
struct PersistedState {
    schema_version: u32,
    coordinator_id: String,
    run_id: String,
    restart_count: u64,
    finishing: bool,
    complete: bool,
    jobs: Vec<PersistedJob>,
    report: PersistedReport,
}

struct StateStore {
    state_path: PathBuf,
    result_dir: PathBuf,
    out: PathBuf,
    _lock: FileLock,
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

#[derive(Debug)]
enum SubmitError {
    Conflict(String),
    Storage(String),
}

impl SubmitError {
    fn into_api(self) -> ApiError {
        match self {
            Self::Conflict(message) => ApiError::conflict(message),
            Self::Storage(message) => ApiError::new(StatusCode::SERVICE_UNAVAILABLE, message),
        }
    }
}

struct OrphanResult {
    digest: String,
    path: PathBuf,
    report: Value,
}

struct FileLock {
    file: File,
}

impl FileLock {
    fn acquire(path: &Path) -> Result<Self, AppError> {
        create_private_dir(path.parent().unwrap_or(Path::new(".")))?;
        let mut options = OpenOptions::new();
        options.create(true).read(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(path).map_err(|error| {
            AppError::runtime(format!(
                "cannot open coordinator lock {}: {error}",
                path.display()
            ))
        })?;
        lock_exclusive(&file).map_err(|error| {
            AppError::runtime(format!(
                "cannot lock coordinator state {}: {error}; another coordinator may own this state/output pair",
                path.display()
            ))
        })?;
        Ok(Self { file })
    }
}

impl Drop for FileLock {
    fn drop(&mut self) {
        unlock(&self.file);
    }
}

#[cfg(unix)]
fn lock_exclusive(file: &File) -> std::io::Result<()> {
    use std::os::unix::io::AsRawFd;
    let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(unix)]
fn unlock(file: &File) {
    use std::os::unix::io::AsRawFd;
    unsafe {
        libc::flock(file.as_raw_fd(), libc::LOCK_UN);
    }
}

#[cfg(windows)]
#[repr(C)]
struct Overlapped {
    internal: usize,
    internal_high: usize,
    offset: u32,
    offset_high: u32,
    event: *mut std::ffi::c_void,
}

#[cfg(windows)]
unsafe extern "system" {
    fn LockFileEx(
        file: *mut std::ffi::c_void,
        flags: u32,
        reserved: u32,
        bytes_low: u32,
        bytes_high: u32,
        overlapped: *mut Overlapped,
    ) -> i32;
    fn UnlockFileEx(
        file: *mut std::ffi::c_void,
        reserved: u32,
        bytes_low: u32,
        bytes_high: u32,
        overlapped: *mut Overlapped,
    ) -> i32;
}

#[cfg(windows)]
fn lock_exclusive(file: &File) -> std::io::Result<()> {
    use std::os::windows::io::AsRawHandle;
    const LOCKFILE_EXCLUSIVE_LOCK: u32 = 0x0000_0002;
    const LOCKFILE_FAIL_IMMEDIATELY: u32 = 0x0000_0001;
    let mut overlapped = Overlapped {
        internal: 0,
        internal_high: 0,
        offset: 0,
        offset_high: 0,
        event: std::ptr::null_mut(),
    };
    let result = unsafe {
        LockFileEx(
            file.as_raw_handle() as *mut std::ffi::c_void,
            LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
            0,
            1,
            0,
            &mut overlapped,
        )
    };
    if result != 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(windows)]
fn unlock(file: &File) {
    use std::os::windows::io::AsRawHandle;
    let mut overlapped = Overlapped {
        internal: 0,
        internal_high: 0,
        offset: 0,
        offset_high: 0,
        event: std::ptr::null_mut(),
    };
    unsafe {
        UnlockFileEx(
            file.as_raw_handle() as *mut std::ffi::c_void,
            0,
            1,
            0,
            &mut overlapped,
        );
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn args_digest(args: &[String]) -> String {
    sha256_hex(args.join("\0").as_bytes())
}

fn work_part_args(args: &[String], index: u32, count: u32) -> Vec<String> {
    let mut split = Vec::with_capacity(args.len() + 4);
    let mut skip = false;
    for arg in args {
        if skip {
            skip = false;
            continue;
        }
        if matches!(
            arg.as_str(),
            "--work-part-index" | "--work-part-count" | "--work-part-index=" | "--work-part-count="
        ) {
            skip = !arg.contains('=');
            continue;
        }
        if arg.starts_with("--work-part-index=") || arg.starts_with("--work-part-count=") {
            continue;
        }
        split.push(arg.clone());
    }
    split.push("--work-part-index".to_string());
    split.push(index.to_string());
    split.push("--work-part-count".to_string());
    split.push(count.to_string());
    split
}

fn new_id(prefix: &str) -> String {
    format!(
        "portensor-{prefix}-{}-{:016x}",
        std::process::id(),
        rand::random::<u64>()
    )
}

fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

fn create_private_dir(path: &Path) -> Result<(), AppError> {
    if path.as_os_str().is_empty() {
        return Ok(());
    }
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path).map_err(|error| {
        AppError::runtime(format!(
            "cannot create coordinator directory {}: {error}",
            path.display()
        ))
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700));
    }
    Ok(())
}

fn sync_parent(path: &Path) {
    #[cfg(not(unix))]
    let _ = path;
    #[cfg(unix)]
    {
        if let Some(parent) = path.parent()
            && let Ok(directory) = File::open(parent)
        {
            let _ = directory.sync_all();
        }
    }
}

fn atomic_write(path: &Path, bytes: &[u8], private: bool) -> Result<(), AppError> {
    let parent = path.parent().filter(|path| !path.as_os_str().is_empty());
    if let Some(parent) = parent {
        if private {
            create_private_dir(parent)?;
        } else {
            std::fs::create_dir_all(parent).map_err(|error| {
                AppError::runtime(format!(
                    "cannot create output directory {}: {error}",
                    parent.display()
                ))
            })?;
        }
    }
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("state");
    let temporary = path.with_file_name(format!(
        ".{file_name}.tmp-{}-{:016x}",
        std::process::id(),
        rand::random::<u64>()
    ));
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    if private {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let result = (|| {
        let mut file = options.open(&temporary).map_err(|error| {
            AppError::runtime(format!(
                "cannot create temporary file {}: {error}",
                temporary.display()
            ))
        })?;
        file.write_all(bytes).map_err(|error| {
            AppError::runtime(format!(
                "cannot write temporary file {}: {error}",
                temporary.display()
            ))
        })?;
        file.sync_all().map_err(|error| {
            AppError::runtime(format!(
                "cannot sync temporary file {}: {error}",
                temporary.display()
            ))
        })?;
        std::fs::rename(&temporary, path).map_err(|error| {
            AppError::runtime(format!(
                "cannot replace {} atomically: {error}",
                path.display()
            ))
        })?;
        sync_parent(path);
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

impl StateStore {
    fn open(state_path: &Path, out: &Path) -> Result<Self, AppError> {
        if let Some(parent) = state_path.parent() {
            create_private_dir(parent)?;
        }
        let result_dir = PathBuf::from(format!("{}.d", state_path.display()));
        create_private_dir(&result_dir)?;
        let lock_path = PathBuf::from(format!("{}.lock", state_path.display()));
        let lock = FileLock::acquire(&lock_path)?;
        Ok(Self {
            state_path: state_path.to_path_buf(),
            result_dir,
            out: out.to_path_buf(),
            _lock: lock,
        })
    }

    fn load(&self) -> Result<Option<PersistedState>, AppError> {
        let bytes = match std::fs::read(&self.state_path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => {
                return Err(AppError::runtime(format!(
                    "cannot read coordinator state {}: {error}",
                    self.state_path.display()
                )));
            }
        };
        let state: PersistedState = serde_json::from_slice(&bytes).map_err(|error| {
            AppError::runtime(format!(
                "cannot parse coordinator state {}: {error}",
                self.state_path.display()
            ))
        })?;
        if state.schema_version != STATE_SCHEMA_VERSION {
            return Err(AppError::runtime(format!(
                "unsupported coordinator state schema {} in {} (expected {})",
                state.schema_version,
                self.state_path.display(),
                STATE_SCHEMA_VERSION
            )));
        }
        if state.report.path != self.out {
            return Err(AppError::runtime(format!(
                "coordinator state {} belongs to output {}, not {}",
                self.state_path.display(),
                state.report.path.display(),
                self.out.display()
            )));
        }
        Ok(Some(state))
    }

    fn save(&self, state: &PersistedState) -> Result<(), AppError> {
        let mut bytes = serde_json::to_vec_pretty(state).map_err(|error| {
            AppError::runtime(format!("cannot encode coordinator state: {error}"))
        })?;
        bytes.push(b'\n');
        atomic_write(&self.state_path, &bytes, true)
    }

    fn write_result(&self, job_id: usize, digest: &str, bytes: &[u8]) -> Result<PathBuf, AppError> {
        let path = self.result_dir.join(format!("{job_id}-{digest}.json"));
        atomic_write(&path, bytes, true)?;
        Ok(path)
    }

    fn read_result(&self, job_id: usize, digest: &str) -> Result<Value, AppError> {
        let path = self.result_dir.join(format!("{job_id}-{digest}.json"));
        let bytes = std::fs::read(&path).map_err(|error| {
            AppError::runtime(format!(
                "cannot read durable result {}: {error}",
                path.display()
            ))
        })?;
        if sha256_hex(&bytes) != digest {
            return Err(AppError::runtime(format!(
                "durable result digest mismatch for {}",
                path.display()
            )));
        }
        let report: Value = serde_json::from_slice(&bytes).map_err(|error| {
            AppError::runtime(format!(
                "cannot parse durable result {}: {error}",
                path.display()
            ))
        })?;
        validate_report(&report).map_err(|error| {
            AppError::runtime(format!(
                "invalid durable result {}: {error}",
                path.display()
            ))
        })?;
        Ok(report)
    }

    fn orphan_results(&self) -> Result<BTreeMap<usize, Vec<OrphanResult>>, AppError> {
        let mut results: BTreeMap<usize, Vec<OrphanResult>> = BTreeMap::new();
        let entries = match std::fs::read_dir(&self.result_dir) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(results),
            Err(error) => {
                return Err(AppError::runtime(format!(
                    "cannot scan coordinator result directory {}: {error}",
                    self.result_dir.display()
                )));
            }
        };
        for entry in entries {
            let entry = entry.map_err(|error| {
                AppError::runtime(format!(
                    "cannot read coordinator result directory entry: {error}"
                ))
            })?;
            let path = entry.path();
            let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            let Some(stem) = name.strip_suffix(".json") else {
                continue;
            };
            let Some((job, digest)) = stem.split_once('-') else {
                continue;
            };
            let Ok(job_id) = job.parse::<usize>() else {
                continue;
            };
            if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                continue;
            }
            let bytes = std::fs::read(&path).map_err(|error| {
                AppError::runtime(format!(
                    "cannot read durable result {}: {error}",
                    path.display()
                ))
            })?;
            if sha256_hex(&bytes) != digest {
                return Err(AppError::runtime(format!(
                    "durable result digest mismatch for {}",
                    path.display()
                )));
            }
            let report: Value = serde_json::from_slice(&bytes).map_err(|error| {
                AppError::runtime(format!(
                    "cannot parse durable result {}: {error}",
                    path.display()
                ))
            })?;
            validate_report(&report).map_err(|error| {
                AppError::runtime(format!(
                    "invalid durable result {}: {error}",
                    path.display()
                ))
            })?;
            results.entry(job_id).or_default().push(OrphanResult {
                digest: digest.to_string(),
                path,
                report,
            });
        }
        Ok(results)
    }
}

impl Coordinator {
    fn open(
        token: String,
        planned: Vec<super::PlannedJob>,
        out: PathBuf,
        state_path: PathBuf,
        lease: Duration,
        max_attempts: u32,
        mode: Mode,
    ) -> Result<Self, AppError> {
        let store = StateStore::open(&state_path, &out)?;
        let jobs: Vec<Job> = planned
            .into_iter()
            .enumerate()
            .map(|(id, job)| Job {
                id,
                shard_index: job.shard_index,
                shard_count: job.shard_count,
                args_digest: args_digest(&job.args),
                args: job.args,
                requires_raw: job.requires_raw,
                timeout_secs: job.timeout_secs,
                attempts: 0,
                status: JobStatus::Pending,
                report: None,
                result_digest: None,
                result_path: None,
                error: None,
                elapsed_ms: 0,
                worker: None,
                started_unix_ms: None,
                parent_job_id: None,
                work_part: None,
            })
            .collect();
        let (complete_tx, _) = watch::channel(false);
        let mut core = Core {
            jobs,
            workers: BTreeMap::new(),
            run_id: new_id("run"),
            coordinator_id: new_id("coordinator"),
            restart_count: 0,
            finishing: false,
            complete: false,
            ready: false,
            report: None,
            report_digest: None,
            merge_error: None,
            storage_error: None,
            discarded: 0,
            expired_leases: 0,
            duplicate_results: 0,
            merge_failures: 0,
        };
        if let Some(state) = store.load()? {
            restore_state(&mut core, state, &store, max_attempts)?;
        }
        if !core.complete
            && (core.finishing
                || core.jobs.iter().all(|job| {
                    matches!(
                        job.status,
                        JobStatus::Done | JobStatus::Failed | JobStatus::Superseded
                    )
                }))
        {
            recover_merge(&mut core, &store, &out)?;
        }
        core.ready = true;
        store.save(&snapshot(&core, &out))?;
        Ok(Self {
            token,
            core: Mutex::new(core),
            requests: Arc::new(Semaphore::new(MAX_INFLIGHT_REQUESTS)),
            notify: Notify::new(),
            complete_tx,
            out,
            store,
            lease,
            max_attempts,
            mode,
            started: Instant::now(),
        })
    }

    fn persist(&self, core: &Core) -> Result<(), String> {
        self.store
            .save(&snapshot(core, &self.out))
            .map_err(|error| error.to_string())
    }

    fn is_complete(&self) -> bool {
        self.core.lock().unwrap().complete
    }

    fn claim(
        &self,
        worker_id: &str,
        name: &str,
        capabilities: &Capabilities,
    ) -> Result<ClaimOutcome, String> {
        let now = Instant::now();
        let mut core = self.core.lock().unwrap();
        if core.storage_error.is_some() {
            return Err("coordinator state is read-only after a storage failure".to_string());
        }
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
        if self.prune(&mut core, unix_ms())
            && let Err(error) = self.persist(&core)
        {
            self.mark_storage_failure(&mut core, error.clone());
            return Err(error);
        }
        if core.complete {
            return Ok(ClaimOutcome::Complete);
        }
        if core.jobs.iter().all(|job| {
            matches!(
                job.status,
                JobStatus::Done | JobStatus::Failed | JobStatus::Superseded
            )
        }) {
            return Ok(ClaimOutcome::Complete);
        }
        let mut split = false;
        let mut position = core.jobs.iter().position(|job| {
            matches!(job.status, JobStatus::Pending) && (!job.requires_raw || capabilities.syn)
        });
        if position.is_none() && self.split_straggler(&mut core, capabilities, unix_ms()) {
            split = true;
            position = core.jobs.iter().position(|job| {
                matches!(job.status, JobStatus::Pending) && (!job.requires_raw || capabilities.syn)
            });
        }
        let Some(position) = position else {
            if split && let Err(error) = self.persist(&core) {
                self.mark_storage_failure(&mut core, error.clone());
                return Err(error);
            }
            return Ok(ClaimOutcome::Wait);
        };
        let job = &mut core.jobs[position];
        job.attempts += 1;
        job.worker = Some(worker_id.to_string());
        job.started_unix_ms = Some(unix_ms());
        job.status = JobStatus::Running {
            worker: worker_id.to_string(),
            lease_expires_unix_ms: unix_ms() + self.lease.as_millis() as u64,
        };
        let assignment = JobAssignment {
            job_id: job.id,
            shard_index: job.shard_index,
            shard_count: job.shard_count,
            args: job.args.clone(),
            timeout_secs: job.timeout_secs,
            lease_secs: self.lease.as_secs(),
        };
        if let Err(error) = self.persist(&core) {
            self.mark_storage_failure(&mut core, error.clone());
            return Err(error);
        }
        Ok(ClaimOutcome::Job(assignment))
    }

    fn claim_push(&self, index: usize, agent_url: &str) -> Result<Option<JobAssignment>, String> {
        let worker_id = format!("push-agent-{index}");
        match self.claim(&worker_id, agent_url, &Capabilities { syn: true })? {
            ClaimOutcome::Job(job) => Ok(Some(job)),
            ClaimOutcome::Complete | ClaimOutcome::Wait => Ok(None),
        }
    }

    fn mark_storage_failure(&self, core: &mut Core, error: String) {
        core.storage_error = Some(error.clone());
        core.ready = false;
        core.merge_error = Some(error);
    }

    fn prune(&self, core: &mut Core, now_ms: u64) -> bool {
        let mut changed = false;
        for job in &mut core.jobs {
            let expired = matches!(
                &job.status,
                JobStatus::Running { lease_expires_unix_ms, .. } if *lease_expires_unix_ms <= now_ms
            );
            if !expired {
                continue;
            }
            changed = true;
            core.expired_leases += 1;
            job.worker = None;
            if job.attempts >= self.max_attempts {
                job.status = JobStatus::Failed;
                job.error = Some(format!("lease expired after {} attempt(s)", job.attempts));
            } else {
                job.status = JobStatus::Pending;
            }
            diag::event(
                Level::Warn,
                "lease_expired",
                &[
                    ("job_id", json!(job.id)),
                    ("attempts", json!(job.attempts)),
                    (
                        "status",
                        json!(if matches!(job.status, JobStatus::Failed) {
                            "failed"
                        } else {
                            "pending"
                        }),
                    ),
                ],
            );
        }
        changed
    }

    fn split_straggler(&self, core: &mut Core, capabilities: &Capabilities, now_ms: u64) -> bool {
        let active = core
            .workers
            .values()
            .filter(|worker| worker.last_seen.elapsed() <= Duration::from_secs(5))
            .count();
        let parts = active.clamp(2, MAX_SPLIT_PARTS) as u32;
        let Some(index) = core.jobs.iter().position(|job| {
            matches!(job.status, JobStatus::Running { .. })
                && job.work_part.is_none()
                && (!job.requires_raw || capabilities.syn)
                && job
                    .started_unix_ms
                    .is_some_and(|start| now_ms.saturating_sub(start) >= SPLIT_AFTER_MS)
        }) else {
            return false;
        };
        let (parent_id, args, shard_index, shard_count, requires_raw, timeout_secs) = {
            let parent = &core.jobs[index];
            (
                parent.id,
                parent.args.clone(),
                parent.shard_index,
                parent.shard_count,
                parent.requires_raw,
                parent.timeout_secs,
            )
        };
        core.jobs[index].status = JobStatus::Superseded;
        core.jobs[index].worker = None;
        core.jobs[index].error = Some(format!("split into {parts} work units"));
        let mut children = Vec::with_capacity(parts as usize);
        for part in 0..parts {
            let id = core.jobs.len();
            let child_args = work_part_args(&args, part, parts);
            let digest = args_digest(&child_args);
            core.jobs.push(Job {
                id,
                shard_index,
                shard_count,
                args: child_args,
                args_digest: digest,
                requires_raw,
                timeout_secs,
                attempts: 0,
                status: JobStatus::Pending,
                report: None,
                result_digest: None,
                result_path: None,
                error: None,
                elapsed_ms: 0,
                worker: None,
                started_unix_ms: None,
                parent_job_id: Some(parent_id),
                work_part: Some((part, parts)),
            });
            children.push(id);
        }
        diag::event(
            Level::Warn,
            "job_split",
            &[
                ("job_id", json!(parent_id)),
                ("parts", json!(parts)),
                ("children", json!(children)),
                ("active_workers", json!(active)),
            ],
        );
        true
    }

    fn heartbeat(&self, worker_id: &str, job_id: usize) -> Result<bool, String> {
        let now = Instant::now();
        let mut core = self.core.lock().unwrap();
        if core.storage_error.is_some() {
            return Err("coordinator state is read-only after a storage failure".to_string());
        }
        if let Some(worker) = core.workers.get_mut(worker_id) {
            worker.last_seen = now;
        }
        let Some(job) = core.jobs.iter_mut().find(|job| job.id == job_id) else {
            return Ok(false);
        };
        match &mut job.status {
            JobStatus::Running {
                worker,
                lease_expires_unix_ms,
            } if worker == worker_id => {
                *lease_expires_unix_ms = unix_ms() + self.lease.as_millis() as u64;
            }
            JobStatus::Done | JobStatus::Failed => return Ok(true),
            _ => return Ok(false),
        }
        if let Err(error) = self.persist(&core) {
            self.mark_storage_failure(&mut core, error.clone());
            return Err(error);
        }
        Ok(true)
    }

    fn submit(&self, request: &ResultRequest) -> Result<(), SubmitError> {
        let mut core = self.core.lock().unwrap();
        if let Some(error) = &core.storage_error {
            return Err(SubmitError::Storage(error.clone()));
        }
        let index = core
            .jobs
            .iter()
            .position(|job| job.id == request.job_id)
            .ok_or_else(|| SubmitError::Conflict(format!("unknown job {}", request.job_id)))?;

        if let Some(report) = &request.report {
            validate_report(report).map_err(SubmitError::Conflict)?;
            let mut bytes = serde_json::to_vec_pretty(report)
                .map_err(|error| SubmitError::Storage(format!("cannot encode result: {error}")))?;
            bytes.push(b'\n');
            let digest = sha256_hex(&bytes);
            let job = &mut core.jobs[index];
            match &job.status {
                JobStatus::Done => {
                    if job.result_digest.as_deref() == Some(digest.as_str()) {
                        core.duplicate_results += 1;
                        if let Err(error) = self.persist(&core) {
                            self.mark_storage_failure(&mut core, error.clone());
                            return Err(SubmitError::Storage(error));
                        }
                        return Ok(());
                    }
                    return Err(SubmitError::Conflict(format!(
                        "job {} is already complete with a different result",
                        request.job_id
                    )));
                }
                JobStatus::Failed => {
                    return Err(SubmitError::Conflict(format!(
                        "job {} already failed; a late result is not accepted",
                        request.job_id
                    )));
                }
                JobStatus::Superseded => {
                    return Err(SubmitError::Conflict(format!(
                        "job {} was split into work units; its result is no longer accepted",
                        request.job_id
                    )));
                }
                JobStatus::Running { worker, .. } if worker == &request.worker_id => {}
                JobStatus::Running { worker, .. } => {
                    return Err(SubmitError::Conflict(format!(
                        "job {} is leased to worker {worker}",
                        request.job_id
                    )));
                }
                JobStatus::Pending => {
                    return Err(SubmitError::Conflict(format!(
                        "job {} is not leased to worker {}; re-claim it before submitting",
                        request.job_id, request.worker_id
                    )));
                }
            }
            let path = self
                .store
                .write_result(request.job_id, &digest, &bytes)
                .map_err(|error| {
                    let message = error.to_string();
                    self.mark_storage_failure(&mut core, message.clone());
                    SubmitError::Storage(message)
                })?;
            let job = &mut core.jobs[index];
            job.report = Some(report.clone());
            job.result_digest = Some(digest);
            job.result_path = Some(path);
            job.error = None;
            job.elapsed_ms = request.elapsed_ms;
            job.status = JobStatus::Done;
            job.worker = Some(request.worker_id.clone());
            if let Err(error) = self.persist(&core) {
                self.mark_storage_failure(&mut core, error.clone());
                return Err(SubmitError::Storage(error));
            }
            return Ok(());
        }
        if let Some(error) = &request.error {
            let job = &mut core.jobs[index];
            match &job.status {
                JobStatus::Done => {
                    core.duplicate_results += 1;
                    if let Err(error) = self.persist(&core) {
                        self.mark_storage_failure(&mut core, error.clone());
                        return Err(SubmitError::Storage(error));
                    }
                    return Ok(());
                }
                JobStatus::Failed => return Ok(()),
                JobStatus::Superseded => return Ok(()),
                JobStatus::Running { worker, .. } if worker == &request.worker_id => {}
                JobStatus::Running { worker, .. } => {
                    return Err(SubmitError::Conflict(format!(
                        "job {} is leased to worker {worker}",
                        request.job_id
                    )));
                }
                JobStatus::Pending => {
                    return Err(SubmitError::Conflict(format!(
                        "job {} is not leased to worker {}",
                        request.job_id, request.worker_id
                    )));
                }
            }
            job.error = Some(error.clone());
            job.elapsed_ms = request.elapsed_ms;
            job.report = None;
            job.result_digest = None;
            job.result_path = None;
            job.worker = None;
            if job.attempts >= self.max_attempts {
                job.status = JobStatus::Failed;
            } else {
                job.status = JobStatus::Pending;
            }
            let failed = matches!(job.status, JobStatus::Failed);
            if let Err(error) = self.persist(&core) {
                self.mark_storage_failure(&mut core, error.clone());
                return Err(SubmitError::Storage(error));
            }
            diag::event(
                Level::Info,
                "result_error",
                &[
                    ("job_id", json!(request.job_id)),
                    ("worker_id", json!(request.worker_id)),
                    ("failed", json!(failed)),
                    ("error", json!(error)),
                ],
            );
            return Ok(());
        }
        Err(SubmitError::Conflict(
            "result must contain either a report or an error".to_string(),
        ))
    }

    fn discard(&self) {
        let mut core = self.core.lock().unwrap();
        if core.storage_error.is_some() {
            return;
        }
        core.discarded += 1;
        if let Err(error) = self.persist(&core) {
            self.mark_storage_failure(&mut core, error);
        }
    }

    async fn maintain(&self) {
        {
            let mut core = self.core.lock().unwrap();
            if core.storage_error.is_none()
                && self.prune(&mut core, unix_ms())
                && let Err(error) = self.persist(&core)
            {
                self.mark_storage_failure(&mut core, error);
            }
        }
        self.notify.notify_waiters();
        self.maybe_finish().await;
    }

    async fn maybe_finish(&self) {
        let reports: Vec<Value> = {
            let mut core = self.core.lock().unwrap();
            if core.complete
                || core.finishing
                || core.storage_error.is_some()
                || !core.jobs.iter().all(|job| {
                    matches!(
                        job.status,
                        JobStatus::Done | JobStatus::Failed | JobStatus::Superseded
                    )
                })
            {
                return;
            }
            core.finishing = true;
            if let Err(error) = self.persist(&core) {
                core.finishing = false;
                self.mark_storage_failure(&mut core, error);
                return;
            }
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
        let mut core = self.core.lock().unwrap();
        match merged {
            Ok(value) => {
                let mut text = match serde_json::to_string_pretty(&value) {
                    Ok(text) => text,
                    Err(error) => {
                        core.finishing = false;
                        core.merge_failures += 1;
                        core.merge_error = Some(format!("cannot encode merged report: {error}"));
                        diag::event(
                            Level::Error,
                            "merge_failed",
                            &[("error", json!(core.merge_error))],
                        );
                        return;
                    }
                };
                text.push('\n');
                let digest = sha256_hex(text.as_bytes());
                if let Err(error) = atomic_write(&self.out, text.as_bytes(), false) {
                    core.finishing = false;
                    core.merge_failures += 1;
                    core.merge_error = Some(error.to_string());
                    diag::event(
                        Level::Error,
                        "merge_failed",
                        &[("error", json!(core.merge_error))],
                    );
                    return;
                }
                core.report = Some(value);
                core.report_digest = Some(digest);
                core.finishing = false;
                core.complete = true;
                core.merge_error = None;
                if let Err(error) = self.persist(&core) {
                    self.mark_storage_failure(&mut core, error);
                    return;
                }
                diag::event(
                    Level::Info,
                    "merge_complete",
                    &[
                        ("jobs", json!(core.jobs.len())),
                        ("report", json!(self.out.display().to_string())),
                    ],
                );
            }
            Err(error) => {
                core.finishing = false;
                core.merge_failures += 1;
                core.merge_error = Some(error.to_string());
                diag::event(
                    Level::Error,
                    "merge_failed",
                    &[("error", json!(core.merge_error))],
                );
                return;
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
        let mut superseded = 0;
        let mut elapsed = 0u64;
        for job in &core.jobs {
            elapsed += job.elapsed_ms;
            match job.status {
                JobStatus::Pending => pending += 1,
                JobStatus::Running { .. } => running += 1,
                JobStatus::Done => done += 1,
                JobStatus::Failed => failed += 1,
                JobStatus::Superseded => superseded += 1,
            }
        }
        let workers: Vec<Value> = core
            .workers
            .iter()
            .map(|(id, worker)| {
                let current = core.jobs.iter().find(|job| {
                    matches!(&job.status, JobStatus::Running { worker: owner, .. } if owner == id)
                });
                let lease_expires_in_ms = current.and_then(|job| match &job.status {
                    JobStatus::Running {
                        lease_expires_unix_ms,
                        ..
                    } => Some(lease_expires_unix_ms.saturating_sub(unix_ms())),
                    _ => None,
                });
                json!({
                    "id": id,
                    "name": worker.name,
                    "last_seen_ms": now.duration_since(worker.last_seen).as_millis() as u64,
                    "job_id": current.map(|job| job.id),
                    "shard_index": current.map(|job| job.shard_index),
                    "lease_expires_in_ms": lease_expires_in_ms,
                })
            })
            .collect();
        json!({
            "state": if core.storage_error.is_some() {
                "error"
            } else if core.complete {
                "complete"
            } else {
                "running"
            },
            "mode": self.mode.as_str(),
            "run_id": core.run_id,
            "restart_count": core.restart_count,
            "ready": core.ready,
            "jobs": {
                "total": core.jobs.len(),
                "pending": pending,
                "running": running,
                "done": done,
                "failed": failed,
                "superseded": superseded,
            },
            "workers": workers,
            "elapsed_ms": self.started.elapsed().as_millis() as u64,
            "reported_elapsed_ms": elapsed,
            "discarded_results": core.discarded,
            "duplicate_results": core.duplicate_results,
            "expired_leases": core.expired_leases,
            "merge_failures": core.merge_failures,
            "out": self.out.display().to_string(),
            "state_file": self.store.state_path.display().to_string(),
            "error": core.merge_error,
            "storage_error": core.storage_error,
        })
    }

    fn metrics_text(&self) -> String {
        let core = self.core.lock().unwrap();
        let mut pending = 0u64;
        let mut running = 0u64;
        let mut done = 0u64;
        let mut failed = 0u64;
        let mut superseded = 0u64;
        for job in &core.jobs {
            match job.status {
                JobStatus::Pending => pending += 1,
                JobStatus::Running { .. } => running += 1,
                JobStatus::Done => done += 1,
                JobStatus::Failed => failed += 1,
                JobStatus::Superseded => superseded += 1,
            }
        }
        let inflight = (MAX_INFLIGHT_REQUESTS - self.requests.available_permits()) as u64;
        format!(
            "# HELP portensor_coordinator_ready Whether recovery completed and the lock is held.\n\
             # TYPE portensor_coordinator_ready gauge\n\
             portensor_coordinator_ready {}\n\
             # HELP portensor_coordinator_restart_count Number of coordinator process restarts.\n\
             # TYPE portensor_coordinator_restart_count gauge\n\
             portensor_coordinator_restart_count {}\n\
             # HELP portensor_jobs Queue depth, running, completed, and failed shard jobs.\n\
             # TYPE portensor_jobs gauge\n\
             portensor_jobs{{state=\"pending\"}} {}\n\
             portensor_jobs{{state=\"running\"}} {}\n\
             portensor_jobs{{state=\"done\"}} {}\n\
             portensor_jobs{{state=\"failed\"}} {}\n\
             portensor_jobs{{state=\"superseded\"}} {}\n\
             # HELP portensor_inflight_requests Control-plane requests currently executing.\n\
             # TYPE portensor_inflight_requests gauge\n\
             portensor_inflight_requests {}\n\
             # HELP portensor_active_leases Shard leases currently held by workers.\n\
             # TYPE portensor_active_leases gauge\n\
             portensor_active_leases {}\n\
             # HELP portensor_expired_leases_total Leases requeued after expiry.\n\
             # TYPE portensor_expired_leases_total counter\n\
             portensor_expired_leases_total {}\n\
             # HELP portensor_duplicate_results_total Idempotent duplicate result submissions.\n\
             # TYPE portensor_duplicate_results_total counter\n\
             portensor_duplicate_results_total {}\n\
             # HELP portensor_merge_failures_total Failed merge attempts.\n\
             # TYPE portensor_merge_failures_total counter\n\
             portensor_merge_failures_total {}\n\
             # HELP portensor_discarded_results_total Stale push results discarded.\n\
             # TYPE portensor_discarded_results_total counter\n\
             portensor_discarded_results_total {}\n",
            u8::from(core.ready && core.storage_error.is_none()),
            core.restart_count,
            pending,
            running,
            done,
            failed,
            superseded,
            inflight,
            running,
            core.expired_leases,
            core.duplicate_results,
            core.merge_failures,
            core.discarded,
        )
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

    fn run_id(&self) -> String {
        self.core.lock().unwrap().run_id.clone()
    }
}

fn snapshot(core: &Core, out: &Path) -> PersistedState {
    PersistedState {
        schema_version: STATE_SCHEMA_VERSION,
        coordinator_id: core.coordinator_id.clone(),
        run_id: core.run_id.clone(),
        restart_count: core.restart_count,
        finishing: core.finishing,
        complete: core.complete,
        jobs: core
            .jobs
            .iter()
            .map(|job| {
                let (status, worker, lease) = match &job.status {
                    JobStatus::Pending => (PersistedStatus::Pending, None, None),
                    JobStatus::Running {
                        worker,
                        lease_expires_unix_ms,
                    } => (
                        PersistedStatus::Running,
                        Some(worker.clone()),
                        Some(*lease_expires_unix_ms),
                    ),
                    JobStatus::Done => (PersistedStatus::Done, job.worker.clone(), None),
                    JobStatus::Failed => (PersistedStatus::Failed, job.worker.clone(), None),
                    JobStatus::Superseded => {
                        (PersistedStatus::Superseded, job.worker.clone(), None)
                    }
                };
                PersistedJob {
                    id: job.id,
                    shard_index: job.shard_index,
                    shard_count: job.shard_count,
                    args_digest: job.args_digest.clone(),
                    status,
                    worker,
                    lease_expires_unix_ms: lease,
                    started_unix_ms: job.started_unix_ms,
                    parent_job_id: job.parent_job_id,
                    unit: job
                        .work_part
                        .map(|(index, count)| PersistedUnit { index, count }),
                    attempts: job.attempts,
                    result_digest: job.result_digest.clone(),
                    result_path: job.result_path.clone(),
                    error: job.error.clone(),
                    elapsed_ms: job.elapsed_ms,
                }
            })
            .collect(),
        report: PersistedReport {
            path: out.to_path_buf(),
            digest: core.report_digest.clone(),
            ready: core.complete && core.report.is_some(),
        },
    }
}

fn restore_state(
    core: &mut Core,
    state: PersistedState,
    store: &StateStore,
    max_attempts: u32,
) -> Result<(), AppError> {
    let planned_count = core.jobs.len();
    if state.jobs.len() < planned_count {
        return Err(AppError::runtime(format!(
            "coordinator state has {} job(s), but this scan needs at least {}; refusing to reuse it",
            state.jobs.len(),
            planned_count
        )));
    }
    for (index, persisted) in state.jobs.iter().enumerate() {
        if persisted.id != index {
            return Err(AppError::runtime(format!(
                "coordinator state job {} is out of order",
                persisted.id
            )));
        }
        if index < planned_count {
            let job = &core.jobs[index];
            if persisted.parent_job_id.is_some() || persisted.unit.is_some() {
                return Err(AppError::runtime(format!(
                    "original coordinator job {} unexpectedly carries split metadata",
                    persisted.id
                )));
            }
            if persisted.shard_index != job.shard_index
                || persisted.shard_count != job.shard_count
                || persisted.args_digest != job.args_digest
            {
                return Err(AppError::runtime(format!(
                    "coordinator state job {} does not match the current scan arguments",
                    persisted.id
                )));
            }
            continue;
        }
        let parent_id = persisted.parent_job_id.ok_or_else(|| {
            AppError::runtime(format!("split job {} has no parent job id", persisted.id))
        })?;
        if parent_id >= planned_count {
            return Err(AppError::runtime(format!(
                "split job {} has invalid parent {parent_id}",
                persisted.id
            )));
        }
        let unit = persisted.unit.ok_or_else(|| {
            AppError::runtime(format!("split job {} has no work unit", persisted.id))
        })?;
        if unit.count < 2 || unit.index >= unit.count {
            return Err(AppError::runtime(format!(
                "split job {} has invalid work unit {}/{}",
                persisted.id, unit.index, unit.count
            )));
        }
        let (args, digest, shard_index, shard_count, requires_raw, timeout_secs) = {
            let parent = &core.jobs[parent_id];
            if parent.work_part.is_some() {
                return Err(AppError::runtime(
                    "nested work splitting is not supported by this state schema",
                ));
            }
            let args = work_part_args(&parent.args, unit.index, unit.count);
            (
                args.clone(),
                args_digest(&args),
                parent.shard_index,
                parent.shard_count,
                parent.requires_raw,
                parent.timeout_secs,
            )
        };
        if persisted.shard_index != shard_index
            || persisted.shard_count != shard_count
            || persisted.args_digest != digest
        {
            return Err(AppError::runtime(format!(
                "split job {} does not match its parent work unit",
                persisted.id
            )));
        }
        core.jobs.push(Job {
            id: index,
            shard_index,
            shard_count,
            args,
            args_digest: digest,
            requires_raw,
            timeout_secs,
            attempts: 0,
            status: JobStatus::Pending,
            report: None,
            result_digest: None,
            result_path: None,
            error: None,
            elapsed_ms: 0,
            worker: None,
            started_unix_ms: None,
            parent_job_id: Some(parent_id),
            work_part: Some((unit.index, unit.count)),
        });
    }
    if core.jobs.len() != state.jobs.len() {
        return Err(AppError::runtime(
            "coordinator state could not be reconstructed exactly",
        ));
    }

    core.run_id = state.run_id;
    core.coordinator_id = state.coordinator_id;
    core.restart_count = state.restart_count.saturating_add(1);
    core.finishing = state.finishing;
    core.complete = state.complete && state.report.ready;
    let mut orphans = store.orphan_results()?;
    let now = unix_ms();
    for (job, persisted) in core.jobs.iter_mut().zip(state.jobs.iter()) {
        job.attempts = persisted.attempts;
        job.elapsed_ms = persisted.elapsed_ms;
        job.error = persisted.error.clone();
        job.worker = persisted.worker.clone();
        job.result_digest = persisted.result_digest.clone();
        job.result_path = persisted.result_path.clone();
        job.started_unix_ms = persisted.started_unix_ms;
        if persisted.status == PersistedStatus::Done {
            let digest = persisted.result_digest.as_deref().ok_or_else(|| {
                AppError::runtime(format!(
                    "completed job {} has no durable result digest",
                    persisted.id
                ))
            })?;
            job.report = Some(store.read_result(persisted.id, digest)?);
            job.status = JobStatus::Done;
        } else {
            job.status = match persisted.status {
                PersistedStatus::Pending => JobStatus::Pending,
                PersistedStatus::Running => {
                    let expires = persisted.lease_expires_unix_ms.unwrap_or(0);
                    if expires > now {
                        JobStatus::Running {
                            worker: persisted.worker.clone().ok_or_else(|| {
                                AppError::runtime(format!(
                                    "running job {} has no worker",
                                    persisted.id
                                ))
                            })?,
                            lease_expires_unix_ms: expires,
                        }
                    } else {
                        core.expired_leases += 1;
                        if persisted.attempts >= max_attempts {
                            JobStatus::Failed
                        } else {
                            JobStatus::Pending
                        }
                    }
                }
                PersistedStatus::Failed => JobStatus::Failed,
                PersistedStatus::Superseded => JobStatus::Superseded,
                PersistedStatus::Done => unreachable!(),
            };
        }

        if let Some(mut found) = orphans.remove(&persisted.id) {
            found.sort_by(|left, right| left.digest.cmp(&right.digest));
            found.dedup_by(|left, right| left.digest == right.digest);
            if found.len() > 1 {
                return Err(AppError::runtime(format!(
                    "job {} has multiple different durable results; refusing to choose",
                    persisted.id
                )));
            }
            let orphan = found.pop().expect("one orphan result");
            if matches!(job.status, JobStatus::Done) {
                if job.result_digest.as_deref() != Some(orphan.digest.as_str()) {
                    return Err(AppError::runtime(format!(
                        "job {} has a completed result that conflicts with an orphan result",
                        persisted.id
                    )));
                }
            } else if matches!(job.status, JobStatus::Superseded) {
                return Err(AppError::runtime(format!(
                    "superseded job {} has an unexpected durable result",
                    persisted.id
                )));
            } else {
                job.report = Some(orphan.report);
                job.result_digest = Some(orphan.digest);
                job.result_path = Some(orphan.path);
                job.status = JobStatus::Done;
                job.error = None;
            }
        }
    }
    if let Some((id, _)) = orphans.iter().next() {
        return Err(AppError::runtime(format!(
            "durable result for unknown job {id} found in {}",
            store.result_dir.display()
        )));
    }

    if core.complete {
        let bytes = std::fs::read(&store.out).map_err(|error| {
            AppError::runtime(format!(
                "coordinator state is complete but merged report {} is unreadable: {error}",
                store.out.display()
            ))
        })?;
        let digest =
            state.report.digest.as_deref().ok_or_else(|| {
                AppError::runtime("complete coordinator state has no report digest")
            })?;
        if sha256_hex(&bytes) != digest {
            core.complete = false;
            core.finishing = true;
            return Ok(());
        }
        let report: Value = serde_json::from_slice(&bytes).map_err(|error| {
            AppError::runtime(format!(
                "cannot parse merged report {}: {error}",
                store.out.display()
            ))
        })?;
        core.report = Some(report);
        core.report_digest = Some(digest.to_string());
    }
    Ok(())
}
fn recover_merge(core: &mut Core, store: &StateStore, out: &Path) -> Result<(), AppError> {
    core.finishing = true;
    store.save(&snapshot(core, out))?;
    let reports: Vec<Value> = core
        .jobs
        .iter()
        .filter_map(|job| job.report.clone())
        .collect();
    let merged = merge_reports(reports)?;
    let mut text = serde_json::to_string_pretty(&merged)
        .map_err(|error| AppError::runtime(format!("cannot encode merged report: {error}")))?;
    text.push('\n');
    atomic_write(out, text.as_bytes(), false)?;
    core.report = Some(merged);
    core.report_digest = Some(sha256_hex(text.as_bytes()));
    core.complete = true;
    core.finishing = false;
    core.merge_error = None;
    store.save(&snapshot(core, out))?;
    Ok(())
}

fn merge_reports(reports: Vec<Value>) -> Result<Value, AppError> {
    if reports.is_empty() {
        return Err(AppError::runtime("no shard reports were produced"));
    }
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    let workspace = loop {
        let candidate = std::env::temp_dir().join(format!(
            "portensor-merge-{}-{stamp}-{:016x}",
            std::process::id(),
            rand::random::<u64>()
        ));
        match std::fs::create_dir(&candidate) {
            Ok(()) => break candidate,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(AppError::runtime(format!(
                    "cannot create merge workspace {}: {error}",
                    candidate.display()
                )));
            }
        }
    };
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
    let server_tls = tls::server_config(args.tls_cert.as_deref(), args.tls_key.as_deref())?;
    let client_tls = ClientTls::load(args.ca_cert.as_deref(), args.insecure_tls)?;
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
    let state_path = args
        .state
        .clone()
        .unwrap_or_else(|| PathBuf::from(format!("{}.state.json", args.out.display())));
    let coordinator = Arc::new(Coordinator::open(
        token,
        jobs,
        args.out.clone(),
        state_path,
        lease,
        args.max_attempts.max(1),
        mode,
    )?);

    let app = Router::new()
        .route("/v1/claim", post(claim_handler))
        .route("/v1/heartbeat", post(heartbeat_handler))
        .route("/v1/result", post(result_handler))
        .route("/v1/status", get(status_handler))
        .route("/v1/report", get(report_handler))
        .route("/v1/healthz", get(health_handler))
        .route("/readyz", get(ready_handler))
        .route("/metrics", get(metrics_handler))
        .with_state(coordinator.clone())
        .layer(DefaultBodyLimit::max(256 * 1024 * 1024))
        .layer(middleware::from_fn(request_timeout))
        .layer(middleware::from_fn_with_state(
            coordinator.clone(),
            authorize,
        ));

    let scheme = if server_tls.is_some() {
        "https"
    } else {
        "http"
    };
    let run_id = coordinator.run_id();
    let restart_count = coordinator.core.lock().unwrap().restart_count;
    eprintln!(
        "[distributed] coordinator on {scheme}://{}/ ({} shard jobs, mode={}, run={run_id}, restart={restart_count})",
        args.listen,
        coordinator.core.lock().unwrap().jobs.len(),
        mode.as_str()
    );
    diag::event(
        Level::Info,
        "coordinator_start",
        &[
            ("listen", serde_json::json!(args.listen)),
            ("scheme", serde_json::json!(scheme)),
            (
                "jobs",
                serde_json::json!(coordinator.core.lock().unwrap().jobs.len()),
            ),
            ("mode", serde_json::json!(mode.as_str())),
            ("run_id", serde_json::json!(run_id)),
            ("restart_count", serde_json::json!(restart_count)),
            (
                "state",
                serde_json::json!(coordinator.store.state_path.display().to_string()),
            ),
        ],
    );

    if mode == Mode::Push {
        for (index, agent) in agents.into_iter().enumerate() {
            spawn_push_loop(coordinator.clone(), index, agent, client_tls.clone());
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
    let serve_result = if let Some(config) = server_tls {
        let listener = TlsListener::bind(&args.listen, config).await?;
        axum::serve(listener, app)
            .with_graceful_shutdown(wait_for_completion(coordinator.clone()))
            .await
    } else {
        let listener = TcpListener::bind(&args.listen).await.map_err(|error| {
            AppError::runtime(format!("cannot listen on {}: {error}", args.listen))
        })?;
        if !is_loopback_listen(&args.listen) {
            eprintln!(
                "[distributed] warning: {} is not a loopback address; the bearer token travels over \
                 plaintext HTTP. Configure --tls-cert/--tls-key or use a trusted network.",
                args.listen
            );
        }
        axum::serve(listener, app)
            .with_graceful_shutdown(wait_for_completion(coordinator.clone()))
            .await
    };
    serve_result.map_err(|error| AppError::runtime(format!("coordinator failed: {error}")))?;

    if !shutdown.is_complete() {
        eprintln!("[distributed] stopped before all shards completed");
        return Ok(());
    }
    let (done, failed, discarded, merge_error, report_ready) = shutdown.failure_summary();
    let run_id = shutdown.run_id();
    eprintln!(
        "[distributed] complete: {done} shard(s) done, {failed} failed, {discarded} stale result(s) discarded (run={run_id})"
    );
    diag::event(
        Level::Info,
        "coordinator_complete",
        &[
            ("run_id", serde_json::json!(run_id)),
            ("done", serde_json::json!(done)),
            ("failed", serde_json::json!(failed)),
            ("discarded", serde_json::json!(discarded)),
            ("report_ready", serde_json::json!(report_ready)),
        ],
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

async fn wait_for_completion(coordinator: Arc<Coordinator>) {
    let mut complete_rx = coordinator.complete_tx.subscribe();
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
            _ = crate::shutdown::wait_for_shutdown() => return,
        }
    }
}

fn spawn_push_loop(
    coordinator: Arc<Coordinator>,
    index: usize,
    agent: String,
    client_tls: ClientTls,
) {
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
            let assignment = match coordinator.claim_push(index, &agent) {
                Ok(assignment) => assignment,
                Err(error) => {
                    eprintln!("[distributed] push agent {index} cannot claim work: {error}");
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    continue;
                }
            };
            let Some(job) = assignment else {
                if coordinator.is_complete() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
                continue;
            };
            let job_id = job.job_id;
            let lease_secs = job.lease_secs;
            let timeout = Duration::from_secs(job.timeout_secs.saturating_add(60).max(60));
            let token = coordinator.token.clone();
            let agent_url = agent.clone();
            let body = json!({ "job": job });
            let heartbeat_coordinator = coordinator.clone();
            let heartbeat_worker = worker_id.clone();
            let heartbeat = tokio::spawn(async move {
                let interval = Duration::from_secs((lease_secs / 3).clamp(1, 30));
                loop {
                    tokio::time::sleep(interval).await;
                    match heartbeat_coordinator.heartbeat(&heartbeat_worker, job_id) {
                        Ok(true) => {}
                        Ok(false) => {
                            eprintln!(
                                "[distributed] push job {job_id} is no longer leased; a late result will be discarded"
                            );
                            break;
                        }
                        Err(error) => {
                            eprintln!("[distributed] push job {job_id} heartbeat failed: {error}");
                            break;
                        }
                    }
                }
            });
            let request_tls = client_tls.clone();
            let response = tokio::task::spawn_blocking(move || {
                post_json(
                    &agent_url,
                    &token,
                    "/v1/execute",
                    &body,
                    timeout,
                    &request_tls,
                )
            })
            .await;
            heartbeat.abort();
            let _ = heartbeat.await;
            let mut stale = false;
            let retry_later = match response {
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
                        false
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
                        true
                    }
                }
                Ok(Err(error)) => {
                    diag::event(
                        Level::Warn,
                        "push_job_failed",
                        &[
                            ("job_id", serde_json::json!(job_id)),
                            ("status", serde_json::json!(error.status())),
                            ("error", serde_json::json!(error.to_string())),
                        ],
                    );
                    eprintln!("[distributed] push job {job_id} failed: {error}");
                    let request = ResultRequest {
                        worker_id: worker_id.clone(),
                        job_id,
                        report: None,
                        error: Some(error.to_string()),
                        elapsed_ms: 0,
                    };
                    if coordinator.submit(&request).is_err() {
                        stale = true;
                    }
                    true
                }
                Err(error) => {
                    diag::event(
                        Level::Warn,
                        "push_job_failed",
                        &[
                            ("job_id", serde_json::json!(job_id)),
                            ("error", serde_json::json!(format!("task failed: {error}"))),
                        ],
                    );
                    eprintln!("[distributed] push job {job_id} task failed: {error}");
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
                    true
                }
            };
            if stale {
                coordinator.discard();
            }
            coordinator.maintain().await;
            if retry_later {
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
    });
}

/// Bound request handling so a stalled upload or half-open client cannot hold
/// coordinator resources indefinitely. Result bodies are still accepted up to
/// the configured body limit; this only limits total request lifetime.
async fn request_timeout(request: Request, next: Next) -> Response {
    match tokio::time::timeout(Duration::from_secs(300), next.run(request)).await {
        Ok(response) => response,
        Err(_) => ApiError::new(
            StatusCode::REQUEST_TIMEOUT,
            "coordinator request exceeded 300s",
        )
        .into_response(),
    }
}

async fn authorize(
    State(coordinator): State<Arc<Coordinator>>,
    request: Request,
    next: Next,
) -> Response {
    if !matches!(
        bearer(request.headers()),
        Some(token) if constant_time_eq(&coordinator.token, token)
    ) {
        return ApiError::new(StatusCode::UNAUTHORIZED, "invalid or missing bearer token")
            .into_response();
    }
    let Ok(_permit) = coordinator.requests.clone().try_acquire_owned() else {
        return ApiError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "coordinator is at its request concurrency limit; retry later",
        )
        .into_response();
    };
    next.run(request).await
}

async fn health_handler() -> Json<Value> {
    Json(json!({ "ok": true }))
}

async fn ready_handler(State(coordinator): State<Arc<Coordinator>>) -> Response {
    let core = coordinator.core.lock().unwrap();
    if core.ready && core.storage_error.is_none() && core.complete {
        Json(json!({
            "ready": true,
            "state": "complete",
            "run_id": core.run_id,
            "restart_count": core.restart_count,
        }))
        .into_response()
    } else if core.ready && core.storage_error.is_none() {
        Json(json!({
            "ready": true,
            "state": "running",
            "run_id": core.run_id,
            "restart_count": core.restart_count,
        }))
        .into_response()
    } else {
        let error = core
            .storage_error
            .clone()
            .unwrap_or_else(|| "coordinator is recovering".to_string());
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "ready": false, "error": error })),
        )
            .into_response()
    }
}

async fn metrics_handler(State(coordinator): State<Arc<Coordinator>>) -> Response {
    let error = {
        let core = coordinator.core.lock().unwrap();
        if core.ready && core.storage_error.is_none() {
            None
        } else {
            Some(
                core.storage_error
                    .clone()
                    .unwrap_or_else(|| "coordinator is recovering".to_string()),
            )
        }
    };
    match error {
        None => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
            coordinator.metrics_text(),
        )
            .into_response(),
        Some(error) => ApiError::new(StatusCode::SERVICE_UNAVAILABLE, error).into_response(),
    }
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
            Ok(ClaimOutcome::Job(job)) => {
                return Ok(Json(ClaimResponse {
                    job: Some(job),
                    complete: false,
                }));
            }
            Ok(ClaimOutcome::Complete) => {
                coordinator.maybe_finish().await;
                return Ok(Json(ClaimResponse {
                    job: None,
                    complete: true,
                }));
            }
            Ok(ClaimOutcome::Wait) => {}
            Err(error) => {
                return Err(ApiError::new(StatusCode::SERVICE_UNAVAILABLE, error));
            }
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
    match coordinator.heartbeat(&request.worker_id, request.job_id) {
        Ok(true) => Ok(Json(json!({ "ok": true }))),
        Ok(false) => Err(ApiError::conflict(format!(
            "job {} is not leased to worker {}",
            request.job_id, request.worker_id
        ))),
        Err(error) => Err(ApiError::new(StatusCode::SERVICE_UNAVAILABLE, error)),
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
        Err(error) => Err(error.into_api()),
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
            "portensor-coordinator-test-{}-{}.json",
            std::process::id(),
            rand::random::<u64>()
        ));
        let state = PathBuf::from(format!("{}.state.json", out.display()));
        (
            Coordinator::open(
                "test-token-0123456789".to_string(),
                jobs,
                out.clone(),
                state,
                Duration::from_secs(30),
                2,
                Mode::Pull,
            )
            .unwrap(),
            out,
        )
    }

    #[test]
    fn raw_jobs_wait_for_capable_workers() {
        let (coordinator, _) = coordinator(vec![job(0, true), job(1, false)]);
        let no_raw = Capabilities { syn: false };
        let ClaimOutcome::Job(assignment) = coordinator.claim("worker-a", "a", &no_raw).unwrap()
        else {
            panic!("expected the non-raw job");
        };
        assert_eq!(assignment.shard_index, 1);
        assert!(matches!(
            coordinator.claim("worker-a", "a", &no_raw).unwrap(),
            ClaimOutcome::Wait
        ));
        let raw = Capabilities { syn: true };
        assert!(matches!(
            coordinator.claim("worker-b", "b", &raw).unwrap(),
            ClaimOutcome::Job(_)
        ));
    }

    #[test]
    fn failed_jobs_are_requeued_then_completed() {
        let (coordinator, _) = coordinator(vec![job(0, false)]);
        let ClaimOutcome::Job(assignment) = coordinator
            .claim("worker-a", "a", &Capabilities::default())
            .unwrap()
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
        let ClaimOutcome::Job(assignment) = coordinator
            .claim("worker-b", "b", &Capabilities::default())
            .unwrap()
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
        let ClaimOutcome::Job(assignment) = coordinator
            .claim("worker-a", "a", &Capabilities::default())
            .unwrap()
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
        let ClaimOutcome::Job(assignment) = coordinator
            .claim("worker-a", "a", &Capabilities::default())
            .unwrap()
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
        let ClaimOutcome::Job(assignment) = coordinator
            .claim("worker-a", "a", &Capabilities::default())
            .unwrap()
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

    fn reopen(
        out: &Path,
        state: &Path,
        jobs: Vec<PlannedJob>,
        lease: Duration,
        max_attempts: u32,
    ) -> Coordinator {
        Coordinator::open(
            "test-token-0123456789".to_string(),
            jobs,
            out.to_path_buf(),
            state.to_path_buf(),
            lease,
            max_attempts,
            Mode::Pull,
        )
        .unwrap()
    }

    fn coordinator_paths() -> (PathBuf, PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "portensor-durability-test-{}-{:016x}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        (dir.join("report.json"), dir.join("state.json"))
    }

    #[test]
    fn restart_after_claim_restores_the_lease() {
        let (coordinator, out) = coordinator(vec![job(0, false)]);
        let state = coordinator.store.state_path.clone();
        let ClaimOutcome::Job(assignment) = coordinator
            .claim("worker-a", "a", &Capabilities::default())
            .unwrap()
        else {
            panic!("expected a job");
        };
        drop(coordinator);

        let restored = reopen(
            &out,
            &state,
            vec![job(0, false)],
            Duration::from_secs(30),
            2,
        );
        let status = restored.status_value();
        assert_eq!(status["restart_count"], 1);
        assert_eq!(status["jobs"]["running"], 1);
        assert!(matches!(
            restored
                .claim("worker-b", "b", &Capabilities::default())
                .unwrap(),
            ClaimOutcome::Wait
        ));
        let request = ResultRequest {
            worker_id: "worker-a".into(),
            job_id: assignment.job_id,
            report: Some(report(8080)),
            error: None,
            elapsed_ms: 12,
        };
        restored.submit(&request).unwrap();
        assert!(matches!(
            restored.core.lock().unwrap().jobs.first().unwrap().status,
            JobStatus::Done
        ));
    }

    #[test]
    fn restart_attaches_an_orphan_result() {
        let (coordinator, out) = coordinator(vec![job(0, false)]);
        let state = coordinator.store.state_path.clone();
        let result_dir = coordinator.store.result_dir.clone();
        let ClaimOutcome::Job(assignment) = coordinator
            .claim("worker-a", "a", &Capabilities::default())
            .unwrap()
        else {
            panic!("expected a job");
        };
        let mut bytes = serde_json::to_vec_pretty(&report(9090)).unwrap();
        bytes.push(b'\n');
        let digest = sha256_hex(&bytes);
        drop(coordinator);
        std::fs::write(
            result_dir.join(format!("{}-{digest}.json", assignment.job_id)),
            &bytes,
        )
        .unwrap();

        let restored = reopen(
            &out,
            &state,
            vec![job(0, false)],
            Duration::from_secs(30),
            2,
        );
        assert!(restored.is_complete());
        let merged: Value = serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
        assert_eq!(merged["open"][0]["port"], 9090);
        assert_eq!(
            restored.core.lock().unwrap().jobs[0]
                .result_digest
                .as_deref(),
            Some(digest.as_str())
        );
    }

    #[test]
    fn restart_requeues_an_expired_lease_within_attempt_limit() {
        let (out, state) = coordinator_paths();
        let first = reopen(
            &out,
            &state,
            vec![job(0, false)],
            Duration::from_millis(50),
            2,
        );
        let ClaimOutcome::Job(_) = first
            .claim("worker-a", "a", &Capabilities::default())
            .unwrap()
        else {
            panic!("expected a job");
        };
        std::thread::sleep(Duration::from_millis(120));
        drop(first);

        let restored = reopen(
            &out,
            &state,
            vec![job(0, false)],
            Duration::from_secs(30),
            2,
        );
        let status = restored.status_value();
        assert_eq!(status["jobs"]["pending"], 1);
        assert_eq!(status["expired_leases"], 1);
        let ClaimOutcome::Job(assignment) = restored
            .claim("worker-b", "b", &Capabilities::default())
            .unwrap()
        else {
            panic!("expected a retry");
        };
        assert_eq!(assignment.job_id, 0);
        assert_eq!(restored.core.lock().unwrap().jobs[0].attempts, 2);
    }

    #[tokio::test]
    async fn restart_after_completion_reuses_the_merged_report() {
        let (coordinator, out) = coordinator(vec![job(0, false)]);
        let state = coordinator.store.state_path.clone();
        let ClaimOutcome::Job(assignment) = coordinator
            .claim("worker-a", "a", &Capabilities::default())
            .unwrap()
        else {
            panic!("expected a job");
        };
        coordinator
            .submit(&ResultRequest {
                worker_id: "worker-a".into(),
                job_id: assignment.job_id,
                report: Some(report(443)),
                error: None,
                elapsed_ms: 10,
            })
            .unwrap();
        coordinator.maintain().await;
        let before = std::fs::read(&out).unwrap();
        drop(coordinator);

        let restored = reopen(
            &out,
            &state,
            vec![job(0, false)],
            Duration::from_secs(30),
            2,
        );
        assert!(restored.is_complete());
        assert_eq!(std::fs::read(&out).unwrap(), before);
        assert_eq!(restored.status_value()["restart_count"], 1);
        assert!(matches!(
            restored
                .claim("worker-c", "c", &Capabilities::default())
                .unwrap(),
            ClaimOutcome::Complete
        ));
        drop(restored);

        let again = reopen(
            &out,
            &state,
            vec![job(0, false)],
            Duration::from_secs(30),
            2,
        );
        assert!(again.is_complete());
        assert_eq!(again.status_value()["restart_count"], 2);
        assert_eq!(std::fs::read(&out).unwrap(), before);
    }

    #[tokio::test]
    async fn interrupted_merge_is_repaired_on_restart() {
        let (coordinator, out) = coordinator(vec![job(0, false)]);
        let state = coordinator.store.state_path.clone();
        let ClaimOutcome::Job(assignment) = coordinator
            .claim("worker-a", "a", &Capabilities::default())
            .unwrap()
        else {
            panic!("expected a job");
        };
        coordinator
            .submit(&ResultRequest {
                worker_id: "worker-a".into(),
                job_id: assignment.job_id,
                report: Some(report(8443)),
                error: None,
                elapsed_ms: 10,
            })
            .unwrap();
        coordinator.maintain().await;
        assert!(coordinator.is_complete());
        drop(coordinator);

        let mut persisted: Value =
            serde_json::from_str(&std::fs::read_to_string(&state).unwrap()).unwrap();
        persisted["finishing"] = json!(true);
        persisted["complete"] = json!(false);
        persisted["report"]["ready"] = json!(false);
        std::fs::write(&state, serde_json::to_vec_pretty(&persisted).unwrap()).unwrap();
        let _ = std::fs::remove_file(&out);

        let restored = reopen(
            &out,
            &state,
            vec![job(0, false)],
            Duration::from_secs(30),
            2,
        );
        assert!(restored.is_complete());
        let merged: Value = serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
        assert_eq!(merged["open"][0]["port"], 8443);
        assert_eq!(restored.status_value()["restart_count"], 1);
    }

    #[test]
    fn conflicting_results_are_rejected_and_identical_duplicates_are_idempotent() {
        let (coordinator, _) = coordinator(vec![job(0, false)]);
        let ClaimOutcome::Job(assignment) = coordinator
            .claim("worker-a", "a", &Capabilities::default())
            .unwrap()
        else {
            panic!("expected a job");
        };
        let first = ResultRequest {
            worker_id: "worker-a".into(),
            job_id: assignment.job_id,
            report: Some(report(80)),
            error: None,
            elapsed_ms: 10,
        };
        coordinator.submit(&first).unwrap();
        coordinator.submit(&first).unwrap();
        let conflicting = ResultRequest {
            report: Some(report(81)),
            ..first.clone()
        };
        assert!(coordinator.submit(&conflicting).is_err());
        assert_eq!(
            coordinator.core.lock().unwrap().jobs[0]
                .report
                .as_ref()
                .unwrap()["open"][0]["port"],
            80
        );
    }

    #[test]
    fn a_second_coordinator_cannot_steal_the_state_lock() {
        let (out, state) = coordinator_paths();
        let first = reopen(
            &out,
            &state,
            vec![job(0, false)],
            Duration::from_secs(30),
            2,
        );
        let error = Coordinator::open(
            "test-token-0123456789".to_string(),
            vec![job(0, false)],
            out,
            state,
            Duration::from_secs(30),
            2,
            Mode::Pull,
        )
        .err()
        .expect("second coordinator must be rejected");
        assert!(error.to_string().contains("another coordinator"));
        drop(first);
    }

    #[test]
    fn a_state_file_for_another_output_is_rejected() {
        let (coordinator, out) = coordinator(vec![job(0, false)]);
        let state = coordinator.store.state_path.clone();
        drop(coordinator);
        let mut persisted: Value =
            serde_json::from_str(&std::fs::read_to_string(&state).unwrap()).unwrap();
        persisted["report"]["path"] = json!(out.with_file_name("other-report.json"));
        std::fs::write(&state, serde_json::to_vec_pretty(&persisted).unwrap()).unwrap();
        let error = Coordinator::open(
            "test-token-0123456789".to_string(),
            vec![job(0, false)],
            out,
            state,
            Duration::from_secs(30),
            2,
            Mode::Pull,
        )
        .err()
        .expect("mismatched state must be rejected");
        assert!(error.to_string().contains("belongs to output"));
    }
    #[tokio::test]
    async fn a_straggler_is_split_into_durable_work_units() {
        let (coordinator, out) = coordinator(vec![job(0, false)]);
        let state = coordinator.store.state_path.clone();
        let ClaimOutcome::Job(parent) = coordinator
            .claim("worker-a", "a", &Capabilities::default())
            .unwrap()
        else {
            panic!("expected the original job");
        };
        {
            let mut core = coordinator.core.lock().unwrap();
            core.jobs[0].started_unix_ms = Some(unix_ms().saturating_sub(SPLIT_AFTER_MS + 1));
        }
        let ClaimOutcome::Job(first_child) = coordinator
            .claim("worker-b", "b", &Capabilities::default())
            .unwrap()
        else {
            panic!("expected a split child");
        };
        {
            let core = coordinator.core.lock().unwrap();
            assert_eq!(core.jobs.len(), 3);
            assert!(matches!(core.jobs[0].status, JobStatus::Superseded));
            assert_eq!(core.jobs[first_child.job_id].work_part, Some((0, 2)));
            assert_eq!(core.jobs[first_child.job_id].parent_job_id, Some(0));
        }
        assert!(first_child.job_id > 0);
        let stale = ResultRequest {
            worker_id: "worker-a".into(),
            job_id: parent.job_id,
            report: Some(report(81)),
            error: None,
            elapsed_ms: 1,
        };
        assert!(coordinator.submit(&stale).is_err());
        coordinator
            .submit(&ResultRequest {
                worker_id: "worker-b".into(),
                job_id: first_child.job_id,
                report: Some(report(82)),
                error: None,
                elapsed_ms: 1,
            })
            .unwrap();
        drop(coordinator);

        let restored = reopen(
            &out,
            &state,
            vec![job(0, false)],
            Duration::from_secs(30),
            2,
        );
        {
            let core = restored.core.lock().unwrap();
            assert_eq!(core.jobs.len(), 3);
            assert!(matches!(core.jobs[0].status, JobStatus::Superseded));
            assert!(matches!(
                core.jobs[first_child.job_id].status,
                JobStatus::Done
            ));
            assert_eq!(core.jobs[2].work_part, Some((1, 2)));
        }
        let ClaimOutcome::Job(second_child) = restored
            .claim("worker-c", "c", &Capabilities::default())
            .unwrap()
        else {
            panic!("expected the remaining child");
        };
        restored
            .submit(&ResultRequest {
                worker_id: "worker-c".into(),
                job_id: second_child.job_id,
                report: Some(report(83)),
                error: None,
                elapsed_ms: 1,
            })
            .unwrap();
        restored.maintain().await;
        assert!(restored.is_complete());
        let merged: Value = serde_json::from_str(&std::fs::read_to_string(&out).unwrap()).unwrap();
        assert_eq!(merged["open"].as_array().unwrap().len(), 2);
    }
}
