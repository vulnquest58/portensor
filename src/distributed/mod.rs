//! Distributed scanning.
//!
//! The coordinator hands out deterministic target shards as `rayscan scan`
//! command lines. Workers and push agents execute the same binary locally, so
//! every node runs the full verification pipeline, and the coordinator merges
//! the returned JSON reports with [`crate::merge`].
//!
//! Three deployment shapes are supported:
//! - `distributed plan`: emit a shell script that runs shards locally.
//! - `distributed serve` plus `distributed worker`: workers poll the
//!   token-authenticated HTTP/JSON control plane.
//! - `distributed serve --agents` plus `distributed agent`: the coordinator
//!   pushes jobs to inbound agents.

pub mod agent;
pub mod coordinator;
pub mod worker;

use std::io::Write as _;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum::http::HeaderMap;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::cli::{DistributedArgs, DistributedPlanArgs, DistributedShell};
use crate::error::AppError;

/// Minimum accepted bearer-token length.
pub const MIN_TOKEN_LEN: usize = 16;

/// Upper bound for a single shard job.
pub const MAX_JOB_TIMEOUT_SECS: u64 = 7 * 24 * 60 * 60;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Capabilities {
    #[serde(default)]
    pub syn: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClaimRequest {
    pub worker_id: String,
    pub name: String,
    #[serde(default)]
    pub capabilities: Capabilities,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JobAssignment {
    pub job_id: usize,
    pub shard_index: usize,
    pub shard_count: usize,
    pub args: Vec<String>,
    pub timeout_secs: u64,
    pub lease_secs: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClaimResponse {
    pub job: Option<JobAssignment>,
    pub complete: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HeartbeatRequest {
    pub worker_id: String,
    pub job_id: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResultRequest {
    pub worker_id: String,
    pub job_id: usize,
    #[serde(default)]
    pub report: Option<Value>,
    #[serde(default)]
    pub error: Option<String>,
    pub elapsed_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExecuteRequest {
    pub job: JobAssignment,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExecuteResponse {
    pub report: Value,
    pub elapsed_ms: u64,
}

#[derive(Clone, Debug)]
pub struct PlannedJob {
    pub shard_index: usize,
    pub shard_count: usize,
    pub args: Vec<String>,
    pub requires_raw: bool,
    pub timeout_secs: u64,
}

#[derive(Clone, Debug)]
pub struct JobOutcome {
    pub report: Option<Value>,
    pub error: Option<String>,
    pub elapsed_ms: u64,
}

/// Validate and expand the scan template into one job per deterministic shard.
pub fn build_jobs(
    scan_args: &[String],
    shards: usize,
    timeout_secs: u64,
) -> Result<Vec<PlannedJob>, AppError> {
    if !(1..=crate::shard::MAX_SHARDS).contains(&shards) {
        return Err(AppError::usage(format!(
            "--shards must be between 1 and {}",
            crate::shard::MAX_SHARDS
        )));
    }
    if scan_args.first().map(String::as_str) != Some("scan") {
        return Err(AppError::usage(
            "distributed scan arguments must start with `scan`, for example: \
             -- scan --target 10.0.0.0/24 --ports 22,80,443",
        ));
    }
    let base = normalize_scan_args(&scan_args[1..])?;
    if !has_target(&base) {
        return Err(AppError::usage(
            "distributed scan arguments must include --target or --target-file",
        ));
    }
    let requires_raw = base
        .iter()
        .any(|arg| matches!(arg.as_str(), "--syn" | "--os" | "--ndp"));
    let mut jobs = Vec::with_capacity(shards);
    for shard_index in 0..shards {
        let mut args = Vec::with_capacity(base.len() + 8);
        args.push("scan".to_string());
        args.extend(base.iter().cloned());
        args.push("--format".to_string());
        args.push("json".to_string());
        args.push("--shard-index".to_string());
        args.push(shard_index.to_string());
        args.push("--shard-count".to_string());
        args.push(shards.to_string());
        jobs.push(PlannedJob {
            shard_index,
            shard_count: shards,
            args,
            requires_raw,
            timeout_secs: timeout_secs.clamp(1, MAX_JOB_TIMEOUT_SECS),
        });
    }
    Ok(jobs)
}

fn has_target(args: &[String]) -> bool {
    args.iter().any(|arg| {
        arg == "--target"
            || arg == "-t"
            || arg == "--target-file"
            || arg.starts_with("--target=")
            || arg.starts_with("--target-file=")
            || (arg.starts_with("-t") && !arg.starts_with("--") && arg.len() > 2)
    })
}

fn normalize_scan_args(args: &[String]) -> Result<Vec<String>, AppError> {
    let mut normalized = Vec::with_capacity(args.len());
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        let name = arg.split('=').next().unwrap_or(arg);

        if matches!(
            name,
            "--format" | "--output" | "-o" | "--shard-index" | "--shard-count"
        ) {
            index += if arg.contains('=') { 1 } else { 2 };
            continue;
        }
        if arg.starts_with("-o") && !arg.starts_with("--") && arg.len() > 2 {
            index += 1;
            continue;
        }
        if arg == "--json" {
            index += 1;
            continue;
        }
        if matches!(
            name,
            "--resume"
                | "--save-state"
                | "--diff"
                | "--compare-to"
                | "--save-baseline"
                | "--alert-file"
                | "--fail-on-change"
                | "--stream"
        ) {
            return Err(AppError::usage(format!(
                "{name} is not supported in distributed scan jobs"
            )));
        }
        normalized.push(arg.clone());
        index += 1;
    }
    Ok(normalized)
}

pub fn resolve_token(token: Option<String>) -> Result<String, AppError> {
    let token = token
        .or_else(|| std::env::var("RAYSCAN_DISTRIBUTED_TOKEN").ok())
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            AppError::usage("a bearer token is required (--token or RAYSCAN_DISTRIBUTED_TOKEN)")
        })?;
    if token.len() < MIN_TOKEN_LEN {
        return Err(AppError::usage(format!(
            "distributed token must be at least {MIN_TOKEN_LEN} characters"
        )));
    }
    Ok(token)
}

pub fn constant_time_eq(expected: &str, provided: &str) -> bool {
    let (expected, provided) = (expected.as_bytes(), provided.as_bytes());
    if expected.len() != provided.len() {
        return false;
    }
    let mut difference = 0u8;
    for (left, right) in expected.iter().zip(provided) {
        difference |= left ^ right;
    }
    difference == 0
}

pub fn local_hostname() -> String {
    std::env::var("HOSTNAME")
        .or_else(|_| std::env::var("COMPUTERNAME"))
        .unwrap_or_else(|_| "worker".to_string())
}

pub fn worker_name(requested: Option<String>) -> String {
    requested
        .map(|name| name.trim().to_string())
        .filter(|name| !name.is_empty())
        .unwrap_or_else(local_hostname)
}

pub fn new_worker_id(name: &str) -> String {
    format!(
        "{name}-{}-{:016x}",
        std::process::id(),
        rand::random::<u64>()
    )
}

pub fn syn_available() -> bool {
    #[cfg(target_os = "linux")]
    {
        unsafe { libc::geteuid() == 0 }
    }
    #[cfg(not(target_os = "linux"))]
    {
        false
    }
}

pub fn normalize_base(url: &str) -> Result<String, AppError> {
    let trimmed = url.trim().trim_end_matches('/');
    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        Ok(trimmed.to_string())
    } else {
        Err(AppError::usage(
            "distributed URLs must start with http:// or https://",
        ))
    }
}

pub fn bearer(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
}

pub fn post_json(
    base: &str,
    token: &str,
    path: &str,
    body: &Value,
    timeout: Duration,
) -> Result<Value, String> {
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(10))
        .timeout(timeout)
        .build();
    let response = agent
        .post(&format!("{base}{path}"))
        .set("Authorization", &format!("Bearer {token}"))
        .set("Content-Type", "application/json")
        .send_json(body.clone());
    match response {
        Ok(response) => response
            .into_json::<Value>()
            .map_err(|error| format!("invalid JSON response from {base}{path}: {error}")),
        Err(ureq::Error::Status(code, response)) => {
            let detail = response
                .into_json::<Value>()
                .ok()
                .and_then(|value| {
                    value
                        .get("error")
                        .and_then(Value::as_str)
                        .map(str::to_string)
                })
                .unwrap_or_else(|| format!("HTTP {code}"));
            Err(detail)
        }
        Err(error) => Err(format!("cannot reach {base}{path}: {error}")),
    }
}

pub fn validate_report(value: &Value) -> Result<(), String> {
    let object = value
        .as_object()
        .ok_or_else(|| "shard report must be a JSON object".to_string())?;
    if let Some(open) = object.get("open")
        && !open.is_array()
    {
        return Err("shard report `open` field must be an array".to_string());
    }
    if let Some(results) = object.get("results")
        && !results.is_array()
    {
        return Err("shard report `results` field must be an array".to_string());
    }
    if !object.contains_key("open") && !object.contains_key("results") {
        return Err("shard report contains neither `open` nor `results`".to_string());
    }
    Ok(())
}

/// Return true when a listen address is limited to the local host.
pub fn is_loopback_listen(listen: &str) -> bool {
    let listen = listen.trim();
    let host = match listen.rsplit_once(':') {
        Some((host, _)) => host,
        None => listen,
    };
    let host = host.trim_start_matches('[').trim_end_matches(']');
    host == "localhost"
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|address| address.is_loopback())
}

pub async fn run_cli(args: DistributedArgs) -> Result<(), AppError> {
    match args.action {
        crate::cli::DistributedAction::Plan(args) => run_plan(args),
        crate::cli::DistributedAction::Serve(args) => coordinator::serve(args).await,
        crate::cli::DistributedAction::Worker(args) => worker::run(args).await,
        crate::cli::DistributedAction::Agent(args) => agent::serve(args).await,
    }
}

fn run_plan(args: DistributedPlanArgs) -> Result<(), AppError> {
    let jobs = build_jobs(&args.scan_args, args.shards, 0)?;
    let script = plan_script(&jobs, args.shell);
    match args.output.as_deref() {
        Some(path) if path.as_os_str() != "-" => {
            if let Some(parent) = path.parent()
                && !parent.as_os_str().is_empty()
            {
                std::fs::create_dir_all(parent).map_err(|error| {
                    AppError::runtime(format!(
                        "cannot create output directory {}: {error}",
                        parent.display()
                    ))
                })?;
            }
            std::fs::write(path, script).map_err(|error| {
                AppError::runtime(format!("cannot write {}: {error}", path.display()))
            })?;
            eprintln!("wrote {}", path.display());
        }
        _ => print!("{script}"),
    }
    Ok(())
}

fn plan_script(jobs: &[PlannedJob], shell: DistributedShell) -> String {
    let mut script = String::new();
    match shell {
        DistributedShell::Bash => {
            script.push_str("#!/usr/bin/env bash\nset -euo pipefail\nmkdir -p shards\n");
            for job in jobs {
                let mut args = job.args.clone();
                args.push("--output".to_string());
                args.push(format!("shards/shard-{}.json", job.shard_index));
                script.push_str(
                    &args
                        .iter()
                        .map(|arg| bash_quote(arg))
                        .collect::<Vec<_>>()
                        .join(" "),
                );
                script.push('\n');
            }
            script.push_str("rayscan merge shards/shard-*.json --output merged.json\n");
        }
        DistributedShell::Powershell => {
            script.push_str("$ErrorActionPreference = 'Stop'\nNew-Item -ItemType Directory -Force -Path shards | Out-Null\n");
            for job in jobs {
                let mut args = job.args.clone();
                args.push("--output".to_string());
                args.push(format!("shards/shard-{}.json", job.shard_index));
                script.push_str("& rayscan ");
                script.push_str(
                    &args
                        .iter()
                        .map(|arg| powershell_quote(arg))
                        .collect::<Vec<_>>()
                        .join(" "),
                );
                script.push('\n');
            }
            script.push_str("& rayscan merge (Get-ChildItem shards/*.json | ForEach-Object FullName) --output merged.json\n");
        }
    }
    script
}

fn bash_quote(value: &str) -> String {
    if !value.is_empty()
        && value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_./:=@%+,.".contains(c))
    {
        value.to_string()
    } else {
        format!("'{}'", value.replace('\'', "'\\''"))
    }
}

fn powershell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}

/// Execute one scan job with the current binary and capture its JSON report.
pub fn execute_job(job: &JobAssignment) -> JobOutcome {
    let started = Instant::now();
    let mut outcome = JobOutcome {
        report: None,
        error: None,
        elapsed_ms: 0,
    };
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    let workspace = std::env::temp_dir().join(format!(
        "rayscan-distributed-{}-{stamp}",
        std::process::id()
    ));
    if let Err(error) = std::fs::create_dir_all(&workspace) {
        outcome.error = Some(format!(
            "cannot create job workspace {}: {error}",
            workspace.display()
        ));
        outcome.elapsed_ms = started.elapsed().as_millis() as u64;
        return outcome;
    }

    let stdout_path = workspace.join("report.json");
    let stderr_path = workspace.join("stderr.log");
    let stdout = match std::fs::File::create(&stdout_path) {
        Ok(file) => file,
        Err(error) => {
            outcome.error = Some(format!("cannot create report file: {error}"));
            let _ = std::fs::remove_dir_all(&workspace);
            outcome.elapsed_ms = started.elapsed().as_millis() as u64;
            return outcome;
        }
    };
    let stderr = match std::fs::File::create(&stderr_path) {
        Ok(file) => file,
        Err(error) => {
            outcome.error = Some(format!("cannot create log file: {error}"));
            let _ = std::fs::remove_dir_all(&workspace);
            outcome.elapsed_ms = started.elapsed().as_millis() as u64;
            return outcome;
        }
    };

    let executable = match std::env::current_exe() {
        Ok(path) => path,
        Err(error) => {
            outcome.error = Some(format!("cannot locate the rayscan binary: {error}"));
            let _ = std::fs::remove_dir_all(&workspace);
            outcome.elapsed_ms = started.elapsed().as_millis() as u64;
            return outcome;
        }
    };

    let mut child = match Command::new(executable)
        .args(&job.args)
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .spawn()
    {
        Ok(child) => child,
        Err(error) => {
            outcome.error = Some(format!("cannot start scan job: {error}"));
            let _ = std::fs::remove_dir_all(&workspace);
            outcome.elapsed_ms = started.elapsed().as_millis() as u64;
            return outcome;
        }
    };

    let timeout = Duration::from_secs(job.timeout_secs.max(1));
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                if status.success() {
                    match std::fs::read_to_string(&stdout_path)
                        .map_err(|error| format!("cannot read job report: {error}"))
                        .and_then(|text| {
                            serde_json::from_str::<Value>(&text)
                                .map_err(|error| format!("job report is not valid JSON: {error}"))
                        })
                        .and_then(|value| {
                            if value.is_object() {
                                Ok(value)
                            } else {
                                Err("job report must be a JSON object".to_string())
                            }
                        }) {
                        Ok(value) => outcome.report = Some(value),
                        Err(error) => outcome.error = Some(error),
                    }
                } else {
                    let details = std::fs::read_to_string(&stderr_path).unwrap_or_default();
                    let details = tail(&details, 2000);
                    outcome.error = Some(format!(
                        "scan exited with {status}{}",
                        if details.is_empty() {
                            String::new()
                        } else {
                            format!(": {details}")
                        }
                    ));
                }
                break;
            }
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    outcome.error = Some(format!(
                        "scan exceeded the {}s job timeout",
                        job.timeout_secs.max(1)
                    ));
                    break;
                }
                std::thread::sleep(Duration::from_millis(200));
            }
            Err(error) => {
                outcome.error = Some(format!("cannot wait for scan: {error}"));
                break;
            }
        }
    }

    let _ = std::fs::remove_dir_all(&workspace);
    outcome.elapsed_ms = started.elapsed().as_millis() as u64;
    outcome
}

fn tail(text: &str, limit: usize) -> String {
    let trimmed = text.trim();
    if trimmed.len() <= limit {
        return trimmed.to_string();
    }
    let mut start = trimmed.len() - limit;
    while !trimmed.is_char_boundary(start) {
        start += 1;
    }
    format!("…{}", &trimmed[start..])
}

pub fn write_report(path: &Path, output: &str) -> Result<(), AppError> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).map_err(|error| {
            AppError::runtime(format!(
                "cannot create output directory {}: {error}",
                parent.display()
            ))
        })?;
    }
    let mut file = std::fs::File::create(path)
        .map_err(|error| AppError::runtime(format!("cannot write {}: {error}", path.display())))?;
    file.write_all(output.as_bytes())
        .map_err(|error| AppError::runtime(format!("cannot write {}: {error}", path.display())))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scan(args: &[&str]) -> Vec<String> {
        std::iter::once("scan".to_string())
            .chain(args.iter().map(|arg| arg.to_string()))
            .collect()
    }

    #[test]
    fn jobs_force_json_and_shard_flags() {
        let args = scan(&[
            "--target",
            "10.0.0.0/24",
            "--ports",
            "22,80",
            "--format",
            "table",
            "--json",
            "--output",
            "out.json",
        ]);
        let jobs = build_jobs(&args, 4, 60).unwrap();
        assert_eq!(jobs.len(), 4);
        assert_eq!(jobs[0].shard_index, 0);
        assert_eq!(jobs[0].shard_count, 4);
        assert_eq!(jobs[0].args[0], "scan");
        assert!(
            jobs[0]
                .args
                .windows(2)
                .any(|pair| pair == ["--format", "json"])
        );
        assert!(!jobs[0].args.iter().any(|arg| arg == "table"));
        assert!(!jobs[0].args.iter().any(|arg| arg == "--json"));
        assert!(!jobs[0].args.iter().any(|arg| arg == "out.json"));
        assert!(
            jobs[0]
                .args
                .windows(2)
                .any(|pair| pair == ["--shard-index", "0"])
        );
        assert!(
            jobs[3]
                .args
                .windows(2)
                .any(|pair| pair == ["--shard-index", "3"])
        );
        assert_eq!(
            jobs[3].args.iter().filter(|arg| *arg == "--format").count(),
            1
        );
    }

    #[test]
    fn jobs_accept_attached_short_target_and_output() {
        let jobs = build_jobs(&scan(&["-t10.0.0.0/30", "-oout.json"]), 1, 60).unwrap();
        assert!(jobs[0].args.iter().any(|arg| arg == "-t10.0.0.0/30"));
        assert!(!jobs[0].args.iter().any(|arg| arg.contains("out.json")));
        let jobs = build_jobs(
            &scan(&["-t", "10.0.0.1", "-o", "out.json", "--timeout", "1"]),
            1,
            60,
        )
        .unwrap();
        assert!(jobs[0].args.iter().any(|arg| arg == "--timeout"));
        assert!(!jobs[0].args.iter().any(|arg| arg == "out.json"));
    }

    #[test]
    fn jobs_require_scan_prefix_and_targets() {
        assert_eq!(
            build_jobs(&["probes".into(), "list".into()], 2, 60)
                .unwrap_err()
                .exit_code(),
            2
        );
        assert_eq!(
            build_jobs(&scan(&["--ports", "80"]), 2, 60)
                .unwrap_err()
                .exit_code(),
            2
        );
        assert_eq!(
            build_jobs(&scan(&["-t", "10.0.0.1"]), 0, 60)
                .unwrap_err()
                .exit_code(),
            2
        );
        assert_eq!(
            build_jobs(&scan(&["-t", "10.0.0.1"]), crate::shard::MAX_SHARDS + 1, 60)
                .unwrap_err()
                .exit_code(),
            2
        );
    }

    #[test]
    fn jobs_reject_side_effect_flags() {
        for flag in ["--resume", "--save-state", "--stream", "--diff"] {
            let args = scan(&["-t", "10.0.0.1", flag, "state.json"]);
            let error = build_jobs(&args, 2, 60).unwrap_err();
            assert_eq!(error.exit_code(), 2, "{flag}");
        }
    }

    #[test]
    fn jobs_mark_raw_engine_requirements() {
        assert!(build_jobs(&scan(&["-t", "10.0.0.1", "--syn"]), 1, 60).unwrap()[0].requires_raw);
        assert!(build_jobs(&scan(&["-t", "10.0.0.1", "--os"]), 1, 60).unwrap()[0].requires_raw);
        assert!(!build_jobs(&scan(&["-t", "10.0.0.1"]), 1, 60).unwrap()[0].requires_raw);
    }

    #[test]
    fn plan_contains_every_shard_and_merge() {
        let args = scan(&["--target", "10.0.0.0/30", "--ports", "80"]);
        let jobs = build_jobs(&args, 2, 0).unwrap();
        let script = plan_script(&jobs, DistributedShell::Bash);
        assert!(script.contains("--shard-index 0"));
        assert!(script.contains("--shard-index 1"));
        assert!(script.contains("shards/shard-0.json"));
        assert!(script.contains("rayscan merge shards/shard-*.json"));
        let script = plan_script(&jobs, DistributedShell::Powershell);
        assert!(script.contains("& rayscan 'scan'"));
        assert!(script.contains("'--shard-index' '1'"));
        assert!(script.contains("Get-ChildItem shards/*.json"));
    }

    #[test]
    fn quotes_are_safe() {
        assert_eq!(bash_quote("a b"), "'a b'");
        assert_eq!(bash_quote("it's"), "'it'\\''s'");
        assert_eq!(bash_quote("*.example.com"), "'*.example.com'");
        assert_eq!(powershell_quote("it's"), "'it''s'");
    }

    #[test]
    fn listen_addresses_are_classified() {
        assert!(is_loopback_listen("127.0.0.1:9090"));
        assert!(is_loopback_listen("localhost:9090"));
        assert!(is_loopback_listen("[::1]:9090"));
        assert!(!is_loopback_listen("0.0.0.0:9090"));
        assert!(!is_loopback_listen("localhost.example.com:9090"));
    }

    #[test]
    fn reports_need_a_results_container() {
        assert!(validate_report(&serde_json::json!({ "open": [] })).is_ok());
        assert!(validate_report(&serde_json::json!({ "results": [] })).is_ok());
        assert!(validate_report(&serde_json::json!({ "targets": 0 })).is_err());
    }

    #[test]
    fn tokens_are_validated() {
        assert!(resolve_token(Some("x".repeat(MIN_TOKEN_LEN))).is_ok());
        assert_eq!(
            resolve_token(Some("short".into())).unwrap_err().exit_code(),
            2
        );
        assert_eq!(resolve_token(None).unwrap_err().exit_code(), 2);
        assert!(constant_time_eq("abcdef", "abcdef"));
        assert!(!constant_time_eq("abcdef", "abcdeg"));
        assert!(!constant_time_eq("abcdef", "abcde"));
    }

    #[test]
    fn protocol_roundtrips() {
        let job = JobAssignment {
            job_id: 1,
            shard_index: 2,
            shard_count: 8,
            args: vec!["scan".into(), "-t".into(), "10.0.0.1".into()],
            timeout_secs: 60,
            lease_secs: 30,
        };
        let encoded = serde_json::to_string(&job).unwrap();
        let decoded: JobAssignment = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded.args, job.args);
        let result = ResultRequest {
            worker_id: "w".into(),
            job_id: 1,
            report: Some(serde_json::json!({"open": []})),
            error: None,
            elapsed_ms: 5,
        };
        let encoded = serde_json::to_string(&result).unwrap();
        let decoded: ResultRequest = serde_json::from_str(&encoded).unwrap();
        assert!(decoded.report.is_some());
    }
}
