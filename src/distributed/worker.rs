//! Polling worker for the distributed coordinator.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use serde_json::Value;

use super::tls::ClientTls;
use super::{
    Capabilities, ClaimRequest, ClaimResponse, HeartbeatRequest, HttpError, ResultRequest,
    execute_job, new_worker_id, normalize_base, post_json, resolve_token, syn_available,
    worker_name,
};
use crate::cli::DistributedWorkerArgs;
use crate::diag::{self, Level};
use crate::error::AppError;

fn encode<T: serde::Serialize>(value: &T) -> Result<Value, String> {
    serde_json::to_value(value).map_err(|error| format!("cannot encode request: {error}"))
}

async fn post(
    base: &str,
    token: &str,
    path: &str,
    body: Value,
    timeout: Duration,
    client_tls: &ClientTls,
) -> Result<Value, HttpError> {
    let base = base.to_string();
    let token = token.to_string();
    let path = path.to_string();
    let client_tls = client_tls.clone();
    tokio::task::spawn_blocking(move || {
        post_json(&base, &token, &path, &body, timeout, &client_tls)
    })
    .await
    .map_err(|error| HttpError::transport(format!("request task failed: {error}")))?
}

async fn heartbeat_loop(
    base: String,
    token: String,
    worker_id: String,
    job_id: usize,
    lease_secs: u64,
    mut stop: tokio::sync::watch::Receiver<bool>,
    client_tls: ClientTls,
) {
    let interval = Duration::from_secs((lease_secs / 3).clamp(1, 30));
    loop {
        if *stop.borrow() {
            break;
        }
        tokio::select! {
            _ = tokio::time::sleep(interval) => {}
            changed = stop.changed() => {
                if changed.is_err() || *stop.borrow() {
                    break;
                }
                continue;
            }
        }
        if *stop.borrow() {
            break;
        }
        let request = HeartbeatRequest {
            worker_id: worker_id.clone(),
            job_id,
        };
        let body = match encode(&request) {
            Ok(body) => body,
            Err(error) => {
                eprintln!("[worker] {error}");
                continue;
            }
        };
        match post(
            &base,
            &token,
            "/v1/heartbeat",
            body,
            Duration::from_secs(10),
            &client_tls,
        )
        .await
        {
            Ok(_) => {}
            Err(error) => {
                diag::event(
                    Level::Warn,
                    "heartbeat_failed",
                    &[
                        ("job_id", serde_json::json!(job_id)),
                        ("error", serde_json::json!(error.to_string())),
                    ],
                );
                eprintln!("[worker] heartbeat for job {job_id} failed: {error}");
            }
        }
    }
}

async fn send_result(
    base: &str,
    token: &str,
    request: &ResultRequest,
    client_tls: &ClientTls,
) -> Result<Value, String> {
    let body = encode(request)?;
    let mut last = String::new();
    for attempt in 1..=5 {
        match post(
            base,
            token,
            "/v1/result",
            body.clone(),
            Duration::from_secs(60),
            client_tls,
        )
        .await
        {
            Ok(value) => return Ok(value),
            Err(error) => {
                last = error.to_string();
                if !error.retryable() {
                    diag::event(
                        Level::Error,
                        "result_rejected",
                        &[
                            ("job_id", serde_json::json!(request.job_id)),
                            ("status", serde_json::json!(error.status())),
                            ("error", serde_json::json!(last)),
                        ],
                    );
                    eprintln!(
                        "[worker] coordinator rejected job {} result: {last}",
                        request.job_id
                    );
                    return Err(last);
                }
                if attempt < 5 {
                    diag::event(
                        Level::Warn,
                        "result_retry",
                        &[
                            ("job_id", serde_json::json!(request.job_id)),
                            ("attempt", serde_json::json!(attempt)),
                            ("error", serde_json::json!(last)),
                        ],
                    );
                    eprintln!(
                        "[worker] cannot submit job {} result (attempt {attempt}/5): {last}",
                        request.job_id
                    );
                    tokio::time::sleep(Duration::from_secs(attempt * 2)).await;
                }
            }
        }
    }
    Err(last)
}

pub async fn run(args: DistributedWorkerArgs) -> Result<(), AppError> {
    let base = normalize_base(&args.coordinator)?;
    let token = resolve_token(args.token)?;
    let client_tls = ClientTls::load(args.ca_cert.as_deref(), args.insecure_tls)?;
    let name = worker_name(args.name);
    if name.len() > 200 {
        return Err(AppError::usage(
            "worker name must be at most 200 characters",
        ));
    }
    let worker_id = new_worker_id(&name);
    let capabilities = Capabilities {
        syn: syn_available(),
    };
    eprintln!(
        "[worker] {name} ({worker_id}) polling {base} (syn={})",
        capabilities.syn
    );
    diag::event(
        Level::Info,
        "worker_start",
        &[
            ("worker_id", serde_json::json!(worker_id)),
            ("name", serde_json::json!(name)),
            ("coordinator", serde_json::json!(base)),
            ("syn", serde_json::json!(capabilities.syn)),
        ],
    );

    let stop = Arc::new(AtomicBool::new(false));
    let signal_stop = stop.clone();
    tokio::spawn(async move {
        crate::shutdown::wait_for_shutdown().await;
        signal_stop.store(true, Ordering::SeqCst);
    });

    let mut completed = 0u64;
    loop {
        if stop.load(Ordering::SeqCst) {
            break;
        }
        let request = ClaimRequest {
            worker_id: worker_id.clone(),
            name: name.clone(),
            capabilities: capabilities.clone(),
        };
        let body = encode(&request)
            .map_err(|error| AppError::runtime(format!("cannot encode claim: {error}")))?;
        let claim = match post(
            &base,
            &token,
            "/v1/claim",
            body,
            Duration::from_secs(45),
            &client_tls,
        )
        .await
        {
            Ok(value) => serde_json::from_value::<ClaimResponse>(value),
            Err(error) => {
                if error.status() == Some(401) {
                    return Err(AppError::runtime(
                        "the coordinator rejected the distributed bearer token",
                    ));
                }
                if args.once || !error.retryable() {
                    return Err(AppError::runtime(format!("cannot claim a job: {error}")));
                }
                eprintln!("[worker] cannot claim a job: {error}");
                tokio::time::sleep(Duration::from_secs(2)).await;
                continue;
            }
        };
        let claim = claim.map_err(|error| {
            AppError::runtime(format!("coordinator returned an invalid claim: {error}"))
        })?;
        let Some(job) = claim.job else {
            if claim.complete {
                break;
            }
            continue;
        };

        eprintln!(
            "[worker] job {} shard {}/{} (lease {}s)",
            job.job_id,
            job.shard_index + 1,
            job.shard_count,
            job.lease_secs
        );
        diag::event(
            Level::Info,
            "job_claimed",
            &[
                ("job_id", serde_json::json!(job.job_id)),
                ("shard_index", serde_json::json!(job.shard_index)),
                ("shard_count", serde_json::json!(job.shard_count)),
                ("lease_secs", serde_json::json!(job.lease_secs)),
            ],
        );
        let job_id = job.job_id;
        let lease_secs = job.lease_secs;
        let (heartbeat_stop, heartbeat_stop_rx) = tokio::sync::watch::channel(false);
        let heartbeat = tokio::spawn(heartbeat_loop(
            base.clone(),
            token.clone(),
            worker_id.clone(),
            job_id,
            lease_secs,
            heartbeat_stop_rx,
            client_tls.clone(),
        ));

        let job_to_execute = job;
        let outcome = tokio::task::spawn_blocking(move || execute_job(&job_to_execute)).await;
        let _ = heartbeat_stop.send(true);
        let _ = heartbeat.await;

        let result = match outcome {
            Ok(outcome) => ResultRequest {
                worker_id: worker_id.clone(),
                job_id,
                report: outcome.report,
                error: outcome.error,
                elapsed_ms: outcome.elapsed_ms,
            },
            Err(error) => ResultRequest {
                worker_id: worker_id.clone(),
                job_id,
                report: None,
                error: Some(format!("scan task failed: {error}")),
                elapsed_ms: 0,
            },
        };
        let accepted = match send_result(&base, &token, &result, &client_tls).await {
            Ok(_) => true,
            Err(error) => {
                diag::event(
                    Level::Warn,
                    "result_not_accepted",
                    &[
                        ("job_id", serde_json::json!(job_id)),
                        ("error", serde_json::json!(error.to_string())),
                    ],
                );
                eprintln!(
                    "[worker] job {job_id} finished but its result was not accepted: {error}. \
                     The coordinator will requeue the shard after the lease expires."
                );
                if args.once {
                    return Err(AppError::runtime(format!(
                        "cannot submit job {job_id} result: {error}"
                    )));
                }
                false
            }
        };
        diag::event(
            Level::Info,
            "job_finished",
            &[
                ("job_id", serde_json::json!(job_id)),
                ("accepted", serde_json::json!(accepted)),
                ("elapsed_ms", serde_json::json!(result.elapsed_ms)),
                ("has_report", serde_json::json!(result.report.is_some())),
            ],
        );

        completed += 1;
        if args.once || (args.max_jobs > 0 && completed >= args.max_jobs) {
            break;
        }
    }

    eprintln!("[worker] stopped after {completed} job(s)");
    diag::event(
        Level::Info,
        "worker_stopped",
        &[("completed", serde_json::json!(completed))],
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn heartbeat_stops_during_its_sleep() {
        let (stop, stop_rx) = tokio::sync::watch::channel(false);
        let task = tokio::spawn(heartbeat_loop(
            "http://127.0.0.1:1".to_string(),
            "token".to_string(),
            "worker".to_string(),
            1,
            300,
            stop_rx,
            ClientTls::default(),
        ));
        tokio::time::sleep(Duration::from_millis(50)).await;
        stop.send(true).expect("heartbeat task is alive");
        tokio::time::timeout(Duration::from_millis(500), task)
            .await
            .expect("heartbeat stops promptly")
            .expect("heartbeat task does not panic");
    }
}
