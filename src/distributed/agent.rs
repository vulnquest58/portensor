//! Push agent that accepts scan jobs from a coordinator.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::extract::{DefaultBodyLimit, Request, State};
use axum::http::StatusCode;
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;

use super::tls::{self, TlsListener};
use super::{
    ExecuteRequest, ExecuteResponse, bearer, constant_time_eq, execute_job, is_loopback_listen,
    resolve_token, validate_report,
};
use crate::cli::DistributedAgentArgs;
use crate::diag::{self, Level};
use crate::error::AppError;

struct Agent {
    token: String,
    slots: Arc<Semaphore>,
    running: AtomicUsize,
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
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(json!({ "error": self.message }))).into_response()
    }
}

pub async fn serve(args: DistributedAgentArgs) -> Result<(), AppError> {
    let token = resolve_token(args.token)?;
    let concurrency = args.concurrency.clamp(1, 64);
    let agent = Arc::new(Agent {
        token,
        slots: Arc::new(Semaphore::new(concurrency)),
        running: AtomicUsize::new(0),
    });
    let app = Router::new()
        .route("/v1/execute", post(execute_handler))
        .route("/v1/healthz", get(health_handler))
        .layer(DefaultBodyLimit::max(256 * 1024 * 1024))
        .layer(middleware::from_fn_with_state(agent.clone(), authorize))
        .with_state(agent.clone());

    let server_tls = tls::server_config(args.tls_cert.as_deref(), args.tls_key.as_deref())?;
    if let Some(config) = server_tls {
        let listener = TlsListener::bind(&args.listen, config).await?;
        eprintln!(
            "[agent] listening on https://{}/ (concurrency {concurrency})",
            args.listen
        );
        diag::event(
            Level::Info,
            "agent_start",
            &[
                ("listen", serde_json::json!(args.listen)),
                ("scheme", serde_json::json!("https")),
                ("concurrency", serde_json::json!(concurrency)),
            ],
        );
        axum::serve(listener, app)
            .with_graceful_shutdown(shutdown())
            .await
            .map_err(|error| AppError::runtime(format!("agent failed: {error}")))?;
        return Ok(());
    }

    let listener = TcpListener::bind(&args.listen)
        .await
        .map_err(|error| AppError::runtime(format!("cannot listen on {}: {error}", args.listen)))?;
    if !is_loopback_listen(&args.listen) {
        eprintln!(
            "[agent] warning: {} is not a loopback address; the bearer token travels over \
             plaintext HTTP. Configure --tls-cert/--tls-key or use a trusted network.",
            args.listen
        );
    }
    eprintln!(
        "[agent] listening on http://{}/ (concurrency {concurrency})",
        args.listen
    );
    diag::event(
        Level::Info,
        "agent_start",
        &[
            ("listen", serde_json::json!(args.listen)),
            ("scheme", serde_json::json!("http")),
            ("concurrency", serde_json::json!(concurrency)),
        ],
    );
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown())
        .await
        .map_err(|error| AppError::runtime(format!("agent failed: {error}")))?;
    Ok(())
}

async fn shutdown() {
    crate::shutdown::wait_for_shutdown().await;
}

async fn authorize(State(agent): State<Arc<Agent>>, request: Request, next: Next) -> Response {
    match bearer(request.headers()) {
        Some(token) if constant_time_eq(&agent.token, token) => next.run(request).await,
        _ => ApiError::new(StatusCode::UNAUTHORIZED, "invalid or missing bearer token")
            .into_response(),
    }
}

async fn health_handler(State(agent): State<Arc<Agent>>) -> Json<Value> {
    Json(json!({
        "ok": true,
        "running": agent.running.load(Ordering::SeqCst),
    }))
}

async fn execute_handler(
    State(agent): State<Arc<Agent>>,
    Json(request): Json<ExecuteRequest>,
) -> Result<Json<ExecuteResponse>, ApiError> {
    let slot = agent.slots.clone().try_acquire_owned().map_err(|_| {
        ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "agent is at its concurrency limit; retry later",
        )
    })?;
    agent.running.fetch_add(1, Ordering::SeqCst);
    let job = request.job;
    let job_id = job.job_id;
    eprintln!(
        "[agent] executing job {} shard {}/{}",
        job.job_id,
        job.shard_index + 1,
        job.shard_count
    );
    diag::event(
        Level::Info,
        "agent_job_start",
        &[
            ("job_id", serde_json::json!(job.job_id)),
            ("shard_index", serde_json::json!(job.shard_index)),
            ("shard_count", serde_json::json!(job.shard_count)),
        ],
    );
    let outcome = tokio::task::spawn_blocking(move || execute_job(&job)).await;
    agent.running.fetch_sub(1, Ordering::SeqCst);
    drop(slot);

    let outcome = outcome
        .map_err(|error| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;
    diag::event(
        Level::Info,
        "agent_job_finished",
        &[
            ("job_id", serde_json::json!(job_id)),
            ("elapsed_ms", serde_json::json!(outcome.elapsed_ms)),
            ("has_report", serde_json::json!(outcome.report.is_some())),
            ("error", serde_json::json!(outcome.error)),
        ],
    );
    match outcome.report {
        Some(report) => {
            validate_report(&report)
                .map_err(|error| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, error))?;
            Ok(Json(ExecuteResponse {
                report,
                elapsed_ms: outcome.elapsed_ms,
            }))
        }
        None => Err(ApiError::new(
            StatusCode::BAD_GATEWAY,
            outcome
                .error
                .unwrap_or_else(|| "scan produced no report".to_string()),
        )),
    }
}
