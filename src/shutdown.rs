//! Cross-platform graceful-termination signal handling.
//!
//! Containers and service managers usually send `SIGTERM`, while an
//! interactive terminal sends `SIGINT`. Both should take the same graceful
//! path: stop claiming work, save partial state, and let in-flight results
//! finish where the caller supports it.

/// Resolve on the first interrupt or termination request.
pub async fn wait_for_shutdown() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};

        let mut terminate = match signal(SignalKind::terminate()) {
            Ok(signal) => signal,
            Err(_) => {
                let _ = tokio::signal::ctrl_c().await;
                return;
            }
        };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = terminate.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
