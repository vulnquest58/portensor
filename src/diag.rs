//! Opt-in structured diagnostics for unattended and distributed scans.
//!
//! Diagnostics are JSON lines on stderr so machine-readable reports on stdout
//! stay untouched. Structured logging is opt-in: set `--log-level` or
//! `PORTENSOR_LOG=error|warn|info|debug|trace` for one process.
//!
//! Records contain only operational metadata (counts, target addresses, ports,
//! retry decisions, and error classes). Banners, payloads, tokens, and report
//! contents are never logged.

use std::io::Write;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use clap::ValueEnum;
use serde_json::{Map, Value, json};

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
#[value(rename_all = "lower")]
pub enum Level {
    Off,
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl Level {
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "off" | "none" => Some(Self::Off),
            "error" => Some(Self::Error),
            "warn" | "warning" => Some(Self::Warn),
            "info" => Some(Self::Info),
            "debug" => Some(Self::Debug),
            "trace" => Some(Self::Trace),
            _ => None,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Error => "error",
            Self::Warn => "warn",
            Self::Info => "info",
            Self::Debug => "debug",
            Self::Trace => "trace",
        }
    }

    const fn rank(self) -> u8 {
        match self {
            Self::Off => 0,
            Self::Error => 1,
            Self::Warn => 2,
            Self::Info => 3,
            Self::Debug => 4,
            Self::Trace => 5,
        }
    }
}

static LEVEL: AtomicU8 = AtomicU8::new(Level::Off.rank());

/// Apply the CLI override, then `PORTENSOR_LOG`, then stay off.
pub fn init(explicit: Option<Level>) {
    let level = explicit
        .or_else(|| {
            std::env::var("PORTENSOR_LOG")
                .ok()
                .and_then(|value| Level::parse(&value))
        })
        .unwrap_or(Level::Off);
    set_level(level);
}

pub fn set_level(level: Level) {
    LEVEL.store(level.rank(), Ordering::Relaxed);
}

pub fn enabled(level: Level) -> bool {
    level != Level::Off && level.rank() <= LEVEL.load(Ordering::Relaxed)
}

/// Emit one structured record when `level` is enabled.
pub fn event(level: Level, event: &str, fields: &[(&str, Value)]) {
    if !enabled(level) {
        return;
    }
    let record = format_record(level, event, fields, timestamp_ms());
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "{record}");
}

fn timestamp_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or(0)
}

fn format_record(level: Level, event: &str, fields: &[(&str, Value)], ts_ms: u128) -> String {
    let mut record = Map::new();
    record.insert("ts_ms".to_string(), json!(ts_ms));
    record.insert("level".to_string(), json!(level.as_str()));
    record.insert("event".to_string(), json!(event));
    for (key, value) in fields {
        if !matches!(*key, "ts_ms" | "level" | "event") {
            record.insert((*key).to_string(), value.clone());
        }
    }
    serde_json::to_string(&Value::Object(record))
        .unwrap_or_else(|_| r#"{"level":"error","event":"diagnostic_encode_failed"}"#.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_levels_case_insensitively() {
        assert_eq!(Level::parse(" WARNING "), Some(Level::Warn));
        assert_eq!(Level::parse("DEBUG"), Some(Level::Debug));
        assert_eq!(Level::parse("off"), Some(Level::Off));
        assert_eq!(Level::parse("verbose"), None);
    }

    #[test]
    fn record_is_valid_json_and_does_not_allow_field_override() {
        let record = format_record(
            Level::Info,
            "scan_start",
            &[
                ("targets", json!(2)),
                ("level", json!("forged")),
                ("event", json!("forged")),
            ],
            42,
        );
        let value: Value = serde_json::from_str(&record).unwrap();
        assert_eq!(value["ts_ms"], 42);
        assert_eq!(value["level"], "info");
        assert_eq!(value["event"], "scan_start");
        assert_eq!(value["targets"], 2);
    }

    #[test]
    fn record_escapes_newlines() {
        let record = format_record(Level::Warn, "test", &[("detail", json!("a\nb"))], 1);
        let value: Value = serde_json::from_str(&record).unwrap();
        assert_eq!(value["detail"], "a\nb");
        assert!(!record.contains('\n'));
    }
}
