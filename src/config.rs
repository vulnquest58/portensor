use std::path::{Path, PathBuf};

use clap::ValueEnum;
use serde::Deserialize;

use crate::error::AppError;
use crate::model::{PortState, StateSet};
use crate::output::OutputFormat;
use crate::theme::Theme;

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StateFilter {
    Open,
    Closed,
    Filtered,
    Unfiltered,
    Silent,
    Unreachable,
    Error,
    All,
}

impl StateFilter {
    pub fn to_set(self) -> StateSet {
        match self {
            Self::Open => state_set(&[Self::Open]),
            Self::Closed => state_set(&[Self::Closed]),
            Self::Filtered => state_set(&[Self::Filtered]),
            Self::Unfiltered => state_set(&[Self::Unfiltered]),
            Self::Silent => state_set(&[Self::Silent]),
            Self::Unreachable => state_set(&[Self::Unreachable]),
            Self::Error => state_set(&[Self::Error]),
            Self::All => StateSet::all(),
        }
    }
}

pub fn state_set(filters: &[StateFilter]) -> StateSet {
    let mut set = StateSet::empty();
    for filter in filters {
        if *filter == StateFilter::All {
            return StateSet::all();
        }
        let state = match filter {
            StateFilter::Open => PortState::Open,
            StateFilter::Closed => PortState::Closed,
            StateFilter::Filtered => PortState::Filtered,
            StateFilter::Unfiltered => PortState::Unfiltered,
            StateFilter::Silent => PortState::Silent,
            StateFilter::Unreachable => PortState::Unreachable,
            StateFilter::Error => PortState::Error,
            StateFilter::All => unreachable!("handled above"),
        };
        set.insert(state);
    }
    set
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Profile {
    Fast,
    #[default]
    Balanced,
    Careful,
    Stealth,
}

impl Profile {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fast => "fast",
            Self::Balanced => "balanced",
            Self::Careful => "careful",
            Self::Stealth => "stealth",
        }
    }

    pub const fn defaults(self) -> ProfileDefaults {
        match self {
            Self::Fast => ProfileDefaults {
                timeout_seconds: 1.0,
                probe_timeout_ms: 150,
                rate: 5_000,
                workers: 0,
                retries: 1,
            },
            Self::Balanced => ProfileDefaults {
                timeout_seconds: 2.0,
                probe_timeout_ms: 300,
                rate: 1_000,
                workers: 0,
                retries: 4,
            },
            Self::Careful => ProfileDefaults {
                timeout_seconds: 5.0,
                probe_timeout_ms: 750,
                rate: 200,
                workers: 128,
                retries: 3,
            },
            Self::Stealth => ProfileDefaults {
                timeout_seconds: 5.0,
                probe_timeout_ms: 1000,
                rate: 20,
                workers: 8,
                retries: 3,
            },
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ProfileDefaults {
    pub timeout_seconds: f64,
    pub probe_timeout_ms: u64,
    pub rate: u64,
    pub workers: usize,
    pub retries: u32,
}

/// Optional TOML configuration. CLI arguments always take precedence.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileConfig {
    pub profile: Option<Profile>,
    pub timeout: Option<f64>,
    pub probe_timeout_ms: Option<u64>,
    pub rate: Option<u64>,
    pub workers: Option<usize>,
    pub host_concurrency: Option<usize>,
    pub os_probes: Option<usize>,
    pub retries: Option<u32>,
    pub randomize: Option<bool>,
    pub connect_only: Option<bool>,
    pub service_detection: Option<bool>,
    pub udp_probe: Option<bool>,
    pub sni: Option<String>,
    pub format: Option<OutputFormat>,
    pub show: Option<Vec<StateFilter>>,
    pub theme: Option<Theme>,
    pub plugins: Option<PathBuf>,
    pub scripts: Option<PathBuf>,
    pub allow_intrusive: Option<bool>,
    pub jitter_ms: Option<u64>,
    pub ttl: Option<u8>,
    pub source_port_range: Option<String>,
}

pub fn load(path: Option<&Path>) -> Result<FileConfig, AppError> {
    let path = match path {
        Some(path) => Some(path.to_path_buf()),
        None => {
            let default = PathBuf::from("portensor.toml");
            default.is_file().then_some(default)
        }
    };

    let Some(path) = path else {
        return Ok(FileConfig::default());
    };

    let contents = std::fs::read_to_string(&path).map_err(|error| {
        AppError::usage(format!("cannot read config {}: {error}", path.display()))
    })?;
    toml::from_str(&contents)
        .map_err(|error| AppError::usage(format!("invalid config {}: {error}", path.display())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_complete_config() {
        let config: FileConfig = toml::from_str(
            r#"
profile = "careful"
timeout = 3.5
probe_timeout_ms = 400
rate = 500
workers = 64
host_concurrency = 32
os_probes = 4
retries = 1
randomize = true
connect_only = false
service_detection = true
udp_probe = true
sni = "sts.example.test"
format = "jsonl"
show = ["open", "closed"]
theme = "hacker"
ttl = 64
source_port_range = "40000-40100"
"#,
        )
        .unwrap();

        assert_eq!(config.profile, Some(Profile::Careful));
        assert_eq!(config.timeout, Some(3.5));
        assert_eq!(config.host_concurrency, Some(32));
        assert_eq!(config.os_probes, Some(4));
        assert_eq!(config.service_detection, Some(true));
        assert_eq!(config.udp_probe, Some(true));
        assert_eq!(config.sni.as_deref(), Some("sts.example.test"));
        assert_eq!(config.format, Some(OutputFormat::Jsonl));
        assert_eq!(config.show.unwrap().len(), 2);
        assert_eq!(config.theme, Some(Theme::Hacker));
        assert_eq!(config.ttl, Some(64));
        assert_eq!(config.source_port_range.as_deref(), Some("40000-40100"));
    }

    #[test]
    fn rejects_unknown_config_keys() {
        let error = toml::from_str::<FileConfig>("typo = 1").unwrap_err();
        assert!(error.to_string().contains("unknown field"));
    }

    #[test]
    fn profile_defaults_are_ordered_by_caution() {
        let fast = Profile::Fast.defaults();
        let balanced = Profile::Balanced.defaults();
        let careful = Profile::Careful.defaults();
        let stealth = Profile::Stealth.defaults();

        assert!(
            fast.rate > balanced.rate
                && balanced.rate > careful.rate
                && careful.rate > stealth.rate
        );
        assert!(fast.timeout_seconds < balanced.timeout_seconds);
        assert!(balanced.timeout_seconds < careful.timeout_seconds);
        assert!(careful.timeout_seconds <= stealth.timeout_seconds);
    }

    #[test]
    fn state_filters_union_and_all_short_circuits() {
        let set = state_set(&[StateFilter::Open, StateFilter::Closed]);
        assert!(set.contains(PortState::Open));
        assert!(set.contains(PortState::Closed));
        assert!(!set.contains(PortState::Filtered));
        assert_eq!(
            state_set(&[StateFilter::Open, StateFilter::All]),
            StateSet::all()
        );

        let unfiltered = StateFilter::Unfiltered.to_set();
        assert!(unfiltered.contains(PortState::Unfiltered));
        assert!(!unfiltered.contains(PortState::Open));
    }
}
