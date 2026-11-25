use std::fmt;
use std::path::Path;
#[cfg(test)]
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::cli::{ScanArgs, SmartArgs};
use crate::error::AppError;
use crate::theme::Theme;

const PLAN_SCHEMA: u32 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PlanMode {
    Syn,
    Connect,
    Ack,
}

impl PlanMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Syn => "syn",
            Self::Connect => "connect",
            Self::Ack => "ack",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanTargets {
    pub inputs: Vec<String>,
    pub hosts: u64,
    pub ipv6: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanPorts {
    pub spec: String,
    pub count: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanDecision {
    pub name: String,
    pub value: String,
    pub source: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanFallback {
    pub requested: String,
    pub selected: String,
    pub rationale: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanScope {
    pub program: String,
    pub file: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanPlan {
    pub schema: u32,
    pub profile: String,
    pub mode: PlanMode,
    pub targets: PlanTargets,
    pub ports: PlanPorts,
    pub estimated_probes: u64,
    pub required_privileges: Vec<String>,
    pub fallback: Option<PlanFallback>,
    pub risk_notes: Vec<String>,
    pub decisions: Vec<PlanDecision>,
    pub scope: Option<PlanScope>,
}

impl ScanPlan {
    pub fn render_human(&self) -> String {
        let mut out = String::new();
        out.push_str("Scan plan\n");
        out.push_str(&format!("  Profile:              {}\n", self.profile));
        out.push_str(&format!("  Mode:                 {}\n", self.mode.as_str()));
        out.push_str(&format!(
            "  Targets:              {} host(s){}\n",
            self.targets.hosts,
            if self.targets.ipv6 { ", IPv6" } else { "" }
        ));
        out.push_str(&format!(
            "  Ports:                {} ({} port(s))\n",
            self.ports.spec, self.ports.count
        ));
        out.push_str(&format!(
            "  Estimated probes:     {}\n",
            self.estimated_probes
        ));
        out.push_str(&format!(
            "  Required privileges:  {}\n",
            self.required_privileges.join(", ")
        ));
        if let Some(scope) = &self.scope {
            out.push_str(&format!(
                "  Scope:                {} ({})\n",
                scope.program, scope.file
            ));
        }
        if let Some(fallback) = &self.fallback {
            out.push_str(&format!(
                "  Fallback:             {} -> {}\n",
                fallback.requested, fallback.selected
            ));
            out.push_str(&format!("    Rationale:          {}\n", fallback.rationale));
        }
        out.push_str("\n  Decisions:\n");
        for decision in &self.decisions {
            out.push_str(&format!(
                "    {:<20} {} ({})\n",
                decision.name, decision.value, decision.source
            ));
        }
        if !self.risk_notes.is_empty() {
            out.push_str("\n  Risk notes:\n");
            for note in &self.risk_notes {
                out.push_str(&format!("    - {note}\n"));
            }
        }
        out
    }
}

impl fmt::Display for ScanPlan {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.render_human())
    }
}

pub async fn build(args: &ScanArgs) -> Result<ScanPlan, AppError> {
    build_with_privilege(args, crate::syn::check_raw_privilege().is_ok()).await
}

pub async fn build_with_privilege(
    args: &ScanArgs,
    raw_available: bool,
) -> Result<ScanPlan, AppError> {
    build_internal(args, raw_available, true).await
}

pub async fn build_for_interactive(
    args: &ScanArgs,
    raw_available: bool,
) -> Result<ScanPlan, AppError> {
    build_internal(args, raw_available, false).await
}

async fn build_internal(
    args: &ScanArgs,
    raw_available: bool,
    auto_select_syn: bool,
) -> Result<ScanPlan, AppError> {
    let resolved = args.resolve()?;
    let (ports, ports_spec) = args.resolve_ports_for(resolved.format)?;
    let targets = crate::targets::resolve_targets_with_ndp(
        &args.target,
        &args.target_file,
        &args.exclude,
        resolved.family,
        None,
    )
    .await?;
    let expanded_specs = crate::targets::expand_target_specs(&args.target, &args.target_file)?;

    let scope = if let Some(path) = &args.scope {
        let guard = crate::scope::ScopeGuard::load_from_file(path)?;
        guard.validate(&expanded_specs, &targets, args.force_out_of_scope)?;
        Some(PlanScope {
            program: guard.program.clone(),
            file: path.display().to_string(),
        })
    } else {
        None
    };

    let mut fallback = None;
    let mode = if args.ack {
        PlanMode::Ack
    } else if args.connect_only {
        PlanMode::Connect
    } else if args.syn {
        if raw_available {
            PlanMode::Syn
        } else {
            fallback = Some(PlanFallback {
                requested: "syn".to_string(),
                selected: "connect".to_string(),
                rationale:
                    "raw SYN privileges are unavailable; TCP connect preserves result accuracy at lower speed"
                        .to_string(),
            });
            PlanMode::Connect
        }
    } else if auto_select_syn && raw_available {
        PlanMode::Syn
    } else {
        if auto_select_syn {
            fallback = Some(PlanFallback {
                requested: "auto".to_string(),
                selected: "connect".to_string(),
                rationale:
                    "raw SYN privileges are unavailable; automatic mode selected TCP connect"
                        .to_string(),
            });
        }
        PlanMode::Connect
    };

    let mut decisions = Vec::new();
    decisions.push(PlanDecision {
        name: "profile".to_string(),
        value: resolved.profile.as_str().to_string(),
        source: if args.stealth {
            "--stealth".to_string()
        } else if args.profile.is_some() {
            "--profile".to_string()
        } else {
            "default/config".to_string()
        },
    });
    decisions.push(PlanDecision {
        name: "mode".to_string(),
        value: mode.as_str().to_string(),
        source: if args.ack {
            "--ack".to_string()
        } else if args.syn {
            "--syn".to_string()
        } else if args.connect_only {
            "--connect-only".to_string()
        } else if !auto_select_syn {
            "interactive selection (connect)".to_string()
        } else if raw_available {
            "auto (raw privileges available)".to_string()
        } else {
            "auto fallback (no raw privileges)".to_string()
        },
    });
    decisions.push(PlanDecision {
        name: "ports".to_string(),
        value: ports_spec.clone(),
        source: if args.ports.is_some() {
            "--ports".to_string()
        } else if args.top_ports.is_some() {
            "--top-ports".to_string()
        } else if args.preset.is_some() {
            "--preset".to_string()
        } else if resolved.format == crate::output::OutputFormat::PortList {
            "port-list discovery default (1-65535)".to_string()
        } else {
            "default (1-1024)".to_string()
        },
    });
    decisions.push(PlanDecision {
        name: "family".to_string(),
        value: if args.ipv6 {
            "ipv6".to_string()
        } else if args.ipv4 {
            "ipv4".to_string()
        } else {
            match resolved.family {
                crate::targets::AddressFamily::Any => "any",
                crate::targets::AddressFamily::V4 => "ipv4",
                crate::targets::AddressFamily::V6 => "ipv6",
            }
            .to_string()
        },
        source: if args.ipv6 || args.ipv4 {
            "explicit".to_string()
        } else {
            "default".to_string()
        },
    });
    decisions.push(PlanDecision {
        name: "service_detection".to_string(),
        value: resolved.service_detection.to_string(),
        source: if args.no_service_detection {
            "--no-service-detection".to_string()
        } else if args.connect_only || args.discover_only {
            "implied off".to_string()
        } else {
            "default".to_string()
        },
    });
    decisions.push(PlanDecision {
        name: "tls_inspection".to_string(),
        value: format!("{:?}", resolved.tls_mode).to_ascii_lowercase(),
        source: if args.tls {
            "--tls".to_string()
        } else if args.no_tls {
            "--no-tls".to_string()
        } else {
            "default".to_string()
        },
    });
    decisions.push(PlanDecision {
        name: "udp_detection".to_string(),
        value: resolved.udp_detection.to_string(),
        source: if args.udp {
            "--udp".to_string()
        } else {
            "default".to_string()
        },
    });
    decisions.push(PlanDecision {
        name: "scripts".to_string(),
        value: if args.scripts_library || !args.scripts.is_empty() {
            "enabled".to_string()
        } else {
            "disabled".to_string()
        },
        source: if args.scripts_library {
            "--scripts-library".to_string()
        } else if !args.scripts.is_empty() {
            "--scripts".to_string()
        } else {
            "default".to_string()
        },
    });
    decisions.push(PlanDecision {
        name: "scope".to_string(),
        value: if scope.is_some() {
            "enforced".to_string()
        } else {
            "not supplied".to_string()
        },
        source: if args.scope.is_some() {
            "--scope".to_string()
        } else {
            "default".to_string()
        },
    });

    let mut required_privileges = Vec::new();
    match mode {
        PlanMode::Syn | PlanMode::Ack => {
            required_privileges.push(
                "root or CAP_NET_RAW (Linux); Npcap plus Administrator (Windows)".to_string(),
            );
        }
        PlanMode::Connect => {
            required_privileges.push("none (unprivileged TCP connect)".to_string());
        }
    }

    let hosts = targets.len() as u64;
    let port_count = ports.len() as u64;
    let estimated_probes = hosts.saturating_mul(port_count);
    let ipv6 = targets.iter().any(|address| address.is_ipv6());

    let mut risk_notes = Vec::new();
    if let Some(entry) = &fallback {
        risk_notes.push(format!(
            "{} -> {}: {}",
            entry.requested, entry.selected, entry.rationale
        ));
    }
    if args.force_out_of_scope {
        risk_notes.push(
            "out-of-scope override is active; confirm written authorization before scanning"
                .to_string(),
        );
    }
    if scope.is_none() {
        risk_notes.push(
            "no scope file supplied; authorization and target boundaries are the operator's responsibility"
                .to_string(),
        );
    }
    if estimated_probes > 1_000_000 {
        risk_notes.push(format!(
            "{estimated_probes} estimated probes may take significant time and trigger defenses"
        ));
    }
    if args.udp {
        risk_notes.push(
            "UDP detection is slower and less reliable than TCP; results are advisory".to_string(),
        );
    }
    if (args.scripts_library || !args.scripts.is_empty()) && !args.allow_intrusive {
        risk_notes.push(
            "intrusive script plugins remain disabled unless --allow-intrusive is set".to_string(),
        );
    }
    if ipv6 && mode == PlanMode::Syn {
        risk_notes.push(
            "raw SYN over IPv6 depends on kernel and Npcap support; verify before relying on it"
                .to_string(),
        );
    }
    if args.os && !raw_available {
        risk_notes.push(
            "OS fingerprinting requested but raw privileges are unavailable; this phase will be skipped"
                .to_string(),
        );
    }

    Ok(ScanPlan {
        schema: PLAN_SCHEMA,
        profile: resolved.profile.as_str().to_string(),
        mode,
        targets: PlanTargets {
            inputs: expanded_specs,
            hosts,
            ipv6,
        },
        ports: PlanPorts {
            spec: ports_spec,
            count: port_count,
        },
        estimated_probes,
        required_privileges,
        fallback,
        risk_notes,
        decisions,
        scope,
    })
}

pub fn save(path: &Path, plan: &ScanPlan) -> Result<(), AppError> {
    let bytes = serde_json::to_vec_pretty(plan)
        .map_err(|error| AppError::runtime(format!("cannot encode scan plan: {error}")))?;
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent).map_err(|error| {
            AppError::usage(format!(
                "cannot create plan directory {}: {error}",
                parent.display()
            ))
        })?;
    }
    std::fs::write(path, bytes).map_err(|error| {
        AppError::runtime(format!(
            "cannot write scan plan {}: {error}",
            path.display()
        ))
    })
}

pub async fn run_smart(
    args: SmartArgs,
    theme: Option<Theme>,
    db_dir: Option<&Path>,
    scripts_dir: Option<&Path>,
) -> Result<(), AppError> {
    let raw_available = crate::syn::check_raw_privilege().is_ok();
    let plan = build_with_privilege(&args.scan, raw_available).await?;
    if let Some(path) = &args.plan_output {
        save(path, &plan)?;
    }
    if args.dry_run {
        if args.plan_json {
            let payload = serde_json::to_string_pretty(&plan)
                .map_err(|error| AppError::runtime(format!("cannot encode scan plan: {error}")))?;
            println!("{payload}");
        } else {
            print!("{plan}");
        }
        return Ok(());
    }

    eprintln!("{plan}");
    let mut scan = args.scan;
    if !raw_available {
        scan.syn = false;
        scan.os = false;
    } else if plan.mode == PlanMode::Syn {
        scan.syn = true;
    }
    crate::run_scan(scan, theme, db_dir, scripts_dir).await
}

#[cfg(test)]
fn temporary_path(prefix: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "portensor-{prefix}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0)
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::ScanArgs;
    use crate::config::Profile;
    use crate::output::OutputFormat;

    fn base_args() -> ScanArgs {
        ScanArgs {
            target: vec!["192.0.2.1".to_string()],
            target_file: Vec::new(),
            exclude: Vec::new(),
            ports: Some("80,443".to_string()),
            top_ports: None,
            preset: None,
            json: false,
            format: None,
            output: None,
            profile: Some(Profile::Balanced),
            stealth: false,
            config: None,
            timeout: None,
            probe_timeout_ms: None,
            connect_timeout_ms: None,
            rate: None,
            workers: None,
            retries: None,
            randomize: false,
            sequential: false,
            top_ports_first: false,
            no_top_ports_first: false,
            discover_only: false,
            no_live: false,
            connect_only: false,
            verify: false,
            no_service_detection: false,
            udp: false,
            no_udp_probe: false,
            tls: false,
            no_tls: false,
            sni: None,
            os: false,
            os_probes: None,
            all_states: false,
            show: Vec::new(),
            ipv4: false,
            ipv6: false,
            quiet: false,
            syn: false,
            ack: false,
            no_aimd: false,
            rate_auto: false,
            host_concurrency: None,
            aimd_min_rate: None,
            retry_rate: None,
            anomaly_threshold: None,
            resume: None,
            save_state: None,
            min_confidence: None,
            explain: None,
            defense: false,
            advisories: false,
            no_db_update: false,
            diff: None,
            save_baseline: None,
            alert_file: None,
            fail_on_change: false,
            ping_sweep: false,
            ping_count: None,
            ping_timeout_ms: None,
            ndp: false,
            ndp_timeout_ms: None,
            jitter_ms: None,
            decoys: None,
            fragment_size: None,
            ttl: None,
            source_port_range: None,
            plugins: None,
            scripts: Vec::new(),
            scripts_library: false,
            allow_intrusive: false,
            min_severity: None,
            scope: None,
            force_out_of_scope: false,
            kev_only: false,
            min_epss: None,
            stream: false,
            shard_index: None,
            shard_count: None,
            work_part_index: None,
            work_part_count: None,
            exclude_ports: None,
        }
    }

    #[tokio::test]
    async fn plan_covers_single_host_and_is_deterministic() {
        let args = base_args();
        let first = build_with_privilege(&args, true).await.unwrap();
        let second = build_with_privilege(&args, true).await.unwrap();
        assert_eq!(first, second);
        assert_eq!(first.mode, PlanMode::Syn);
        assert_eq!(first.targets.hosts, 1);
        assert_eq!(first.ports.count, 2);
        assert_eq!(first.estimated_probes, 2);
    }

    #[tokio::test]
    async fn plan_covers_cidr_targets() {
        let mut args = base_args();
        args.target = vec!["192.0.2.0/30".to_string()];
        args.ports = Some("22".to_string());
        let plan = build_with_privilege(&args, true).await.unwrap();
        assert_eq!(plan.targets.hosts, 4);
        assert_eq!(plan.estimated_probes, 4);
    }

    #[tokio::test]
    async fn plan_covers_target_files() {
        let path = temporary_path("plan-targets");
        std::fs::write(&path, "192.0.2.1\n2001:db8::1\n").unwrap();
        let mut args = base_args();
        args.target = Vec::new();
        args.target_file = vec![path.clone()];
        let plan = build_with_privilege(&args, true).await.unwrap();
        assert_eq!(plan.targets.hosts, 2);
        assert!(plan.targets.ipv6);
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn plan_covers_ipv6_targets() {
        let mut args = base_args();
        args.target = vec!["2001:db8::1".to_string()];
        args.ipv6 = true;
        let plan = build_with_privilege(&args, false).await.unwrap();
        assert!(plan.targets.ipv6);
        assert_eq!(plan.mode, PlanMode::Connect);
    }

    #[tokio::test]
    async fn plan_covers_scope_guarded_targets() {
        let path = temporary_path("plan-scope.toml");
        std::fs::write(
            &path,
            "[scope]\nprogram = \"Plan Test\"\nallow = [\"127.0.0.0/8\"]\ndeny = []\n",
        )
        .unwrap();
        let mut args = base_args();
        args.target = vec!["127.0.0.1".to_string()];
        args.scope = Some(path.clone());
        let plan = build_with_privilege(&args, true).await.unwrap();
        assert_eq!(plan.scope.as_ref().unwrap().program, "Plan Test");
        assert_eq!(
            plan.scope.as_ref().unwrap().file,
            path.display().to_string()
        );
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn plan_covers_missing_raw_privileges() {
        let mut args = base_args();
        args.syn = true;
        let plan = build_with_privilege(&args, false).await.unwrap();
        assert_eq!(plan.mode, PlanMode::Connect);
        let fallback = plan.fallback.unwrap();
        assert_eq!(fallback.requested, "syn");
        assert_eq!(fallback.selected, "connect");
        assert_eq!(plan.required_privileges.len(), 1);
        assert!(plan.required_privileges[0].contains("none"));
    }

    #[test]
    fn json_plan_round_trips() {
        let plan = ScanPlan {
            schema: PLAN_SCHEMA,
            profile: "balanced".to_string(),
            mode: PlanMode::Connect,
            targets: PlanTargets {
                inputs: vec!["127.0.0.1".to_string()],
                hosts: 1,
                ipv6: false,
            },
            ports: PlanPorts {
                spec: "80".to_string(),
                count: 1,
            },
            estimated_probes: 1,
            required_privileges: vec!["none".to_string()],
            fallback: None,
            risk_notes: Vec::new(),
            decisions: Vec::new(),
            scope: None,
        };
        let json = serde_json::to_string(&plan).unwrap();
        let decoded: ScanPlan = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, plan);
        assert!(json.contains("\"mode\":\"connect\""));
    }

    #[tokio::test]
    async fn plan_reports_explicit_pipeline_ports() {
        let mut args = base_args();
        args.format = Some(OutputFormat::PortList);
        args.ports = None;
        let plan = build_with_privilege(&args, true).await.unwrap();
        assert_eq!(plan.ports.spec, "1-65535");
        assert_eq!(plan.ports.count, 65_535);
    }
}
