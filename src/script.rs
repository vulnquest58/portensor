//! Sidecar script plugins (Q2).
//!
//! Scripts are external programs described by TOML manifests.  Rayscan sends
//! one JSON document on stdin and reads one JSON document from stdout.  This
//! keeps the protocol language-neutral: Python, Go, Rust, or a shell script
//! can provide discovery and vulnerability checks without linking to rayscan.
//!
//! ```toml
//! name = "example"
//!
//! [[script]]
//! name = "weak-tls"
//! description = "Detect TLS versions below 1.2"
//! category = "vulnerability"
//! danger = "safe"
//! command = ["python3", "weak_tls.py"]
//! ports = [443, 8443]
//! services = ["https"]
//! timeout_ms = 5000
//! ```
//!
//! The command runs with the manifest directory as its working directory.
//! Scripts marked `danger = "intrusive"` only run with `--allow-intrusive`.
//!
//! Input (stdin):
//!
//! ```json
//! {
//!   "api": 1,
//!   "target": "192.0.2.10",
//!   "port": 443,
//!   "state": "open",
//!   "confidence": 0.98,
//!   "banner": "HTTP/1.1 200 OK",
//!   "detail": "plugin:...",
//!   "evidence": "...",
//!   "service": {"name": "https", "product": "nginx", "version": "1.25.4"},
//!   "tls": {"version": "TLSv1.3", "...": "..."}
//! }
//! ```
//!
//! Output (stdout):
//!
//! ```json
//! {
//!   "findings": [
//!     {
//!       "id": "tls10-enabled",
//!       "title": "TLS 1.0 accepted",
//!       "severity": "medium",
//!       "confidence": 0.9,
//!       "description": "The endpoint negotiates TLS 1.0.",
//!       "evidence": "handshake succeeded with TLSv1.0",
//!       "cve": [],
//!       "references": ["https://example.test/tls"]
//!     }
//!   ],
//!   "service": {
//!     "name": "redis",
//!     "product": "Redis",
//!     "version": "7.2.4",
//!     "cpe": "cpe:2.3:a:redis:redis",
//!     "info": {"mode": "standalone"},
//!     "confidence": 0.9
//!   }
//! }
//! ```
//!
//! Severity is one of `info`, `low`, `medium`, `high`, or `critical`.
//! Findings are advisory metadata: they never raise or lower the port's
//! accuracy confidence.  An optional `service` object identifies the port
//! (discovery scripts): it merges into `service.*` when the port is not yet
//! identified or already carries the same service name, feeds the accuracy
//! score and advisory correlation, and tags `detail` with `script:<pack>/<name>`.
//! `confidence` defaults to the probe ladder (0.98 with a version, 0.85 with a
//! product, 0.70 name-only).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;

use crate::cli::ScriptsListArgs;
use crate::error::AppError;
use crate::model::{PortResult, PortState};
use crate::plugin::{Assessment, merge_assessment};
use crate::service::ServiceInfo;
use crate::tls::TlsInfo;

const MAX_MANIFEST_BYTES: u64 = 64 * 1024;
const MAX_PACKS: usize = 32;
const MAX_SCRIPTS: usize = 128;
const MAX_FINDINGS: usize = 16;
const MAX_STDOUT: usize = 64 * 1024;
const MAX_STDERR: usize = 8 * 1024;
const MAX_TITLE_CHARS: usize = 200;
const MAX_DESCRIPTION_CHARS: usize = 4000;
const MAX_EVIDENCE_CHARS: usize = 2000;
const MAX_REFERENCE_CHARS: usize = 500;
const MAX_REFERENCES: usize = 16;
const MAX_CVES: usize = 16;
const MAX_IDENTIFIER_CHARS: usize = 64;
const MAX_COMMAND_ARGS: usize = 16;
const MAX_COMMAND_ARG_CHARS: usize = 512;
const MAX_IDENTITY_CHARS: usize = 200;
const MAX_INFO_ENTRIES: usize = 16;
const MAX_INFO_KEY_CHARS: usize = 48;
const MAX_INFO_VALUE_CHARS: usize = 200;
const DEFAULT_TIMEOUT_MS: u64 = 5000;
const MIN_TIMEOUT_MS: u64 = 100;
const MAX_TIMEOUT_MS: u64 = 30_000;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Category {
    #[default]
    Discovery,
    Vulnerability,
    Auth,
    Brute,
    Compliance,
}

impl Category {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Discovery => "discovery",
            Self::Vulnerability => "vulnerability",
            Self::Auth => "auth",
            Self::Brute => "brute",
            Self::Compliance => "compliance",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Danger {
    #[default]
    Safe,
    Intrusive,
}

impl Danger {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Safe => "safe",
            Self::Intrusive => "intrusive",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum FindingSeverity {
    #[default]
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl FindingSeverity {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Info => "INFO",
            Self::Low => "LOW",
            Self::Medium => "MEDIUM",
            Self::High => "HIGH",
            Self::Critical => "CRITICAL",
        }
    }

    /// Ordinal used by `--min-severity` filtering (Info < Low < ... < Critical).
    pub const fn rank(self) -> u8 {
        match self {
            Self::Info => 0,
            Self::Low => 1,
            Self::Medium => 2,
            Self::High => 3,
            Self::Critical => 4,
        }
    }
}

/// Drop script findings below `min` severity from the results.
pub fn retain_findings(results: &mut [PortResult], min: FindingSeverity) {
    if min == FindingSeverity::Info {
        return;
    }
    for result in results {
        result
            .script_findings
            .retain(|finding| finding.severity.rank() >= min.rank());
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PluginFinding {
    pub id: String,
    pub title: String,
    pub severity: FindingSeverity,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cve: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub references: Vec<String>,
    pub plugin: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pack {
    name: String,
    #[serde(default)]
    #[allow(dead_code)]
    description: Option<String>,
    #[serde(default, rename = "script")]
    scripts: Vec<RawScript>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawScript {
    name: String,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    category: Category,
    #[serde(default)]
    danger: Danger,
    command: Vec<String>,
    #[serde(default)]
    ports: Vec<u16>,
    #[serde(default)]
    services: Vec<String>,
    #[serde(default)]
    timeout_ms: Option<u64>,
}

#[derive(Debug)]
struct CompiledScript {
    pack: String,
    name: String,
    plugin: String,
    description: Option<String>,
    category: Category,
    danger: Danger,
    command: Vec<String>,
    dir: PathBuf,
    ports: Vec<u16>,
    services: Vec<String>,
    timeout: Duration,
}

#[derive(Clone, Debug, Serialize)]
pub struct ScriptSummary {
    pub pack: String,
    pub name: String,
    pub plugin: String,
    pub description: Option<String>,
    pub category: Category,
    pub danger: Danger,
    pub command: Vec<String>,
    pub ports: Vec<u16>,
    pub services: Vec<String>,
    pub timeout_ms: u64,
}

#[derive(Debug, Default)]
pub struct Registry {
    scripts: Vec<CompiledScript>,
    packs: usize,
}

impl Registry {
    /// Load a manifest file or every `*.toml` manifest in a directory.
    pub fn load(path: &Path) -> Result<Self, AppError> {
        let mut registry = Self::default();
        registry.add_path(path)?;
        Ok(registry)
    }

    pub fn add_path(&mut self, path: &Path) -> Result<(), AppError> {
        let metadata = std::fs::metadata(path).map_err(|error| {
            AppError::usage(format!(
                "cannot read scripts path {}: {error}",
                path.display()
            ))
        })?;

        let mut files = Vec::new();
        if metadata.is_dir() {
            for entry in std::fs::read_dir(path).map_err(|error| {
                AppError::usage(format!(
                    "cannot read scripts directory {}: {error}",
                    path.display()
                ))
            })? {
                let entry = entry.map_err(|error| {
                    AppError::usage(format!(
                        "cannot read scripts directory {}: {error}",
                        path.display()
                    ))
                })?;
                let candidate = entry.path();
                let is_manifest = candidate
                    .extension()
                    .is_some_and(|extension| extension.eq_ignore_ascii_case("toml"));
                if is_manifest && entry.file_type().is_ok_and(|kind| kind.is_file()) {
                    files.push(candidate);
                }
            }
            files.sort();
            if files.is_empty() {
                return Err(AppError::usage(format!(
                    "no *.toml script manifests found in {}",
                    path.display()
                )));
            }
        } else {
            files.push(path.to_path_buf());
        }

        if self.packs + files.len() > MAX_PACKS {
            return Err(AppError::usage(format!(
                "too many script packs (maximum {MAX_PACKS})"
            )));
        }

        for file in files {
            self.load_file(&file)?;
        }
        Ok(())
    }

    fn load_file(&mut self, path: &Path) -> Result<(), AppError> {
        let size = std::fs::metadata(path)
            .map_err(|error| AppError::usage(format!("cannot stat {}: {error}", path.display())))?
            .len();
        if size > MAX_MANIFEST_BYTES {
            return Err(AppError::usage(format!(
                "{} exceeds the {MAX_MANIFEST_BYTES}-byte script manifest limit",
                path.display()
            )));
        }
        let text = std::fs::read_to_string(path)
            .map_err(|error| AppError::usage(format!("cannot read {}: {error}", path.display())))?;
        let dir = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));
        self.parse(&text, &dir)
            .map_err(|error| AppError::usage(format!("{}: {error}", path.display())))
    }

    fn parse(&mut self, text: &str, dir: &Path) -> Result<(), AppError> {
        let pack: Pack = toml::from_str(text)
            .map_err(|error| AppError::usage(format!("invalid script manifest: {error}")))?;
        validate_identifier("script pack", &pack.name)?;
        if pack.scripts.is_empty() {
            return Err(AppError::usage(format!(
                "script pack '{}' contains no [[script]] entries",
                pack.name
            )));
        }
        if self.scripts.len() + pack.scripts.len() > MAX_SCRIPTS {
            return Err(AppError::usage(format!(
                "too many script plugins (maximum {MAX_SCRIPTS})"
            )));
        }

        for raw in pack.scripts {
            let script = compile_script(&pack.name, dir, raw)?;
            if self
                .scripts
                .iter()
                .any(|existing| existing.plugin == script.plugin)
            {
                return Err(AppError::usage(format!(
                    "duplicate script plugin '{}'",
                    script.plugin
                )));
            }
            self.scripts.push(script);
        }
        self.packs += 1;
        Ok(())
    }

    pub fn is_empty(&self) -> bool {
        self.scripts.is_empty()
    }

    pub fn script_count(&self) -> usize {
        self.scripts.len()
    }

    pub fn pack_count(&self) -> usize {
        self.packs
    }

    pub fn summaries(&self) -> Vec<ScriptSummary> {
        self.scripts
            .iter()
            .map(|script| ScriptSummary {
                pack: script.pack.clone(),
                name: script.name.clone(),
                plugin: script.plugin.clone(),
                description: script.description.clone(),
                category: script.category,
                danger: script.danger,
                command: script.command.clone(),
                ports: script.ports.clone(),
                services: script.services.clone(),
                timeout_ms: script.timeout.as_millis() as u64,
            })
            .collect()
    }

    /// Run matching scripts against open ports. Runtime failures are reported
    /// on stderr and do not abort the scan.
    pub async fn apply(
        &self,
        results: &mut [PortResult],
        allow_intrusive: bool,
        quiet: bool,
    ) -> usize {
        if self.is_empty() {
            return 0;
        }

        let mut findings = 0;
        for result in results.iter_mut() {
            if result.state != PortState::Open {
                continue;
            }
            if result
                .service
                .as_ref()
                .is_some_and(|service| service.name.starts_with("udp:"))
            {
                continue;
            }

            for script in &self.scripts {
                if script.danger == Danger::Intrusive && !allow_intrusive {
                    continue;
                }
                if !script.ports.is_empty() && !script.ports.contains(&result.port) {
                    continue;
                }
                if !script.services.is_empty() {
                    let matches = result.service.as_ref().is_some_and(|service| {
                        let name = service.name.to_ascii_lowercase();
                        script.services.iter().any(|service| service == &name)
                    });
                    if !matches {
                        continue;
                    }
                }

                match run_script(script, result).await {
                    Ok((found, assessment)) => {
                        if !found.is_empty() {
                            findings += found.len();
                            result.script_findings.extend(found);
                        }
                        if let Some(assessment) = assessment {
                            let identified = result
                                .service
                                .as_ref()
                                .is_none_or(|existing| existing.name == assessment.service);
                            if identified {
                                let tag = format!("script:{}", script.plugin);
                                let evidence_label = format!("script match {tag}");
                                merge_assessment(result, &tag, &evidence_label, assessment);
                            }
                        }
                    }
                    Err(error) => {
                        if !quiet {
                            eprintln!(
                                "[scripts] {} on {}:{} failed: {error}",
                                script.plugin, result.host, result.port
                            );
                        }
                    }
                }
            }
        }
        findings
    }
}

pub fn run_cli(args: ScriptsListArgs) -> Result<(), AppError> {
    let registry = Registry::load(&args.path)?;
    let summaries = registry.summaries();
    if args.json {
        let json = serde_json::to_string_pretty(&summaries)
            .map_err(|error| AppError::runtime(format!("cannot encode script JSON: {error}")))?;
        println!("{json}");
        return Ok(());
    }

    println!(
        "{} script plugin(s) in {} pack(s):",
        registry.script_count(),
        registry.pack_count()
    );
    let mut current_pack = "";
    for summary in &summaries {
        if summary.pack != current_pack {
            current_pack = &summary.pack;
            println!("\n{current_pack}");
        }
        let ports = if summary.ports.is_empty() {
            "any".to_string()
        } else {
            summary
                .ports
                .iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join(",")
        };
        let services = if summary.services.is_empty() {
            "any".to_string()
        } else {
            summary.services.join(",")
        };
        println!(
            "  {:<28} [{}/{}] {} ms  ports={} services={}",
            summary.name,
            summary.danger.as_str(),
            summary.category.as_str(),
            summary.timeout_ms,
            ports,
            services
        );
        println!("    command: {}", summary.command.join(" "));
        if let Some(description) = &summary.description {
            println!("    {description}");
        }
    }
    Ok(())
}

fn compile_script(pack: &str, dir: &Path, raw: RawScript) -> Result<CompiledScript, AppError> {
    validate_identifier("script", &raw.name)?;
    let plugin = format!("{pack}/{}", raw.name);
    let description = match raw.description {
        Some(description) => Some(clean_optional(
            &description,
            MAX_DESCRIPTION_CHARS,
            &format!("script '{plugin}' description"),
        )?),
        None => None,
    };

    if raw.command.is_empty() || raw.command.len() > MAX_COMMAND_ARGS {
        return Err(AppError::usage(format!(
            "script '{plugin}' command must contain 1-{MAX_COMMAND_ARGS} arguments"
        )));
    }
    let mut command = raw.command;
    for argument in &command {
        if argument.is_empty() || argument.chars().count() > MAX_COMMAND_ARG_CHARS {
            return Err(AppError::usage(format!(
                "script '{plugin}' has an empty or oversized command argument"
            )));
        }
        if argument.contains('\0') {
            return Err(AppError::usage(format!(
                "script '{plugin}' command contains a NUL byte"
            )));
        }
    }
    if command[0].contains(['/', '\\']) {
        let executable = dir.join(&command[0]);
        if !executable.is_file() {
            return Err(AppError::usage(format!(
                "script '{plugin}' executable {} does not exist",
                executable.display()
            )));
        }
        command[0] = executable.display().to_string();
    }

    let mut services = Vec::new();
    for service in raw.services {
        let service = service.trim().to_ascii_lowercase();
        if service.is_empty() || service.chars().count() > MAX_IDENTIFIER_CHARS {
            return Err(AppError::usage(format!(
                "script '{plugin}' has an invalid service filter"
            )));
        }
        services.push(service);
    }
    services.sort();
    services.dedup();

    let timeout_ms = raw.timeout_ms.unwrap_or(DEFAULT_TIMEOUT_MS);
    if !(MIN_TIMEOUT_MS..=MAX_TIMEOUT_MS).contains(&timeout_ms) {
        return Err(AppError::usage(format!(
            "script '{plugin}' timeout_ms must be between {MIN_TIMEOUT_MS} and {MAX_TIMEOUT_MS}"
        )));
    }

    Ok(CompiledScript {
        pack: pack.to_string(),
        name: raw.name,
        plugin,
        description,
        category: raw.category,
        danger: raw.danger,
        command,
        dir: dir.to_path_buf(),
        ports: raw.ports,
        services,
        timeout: Duration::from_millis(timeout_ms),
    })
}

#[derive(Serialize)]
struct ScriptInput<'a> {
    api: u32,
    target: String,
    port: u16,
    state: &'a str,
    confidence: Option<f32>,
    banner: Option<&'a str>,
    detail: Option<&'a str>,
    evidence: Option<&'a str>,
    service: Option<&'a ServiceInfo>,
    tls: Option<&'a TlsInfo>,
}

#[derive(Deserialize)]
struct ScriptOutput {
    #[serde(default)]
    findings: Vec<RawFinding>,
    #[serde(default)]
    service: Option<RawService>,
}

#[derive(Deserialize)]
struct RawService {
    name: String,
    #[serde(default)]
    product: Option<String>,
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    cpe: Option<String>,
    #[serde(default)]
    info: BTreeMap<String, String>,
    #[serde(default)]
    confidence: Option<f32>,
}

#[derive(Deserialize)]
struct RawFinding {
    #[serde(default)]
    id: Option<String>,
    title: String,
    #[serde(default)]
    severity: FindingSeverity,
    #[serde(default)]
    confidence: Option<f32>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    evidence: Option<String>,
    #[serde(default)]
    cve: Vec<String>,
    #[serde(default)]
    references: Vec<String>,
}

async fn run_script(
    script: &CompiledScript,
    result: &PortResult,
) -> Result<(Vec<PluginFinding>, Option<Assessment>), String> {
    let payload = serde_json::to_vec(&ScriptInput {
        api: 1,
        target: result.host.to_string(),
        port: result.port,
        state: result.state.as_str(),
        confidence: result.confidence,
        banner: result.banner.as_deref(),
        detail: result.detail.as_deref(),
        evidence: result.evidence.as_deref(),
        service: result.service.as_ref(),
        tls: result.tls.as_ref(),
    })
    .map_err(|error| format!("cannot encode input: {error}"))?;

    let mut command = Command::new(&script.command[0]);
    command
        .args(&script.command[1..])
        .current_dir(&script.dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .env("RAYSCAN_SCRIPT_API", "1")
        .env("RAYSCAN_SCRIPT_NAME", &script.name)
        .env("RAYSCAN_SCRIPT_PLUGIN", &script.plugin)
        .env("RAYSCAN_TARGET", result.host.to_string())
        .env("RAYSCAN_PORT", result.port.to_string());

    let mut child = command
        .spawn()
        .map_err(|error| format!("cannot start {}: {error}", script.command[0]))?;

    if let Some(mut stdin) = child.stdin.take()
        && let Err(error) = stdin.write_all(&payload).await
        && error.kind() != std::io::ErrorKind::BrokenPipe
    {
        let _ = child.kill().await;
        return Err(format!("cannot write input: {error}"));
    }

    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "missing stdout pipe".to_string())?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| "missing stderr pipe".to_string())?;

    let run = async {
        let read_stdout = async move {
            let mut limited = stdout.take((MAX_STDOUT + 1) as u64);
            let mut buffer = Vec::new();
            limited.read_to_end(&mut buffer).await.map(|_| buffer)
        };
        let read_stderr = async move {
            let mut limited = stderr.take((MAX_STDERR + 1) as u64);
            let mut buffer = Vec::new();
            limited.read_to_end(&mut buffer).await.map(|_| buffer)
        };
        tokio::join!(child.wait(), read_stdout, read_stderr)
    };

    let (status, stdout, stderr) = match tokio::time::timeout(script.timeout, run).await {
        Ok((status, stdout, stderr)) => (status, stdout, stderr),
        Err(_) => {
            let _ = child.kill().await;
            return Err(format!("timed out after {} ms", script.timeout.as_millis()));
        }
    };

    let status = status.map_err(|error| format!("wait failed: {error}"))?;
    let stdout = stdout.map_err(|error| format!("cannot read stdout: {error}"))?;
    let stderr = stderr.map_err(|error| format!("cannot read stderr: {error}"))?;
    if stdout.len() > MAX_STDOUT {
        return Err(format!("stdout exceeds the {MAX_STDOUT}-byte limit"));
    }
    if !status.success() {
        let stderr = String::from_utf8_lossy(&stderr);
        let stderr = stderr.trim();
        return Err(if stderr.is_empty() {
            format!("exited with {status}")
        } else {
            format!("exited with {status}: {stderr}")
        });
    }

    let output: ScriptOutput =
        serde_json::from_slice(&stdout).map_err(|error| format!("invalid JSON output: {error}"))?;
    if output.findings.len() > MAX_FINDINGS {
        return Err(format!(
            "returned {} findings (maximum {MAX_FINDINGS})",
            output.findings.len()
        ));
    }
    let findings = output
        .findings
        .into_iter()
        .map(|raw| validate_finding(&script.plugin, &script.name, raw))
        .collect::<Result<Vec<_>, String>>()?;
    let assessment = match output.service {
        Some(raw) => Some(service_assessment(raw)?),
        None => None,
    };
    Ok((findings, assessment))
}

/// Validate a script-declared service identity and turn it into a mergeable
/// assessment.
fn service_assessment(raw: RawService) -> Result<Assessment, String> {
    let name = raw.name.trim().to_ascii_lowercase();
    if !valid_identifier(&name) {
        return Err(format!(
            "service name '{name}' must be 1-{MAX_IDENTIFIER_CHARS} characters of [a-z0-9._-]"
        ));
    }
    let product = optional_text("product", raw.product, MAX_IDENTITY_CHARS)?;
    let version = optional_text("version", raw.version, MAX_IDENTITY_CHARS)?;
    let cpe = optional_text("cpe", raw.cpe, MAX_IDENTITY_CHARS)?;
    let confidence = match raw.confidence {
        Some(confidence) if confidence.is_finite() && (0.0..=1.0).contains(&confidence) => {
            confidence
        }
        Some(confidence) => {
            return Err(format!(
                "service confidence {confidence} is outside 0.0-1.0"
            ));
        }
        None => match (&version, &product) {
            (_, Some(_)) => 0.98,
            (Some(_), None) => 0.85,
            (None, None) => 0.70,
        },
    };
    if raw.info.len() > MAX_INFO_ENTRIES {
        return Err(format!(
            "service info has {} entries (maximum {MAX_INFO_ENTRIES})",
            raw.info.len()
        ));
    }
    let mut info = BTreeMap::new();
    for (key, value) in raw.info {
        let key = key.trim().to_ascii_lowercase();
        let valid_key = !key.is_empty()
            && key.chars().count() <= MAX_INFO_KEY_CHARS
            && key.chars().all(|character| {
                character.is_ascii_lowercase() || character.is_ascii_digit() || character == '_'
            });
        if !valid_key {
            return Err(format!("service info key '{key}' is invalid"));
        }
        let value = value.trim();
        if value.chars().count() > MAX_INFO_VALUE_CHARS {
            return Err(format!(
                "service info key '{key}' value exceeds {MAX_INFO_VALUE_CHARS} characters"
            ));
        }
        info.insert(key, value.to_string());
    }
    Ok(Assessment::new(
        name, product, version, cpe, info, confidence,
    ))
}

fn validate_finding(
    plugin: &str,
    default_id: &str,
    raw: RawFinding,
) -> Result<PluginFinding, String> {
    let id = match raw.id {
        Some(id) => {
            let id = clean_text(&id);
            if id.is_empty() || !valid_identifier(&id) {
                return Err(format!("invalid finding id '{id}'"));
            }
            id
        }
        None => default_id.to_string(),
    };
    let title = require_text("title", &raw.title, MAX_TITLE_CHARS)?;
    let confidence = match raw.confidence {
        Some(confidence) if confidence.is_finite() && (0.0..=1.0).contains(&confidence) => {
            Some(confidence)
        }
        Some(confidence) => {
            return Err(format!(
                "finding '{id}' confidence {confidence} is outside 0.0-1.0"
            ));
        }
        None => None,
    };
    let description = optional_text("description", raw.description, MAX_DESCRIPTION_CHARS)?;
    let evidence = optional_text("evidence", raw.evidence, MAX_EVIDENCE_CHARS)?;

    if raw.cve.len() > MAX_CVES {
        return Err(format!("finding '{id}' has too many CVE identifiers"));
    }
    let mut cve = Vec::new();
    for value in raw.cve {
        let value = value.trim().to_ascii_uppercase();
        if !valid_cve(&value) {
            return Err(format!(
                "finding '{id}' has invalid CVE identifier '{value}'"
            ));
        }
        cve.push(value);
    }
    cve.sort();
    cve.dedup();

    if raw.references.len() > MAX_REFERENCES {
        return Err(format!("finding '{id}' has too many references"));
    }
    let mut references = Vec::new();
    for value in raw.references {
        let value = value.trim().to_string();
        let valid_url = value.starts_with("http://") || value.starts_with("https://");
        if !valid_url
            || value.chars().count() > MAX_REFERENCE_CHARS
            || value.chars().any(char::is_control)
        {
            return Err(format!("finding '{id}' has an invalid reference"));
        }
        references.push(value);
    }
    references.sort();
    references.dedup();

    Ok(PluginFinding {
        id,
        title,
        severity: raw.severity,
        confidence,
        description,
        evidence,
        cve,
        references,
        plugin: plugin.to_string(),
    })
}

fn validate_identifier(kind: &str, value: &str) -> Result<(), AppError> {
    if valid_identifier(value) {
        Ok(())
    } else {
        Err(AppError::usage(format!(
            "{kind} name '{value}' must be 1-{MAX_IDENTIFIER_CHARS} characters of [A-Za-z0-9._-]"
        )))
    }
}

fn valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.chars().count() <= MAX_IDENTIFIER_CHARS
        && value.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.')
        })
}

fn require_text(label: &str, value: &str, max: usize) -> Result<String, String> {
    let value = clean_text(value);
    if value.is_empty() {
        return Err(format!("finding {label} is empty"));
    }
    if value.chars().count() > max {
        return Err(format!("finding {label} exceeds {max} characters"));
    }
    if value.chars().any(char::is_control) {
        return Err(format!("finding {label} contains control characters"));
    }
    Ok(value)
}

fn optional_text(label: &str, value: Option<String>, max: usize) -> Result<Option<String>, String> {
    match value {
        Some(value) => {
            let value = clean_text(&value);
            if value.is_empty() {
                return Ok(None);
            }
            if value.chars().count() > max {
                return Err(format!("finding {label} exceeds {max} characters"));
            }
            if value.chars().any(char::is_control) {
                return Err(format!("finding {label} contains control characters"));
            }
            Ok(Some(value))
        }
        None => Ok(None),
    }
}

fn clean_optional(value: &str, max: usize, label: &str) -> Result<String, AppError> {
    let value = clean_text(value);
    if value.is_empty() {
        return Err(AppError::usage(format!("{label} cannot be empty")));
    }
    if value.chars().count() > max {
        return Err(AppError::usage(format!("{label} exceeds {max} characters")));
    }
    Ok(value)
}

fn clean_text(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn valid_cve(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("CVE-") else {
        return false;
    };
    let mut parts = rest.split('-');
    let Some(year) = parts.next() else {
        return false;
    };
    let Some(number) = parts.next() else {
        return false;
    };
    parts.next().is_none()
        && year.len() == 4
        && year.chars().all(|character| character.is_ascii_digit())
        && number.len() >= 4
        && number.chars().all(|character| character.is_ascii_digit())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registry(text: &str) -> Registry {
        let mut registry = Registry::default();
        registry
            .parse(text, Path::new("."))
            .expect("parse manifest");
        registry
    }

    #[test]
    fn parses_manifest_with_filters_and_defaults() {
        let registry = registry(
            r#"
name = "unit"
[[script]]
name = "weak-tls"
description = "  Detect old TLS  "
category = "vulnerability"
command = ["python3", "weak_tls.py"]
ports = [443, 8443]
services = ["HTTPS", "https"]
"#,
        );
        assert_eq!(registry.script_count(), 1);
        assert_eq!(registry.pack_count(), 1);
        let summary = &registry.summaries()[0];
        assert_eq!(summary.plugin, "unit/weak-tls");
        assert_eq!(summary.description.as_deref(), Some("Detect old TLS"));
        assert_eq!(summary.category, Category::Vulnerability);
        assert_eq!(summary.danger, Danger::Safe);
        assert_eq!(summary.timeout_ms, DEFAULT_TIMEOUT_MS);
        assert_eq!(summary.services, ["https"]);
        assert_eq!(summary.ports, [443, 8443]);
    }

    #[test]
    fn rejects_duplicate_scripts_and_bad_timeouts() {
        let mut duplicate = Registry::default();
        let text = r#"
name = "unit"
[[script]]
name = "dup"
command = ["true"]
[[script]]
name = "dup"
command = ["true"]
"#;
        assert!(duplicate.parse(text, Path::new(".")).is_err());

        let mut slow = Registry::default();
        let error = slow.parse(
            r#"
name = "slow"
[[script]]
name = "slow"
command = ["true"]
timeout_ms = 100000
"#,
            Path::new("."),
        );
        assert!(error.is_err());
    }

    #[test]
    fn validates_findings_and_normalizes_fields() {
        let finding = validate_finding(
            "pack/check",
            "default-id",
            RawFinding {
                id: None,
                title: "  Weak   TLS  ".to_string(),
                severity: FindingSeverity::High,
                confidence: Some(0.9),
                description: Some("negotiates\nTLS 1.0".to_string()),
                evidence: Some("handshake ok".to_string()),
                cve: vec!["cve-2024-1234".to_string()],
                references: vec!["https://example.test/tls".to_string()],
            },
        )
        .expect("valid finding");
        assert_eq!(finding.title, "Weak TLS");
        assert_eq!(finding.id, "default-id");
        assert_eq!(finding.description.as_deref(), Some("negotiates TLS 1.0"));
        assert_eq!(finding.cve, ["CVE-2024-1234"]);
        assert_eq!(finding.plugin, "pack/check");

        let invalid = validate_finding(
            "pack/check",
            "id",
            RawFinding {
                id: None,
                title: "x".repeat(MAX_TITLE_CHARS + 1),
                severity: FindingSeverity::Info,
                confidence: Some(1.5),
                description: None,
                evidence: None,
                cve: vec![],
                references: vec![],
            },
        );
        assert!(invalid.is_err());
    }

    #[test]
    fn severity_ranking_and_retention() {
        assert!(FindingSeverity::Critical.rank() > FindingSeverity::High.rank());
        assert!(FindingSeverity::Info.rank() < FindingSeverity::Low.rank());

        let finding = |id: &str, severity: FindingSeverity| PluginFinding {
            id: id.to_string(),
            title: id.to_string(),
            severity,
            confidence: None,
            description: None,
            evidence: None,
            cve: Vec::new(),
            references: Vec::new(),
            plugin: "p/check".to_string(),
        };
        let mut results = [PortResult::new(
            "127.0.0.1".parse().expect("ip"),
            80,
            PortState::Open,
            Duration::from_millis(1),
        )];
        results[0]
            .script_findings
            .push(finding("low", FindingSeverity::Low));
        results[0]
            .script_findings
            .push(finding("critical", FindingSeverity::Critical));

        retain_findings(&mut results, FindingSeverity::Info);
        assert_eq!(results[0].script_findings.len(), 2);
        retain_findings(&mut results, FindingSeverity::High);
        assert_eq!(results[0].script_findings.len(), 1);
        assert_eq!(results[0].script_findings[0].title, "critical");
    }

    #[test]
    fn validates_service_attribution() {
        let mut info = BTreeMap::new();
        info.insert("ROLE".to_string(), "test".to_string());
        let assessment = service_assessment(RawService {
            name: "LAB-ENGINE".to_string(),
            product: Some("Lab Engine".to_string()),
            version: Some("1.2.3".to_string()),
            cpe: None,
            info,
            confidence: None,
        })
        .expect("valid service");
        assert_eq!(assessment.service, "lab-engine");
        assert_eq!(assessment.confidence, 0.98);
        assert_eq!(
            assessment.info.get("role").map(String::as_str),
            Some("test")
        );

        let name_only = service_assessment(RawService {
            name: "lab-engine".to_string(),
            product: None,
            version: None,
            cpe: None,
            info: BTreeMap::new(),
            confidence: None,
        })
        .expect("name-only service");
        assert_eq!(name_only.confidence, 0.70);

        let invalid_name = service_assessment(RawService {
            name: "bad name!".to_string(),
            product: None,
            version: None,
            cpe: None,
            info: BTreeMap::new(),
            confidence: None,
        });
        assert!(invalid_name.is_err());

        let invalid_confidence = service_assessment(RawService {
            name: "ok".to_string(),
            product: None,
            version: None,
            cpe: None,
            info: BTreeMap::new(),
            confidence: Some(1.5),
        });
        assert!(invalid_confidence.is_err());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn apply_honors_service_filters_and_danger_gating() {
        let dir =
            std::env::temp_dir().join(format!("rayscan-script-filter-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        std::fs::write(
            dir.join("emit.sh"),
            "#!/bin/sh\ncat >/dev/null\ncase \"$RAYSCAN_SCRIPT_NAME\" in\n  http-only) svc='{\"name\":\"http\",\"product\":\"Lab HTTP\",\"version\":\"9.9\"}' ;;\n  redis-only) svc='{\"name\":\"redis\"}' ;;\n  *) svc='{\"name\":\"intrusive-svc\"}' ;;\nesac\nprintf '%s\\n' \"{\\\"findings\\\":[{\\\"title\\\":\\\"Always emits\\\",\\\"severity\\\":\\\"low\\\"}],\\\"service\\\":$svc}\"\n",
        )
        .expect("write script");
        let registry = {
            let mut registry = Registry::default();
            registry
                .parse(
                    r#"
name = "unit"
[[script]]
name = "http-only"
command = ["sh", "emit.sh"]
services = ["http"]
[[script]]
name = "redis-only"
command = ["sh", "emit.sh"]
services = ["redis"]
[[script]]
name = "intrusive"
command = ["sh", "emit.sh"]
danger = "intrusive"
"#,
                    &dir,
                )
                .expect("parse manifest");
            registry
        };
        let mut results = [PortResult::new(
            "127.0.0.1".parse().expect("ip"),
            80,
            PortState::Open,
            Duration::from_millis(1),
        )];
        results[0].service = Some(ServiceInfo {
            name: "http".to_string(),
            ..Default::default()
        });

        let gated = registry.apply(&mut results, false, true).await;
        assert_eq!(gated, 1, "intrusive and non-matching scripts must not run");
        let findings = registry.apply(&mut results, true, true).await;
        assert_eq!(findings, 2, "intrusive script runs with the flag");
        let service = results[0].service.as_ref().expect("service after merge");
        assert_eq!(service.name, "http", "same-name script service must merge");
        assert_eq!(service.product.as_deref(), Some("Lab HTTP"));
        assert_eq!(service.version.as_deref(), Some("9.9"));
        assert_eq!(
            results[0].detail.as_deref(),
            Some("script:unit/http-only"),
            "redis and intrusive service names must not override http"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn executes_sidecar_and_parses_findings() {
        let dir = std::env::temp_dir().join(format!("rayscan-script-unit-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        std::fs::write(
            dir.join("emit.sh"),
            "#!/bin/sh\ncat >/dev/null\nprintf '%s\\n' '{\"findings\":[{\"title\":\"Test finding\",\"severity\":\"high\",\"confidence\":0.9,\"cve\":[\"cve-2024-1234\"],\"references\":[\"https://example.test\"]}]}'\n",
        )
        .expect("write script");
        let registry = {
            let mut registry = Registry::default();
            registry
                .parse(
                    r#"
name = "unit"
[[script]]
name = "emit"
command = ["sh", "emit.sh"]
"#,
                    &dir,
                )
                .expect("parse manifest");
            registry
        };
        let script = &registry.scripts[0];
        let mut result = PortResult::new(
            "127.0.0.1".parse().expect("ip"),
            80,
            PortState::Open,
            Duration::from_millis(1),
        );
        result.service = Some(ServiceInfo {
            name: "http".to_string(),
            ..Default::default()
        });

        let (findings, assessment) = run_script(script, &result).await.expect("run sidecar");
        assert!(assessment.is_none());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].title, "Test finding");
        assert_eq!(findings[0].severity, FindingSeverity::High);
        assert_eq!(findings[0].cve, ["CVE-2024-1234"]);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
