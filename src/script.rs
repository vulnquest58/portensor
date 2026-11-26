//! Script plugins (Q2): sidecar processes and sandboxed WASM modules.
//!
//! Scripts are described by TOML manifests and communicate over one JSON
//! document in, one JSON document out. Two runtimes are supported:
//!
//! * **Sidecar** (`command = ["python3", "check.py"]`): an external program
//!   with the manifest directory as working directory. The protocol stays
//!   language-neutral: Python, Go, Rust, or a shell script can provide
//!   discovery and vulnerability checks without linking to portensor.
//! * **WASM** (`wasm = "check.wasm"`): a WebAssembly module executed in-process
//!   by wasmtime. Modules run without WASI, so they cannot touch the file
//!   system, network, or environment; execution is bounded by fuel metering,
//!   a memory/table limiter, and the manifest timeout.
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
//! # - or, instead of command -
//! # wasm = "weak_tls.wasm"
//! ports = [443, 8443]
//! services = ["https"]
//! timeout_ms = 5000
//! ```
//!
//! Sidecar commands run with the manifest directory as their working
//! directory. Scripts marked `danger = "intrusive"` only run with
//! `--allow-intrusive`.
//!
//! Input (stdin / module memory):
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
//! Output (stdout / module memory):
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
//! WASM modules must export `memory`, `alloc(len: i32) -> i32` (bump-allocator
//! pointer for the input JSON) and `run(input_ptr: i32, input_len: i32) -> i64`
//! returning the packed output pointer/length: `(ptr as u64) << 32 | len`.
//!
//! Severity is one of `info`, `low`, `medium`, `high`, or `critical`.
//! Findings are advisory metadata: they never raise or lower the port's
//! accuracy confidence.  An optional `service` object identifies the port
//! (discovery scripts): it merges into `service.*` when the port is not yet
//! identified or already carries the same service name, feeds the accuracy
//! score and advisory correlation, and tags `detail` with `script:<pack>/<name>`.
//! `confidence` defaults to the probe ladder (0.98 with a version, 0.85 with a
//! product, 0.70 name-only).

use std::collections::{BTreeMap, VecDeque};
use std::io::Write as _;
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;

use crate::cli::{ScriptsAction, ScriptsArgs, ScriptsListArgs};
use crate::error::AppError;
use crate::marketplace::{self, REGISTRY_ENV};
use crate::model::{PortResult, PortState};
use crate::plugin::{Assessment, merge_assessment};
use crate::scope::ScopeGuard;
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
const MAX_WASM_BYTES: usize = 4 * 1024 * 1024;
/// Caps applied when installing a pack directory into the script library.
const MAX_LIBRARY_ENTRIES: usize = 4096;
const MAX_LIBRARY_BYTES: u64 = 512 * 1024 * 1024;
/// Fuel budget per WASM run (roughly wasm instructions). The wall-clock
/// timeout remains the hard backstop; fuel keeps a runaway loop bounded even
/// beyond the kill window.
const WASM_FUEL: u64 = 200_000_000;
/// Memory and table ceilings applied to WASM script stores.
const WASM_MEMORY_BYTES: usize = 16 * 1024 * 1024;
const WASM_TABLE_ELEMENTS: usize = 10_000;
const MAX_IDENTITY_CHARS: usize = 200;
const MAX_INFO_ENTRIES: usize = 16;
const MAX_INFO_KEY_CHARS: usize = 48;
const MAX_INFO_VALUE_CHARS: usize = 200;
const DEFAULT_TIMEOUT_MS: u64 = 5000;
const MIN_TIMEOUT_MS: u64 = 100;
const MAX_TIMEOUT_MS: u64 = 30_000;
/// Active-host limits from ADR 0001.
const ACTIVE_MAX_CONNECTIONS: u32 = 10;
const ACTIVE_RATE_PER_SECOND: usize = 5;
const ACTIVE_MAX_BYTES: usize = 1024 * 1024;
const ACTIVE_OP_TIMEOUT: Duration = Duration::from_secs(5);
const ACTIVE_OK: i32 = 0;
const ACTIVE_DENIED: i32 = -1;
const ACTIVE_WRONG_PORT: i32 = -2;
const ACTIVE_ATTEMPT_LIMIT: i32 = -3;
const ACTIVE_RATE_LIMIT: i32 = -4;
const ACTIVE_NOT_OPEN: i32 = -5;
const ACTIVE_IO_ERROR: i32 = -6;
const ACTIVE_BYTE_LIMIT: i32 = -7;
const ACTIVE_BAD_REQUEST: i32 = -8;

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

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Capability {
    #[default]
    Metadata,
    TargetTcp,
}

impl Capability {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Metadata => "metadata",
            Self::TargetTcp => "target-tcp",
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
    #[serde(default)]
    capabilities: Vec<Capability>,
    #[serde(default)]
    command: Option<Vec<String>>,
    #[serde(default)]
    wasm: Option<String>,
    #[serde(default)]
    ports: Vec<u16>,
    #[serde(default)]
    services: Vec<String>,
    #[serde(default)]
    timeout_ms: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ScriptKind {
    Sidecar,
    Wasm,
}

impl ScriptKind {
    fn as_str(self) -> &'static str {
        match self {
            ScriptKind::Sidecar => "sidecar",
            ScriptKind::Wasm => "wasm",
        }
    }
}

#[derive(Clone, Debug)]
struct CompiledScript {
    pack: String,
    name: String,
    plugin: String,
    description: Option<String>,
    category: Category,
    danger: Danger,
    capabilities: Vec<Capability>,
    /// Sidecar argv (kind Sidecar) or empty (kind Wasm).
    command: Vec<String>,
    kind: ScriptKind,
    /// Resolved WASM module path (kind Wasm only).
    wasm_path: Option<PathBuf>,
    /// WASM source (binary or WAT text) compiled at load time.
    module: Option<wasmtime::Module>,
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
    pub capabilities: Vec<Capability>,
    /// Sidecar argv; empty for WASM scripts, which carry `wasm_path` instead.
    pub command: Vec<String>,
    /// Path of the WASM module for wasm scripts; `None` for sidecar scripts.
    pub wasm_path: Option<String>,
    pub kind: &'static str,
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
            let mut subdirectories = Vec::new();
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
                let file_type = entry.file_type().ok();
                let is_manifest = candidate
                    .extension()
                    .is_some_and(|extension| extension.eq_ignore_ascii_case("toml"));
                let hidden = candidate
                    .file_name()
                    .is_some_and(|name| name.to_string_lossy().starts_with('.'));
                if is_manifest && file_type.is_some_and(|kind| kind.is_file()) {
                    files.push(candidate);
                } else if file_type.is_some_and(|kind| kind.is_dir()) && !hidden {
                    subdirectories.push(candidate);
                }
            }
            // Library layout: one subdirectory per installed pack. Load
            // manifests directly inside each subdirectory so a library root
            // (or any grouped scripts directory) works without extra flags.
            subdirectories.sort();
            for directory in subdirectories {
                let mut nested = Vec::new();
                let entries = match std::fs::read_dir(&directory) {
                    Ok(entries) => entries,
                    Err(_) => continue,
                };
                for entry in entries.flatten() {
                    let candidate = entry.path();
                    let is_manifest = candidate
                        .extension()
                        .is_some_and(|extension| extension.eq_ignore_ascii_case("toml"));
                    if is_manifest && entry.file_type().is_ok_and(|kind| kind.is_file()) {
                        nested.push(candidate);
                    }
                }
                nested.sort();
                files.extend(nested);
            }
            files.sort();
            if files.is_empty() {
                return Err(AppError::usage(format!(
                    "no *.toml script manifests found in {} or its pack subdirectories",
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
                capabilities: script.capabilities.clone(),
                command: script.command.clone(),
                wasm_path: script
                    .wasm_path
                    .as_ref()
                    .map(|path| path.display().to_string()),
                kind: script.kind.as_str(),
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
        self.apply_with_scope(results, allow_intrusive, quiet, None, false)
            .await
    }

    /// Run matching scripts with the active-script scope policy. The rate
    /// limiter is shared across every script and result in this invocation.
    pub async fn apply_with_scope(
        &self,
        results: &mut [PortResult],
        allow_intrusive: bool,
        quiet: bool,
        scope: Option<&ScopeGuard>,
        force_out_of_scope: bool,
    ) -> usize {
        if self.is_empty() {
            return 0;
        }

        let context = ScriptExecutionContext::new(scope, force_out_of_scope);
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

                match run_script(script, result, Some(&context)).await {
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

/// Resolve the local script pack library directory.
///
/// Priority: explicit `--scripts-dir`, `PORTENSOR_SCRIPTS_DIR`, then the
/// platform data directory (`<data>/portensor/scripts`, sibling of the NVD db).
pub fn library_dir(explicit: Option<&Path>) -> Result<PathBuf, AppError> {
    if let Some(path) = explicit {
        return Ok(path.to_path_buf());
    }
    if let Some(path) = std::env::var_os("PORTENSOR_SCRIPTS_DIR") {
        return Ok(PathBuf::from(path));
    }
    crate::db::default_data_root()
        .map(|base| base.join("scripts"))
        .ok_or_else(|| {
            AppError::usage(
                "cannot determine the script library directory; set PORTENSOR_SCRIPTS_DIR or --scripts-dir",
            )
        })
}

pub fn run_cli(args: ScriptsArgs, scripts_dir: Option<&Path>) -> Result<(), AppError> {
    match args.action {
        ScriptsAction::List(list) => list_cli(list, scripts_dir),
        ScriptsAction::Search(search) => marketplace::search_cli(search),
        ScriptsAction::Install(install) => {
            let library = library_dir(scripts_dir)?;
            let local_path =
                !marketplace::is_remote_url(&install.source) && Path::new(&install.source).exists();
            // An explicit --registry always wins. The environment fallback is
            // only consulted for bare pack names, so a sticky registry URL
            // can never hijack a local directory install.
            let registry = install.registry.or_else(|| {
                if local_path || marketplace::is_remote_url(&install.source) {
                    return None;
                }
                std::env::var(REGISTRY_ENV)
                    .ok()
                    .filter(|value| !value.trim().is_empty())
            });
            if let Some(registry) = registry {
                if marketplace::is_remote_url(&install.source) {
                    return Err(AppError::usage(
                        "--registry installs take a pack name; archive URLs install with --sha256 and no --registry",
                    ));
                }
                if install.sha256.is_some() {
                    return Err(AppError::usage(
                        "--sha256 applies to direct archive URLs; registry installs use the index digest",
                    ));
                }
                let installed = marketplace::install_named(
                    &registry,
                    &install.source,
                    &library,
                    install.force,
                )?;
                println!(
                    "installed {} from {} -> {}",
                    install.source,
                    registry,
                    installed.display()
                );
                return Ok(());
            }
            if marketplace::is_remote_url(&install.source) {
                let sha256 = install.sha256.ok_or_else(|| {
                    AppError::usage(
                        "installing an archive URL requires --sha256 HEX so the download can be verified",
                    )
                })?;
                let installed =
                    marketplace::install_url(&install.source, &sha256, &library, install.force)?;
                let name = installed
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or(&install.source);
                println!(
                    "installed {name} (sha256 verified) -> {}",
                    installed.display()
                );
                return Ok(());
            }
            if install.sha256.is_some() {
                return Err(AppError::usage(
                    "--sha256 requires an http(s) archive URL or --registry",
                ));
            }
            let installed = install_pack(Path::new(&install.source), &library, install.force)?;
            println!("installed {} -> {}", install.source, installed.display());
            Ok(())
        }
        ScriptsAction::Uninstall(uninstall) => {
            let library = library_dir(scripts_dir)?;
            let removed = uninstall_pack(&uninstall.name, &library)?;
            println!("removed {}", removed.display());
            Ok(())
        }
        ScriptsAction::Update(update) => {
            let library = library_dir(scripts_dir)?;
            marketplace::update_cli(update, &library)
        }
        ScriptsAction::Library(library_args) => {
            let library = library_dir(scripts_dir)?;
            let exists = library.is_dir();
            if library_args.json {
                let payload = serde_json::json!({
                    "path": library.display().to_string(),
                    "exists": exists,
                });
                println!(
                    "{}",
                    serde_json::to_string_pretty(&payload).map_err(|error| AppError::runtime(
                        format!("cannot encode library JSON: {error}")
                    ))?
                );
            } else {
                println!("{}", library.display());
                if !exists {
                    println!(
                        "(directory does not exist yet; install a pack with `portensor scripts install DIR`)"
                    );
                }
            }
            Ok(())
        }
    }
}

fn list_cli(args: ScriptsListArgs, scripts_dir: Option<&Path>) -> Result<(), AppError> {
    let path = match args.path {
        Some(path) => path,
        None => {
            let library = library_dir(scripts_dir)?;
            if !library.is_dir() {
                return Err(AppError::usage(format!(
                    "no script library directory at {}; install a pack with `portensor scripts install <DIR>` or pass an explicit PATH",
                    library.display()
                )));
            }
            library
        }
    };
    recover_library(&path)?;
    let registry = Registry::load(&path)?;
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
        let capabilities = summary
            .capabilities
            .iter()
            .map(|capability| capability.as_str())
            .collect::<Vec<_>>()
            .join(",");
        println!(
            "  {:<28} [{}/{}] {} ms  capabilities={}  ports={} services={}",
            summary.name,
            summary.danger.as_str(),
            summary.category.as_str(),
            summary.timeout_ms,
            capabilities,
            ports,
            services
        );
        if summary.kind == "wasm" {
            println!(
                "    wasm: {}",
                summary.wasm_path.as_deref().unwrap_or("<unknown>")
            );
        } else {
            println!("    command: {}", summary.command.join(" "));
        }
        if let Some(description) = &summary.description {
            println!("    {description}");
        }
    }
    Ok(())
}

pub(crate) struct LibraryLock {
    path: PathBuf,
}

impl LibraryLock {
    pub(crate) fn acquire(library: &Path) -> Result<Self, AppError> {
        std::fs::create_dir_all(library).map_err(|error| {
            AppError::usage(format!(
                "cannot create script library {}: {error}",
                library.display()
            ))
        })?;
        let path = library.join("packs.lock.lock");
        let mut file = match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                return Err(AppError::usage(format!(
                    "another script pack operation holds {}; remove it only if no portensor process is running",
                    path.display()
                )));
            }
            Err(error) => {
                return Err(AppError::usage(format!(
                    "cannot lock script library {}: {error}",
                    library.display()
                )));
            }
        };
        let _ = writeln!(file, "{}", std::process::id());
        Ok(Self { path })
    }
}

impl Drop for LibraryLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

fn staging_path(library: &Path, name: &str) -> PathBuf {
    library.join(format!(".staging-{name}"))
}

fn backup_path(library: &Path, name: &str) -> PathBuf {
    library.join(format!(".backup-{name}"))
}

pub(crate) fn recover_library(library: &Path) -> Result<(), AppError> {
    if !library.is_dir() {
        return Ok(());
    }
    let _lock = LibraryLock::acquire(library)?;
    recover_library_unlocked(library)
}

/// Restore or clean interrupted installs. Callers must hold `LibraryLock`.
pub(crate) fn recover_library_unlocked(library: &Path) -> Result<(), AppError> {
    if !library.is_dir() {
        return Ok(());
    }
    for entry in std::fs::read_dir(library).map_err(|error| {
        AppError::usage(format!(
            "cannot inspect script library {}: {error}",
            library.display()
        ))
    })? {
        let entry = entry.map_err(|error| {
            AppError::usage(format!("cannot inspect script library entry: {error}"))
        })?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if let Some(pack) = name.strip_prefix(".backup-") {
            if validate_library_name(pack).is_err() {
                continue;
            }
            let destination = library.join(pack);
            if destination.exists() {
                let _ = std::fs::remove_dir_all(entry.path());
            } else {
                std::fs::rename(entry.path(), &destination).map_err(|error| {
                    AppError::runtime(format!(
                        "cannot restore interrupted script pack update for '{pack}': {error}"
                    ))
                })?;
            }
        } else if name.starts_with(".staging-") {
            let _ = std::fs::remove_dir_all(entry.path());
        }
    }
    Ok(())
}

/// Validate a pack directory and copy it into the library under its
/// directory name. Existing installations require `force`.
pub fn install_pack(source: &Path, library: &Path, force: bool) -> Result<PathBuf, AppError> {
    let _lock = LibraryLock::acquire(library)?;
    let installed = install_pack_locked(source, library, force)?;
    if let Some(name) = installed.file_name().and_then(|name| name.to_str()) {
        let _ = marketplace::remove_lock_entry_unlocked(library, name);
    }
    Ok(installed)
}

pub(crate) fn install_pack_locked(
    source: &Path,
    library: &Path,
    force: bool,
) -> Result<PathBuf, AppError> {
    recover_library_unlocked(library)?;
    let metadata = std::fs::metadata(source).map_err(|error| {
        AppError::usage(format!(
            "cannot read script pack {}: {error}",
            source.display()
        ))
    })?;
    if !metadata.is_dir() {
        return Err(AppError::usage(format!(
            "script pack {} must be a directory",
            source.display()
        )));
    }
    // Compile every manifest before touching the library so a broken pack
    // never lands on disk.
    Registry::load(source)?;
    let name = source
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| AppError::usage("script pack directory has no usable name"))?;
    validate_library_name(name)?;
    let destination = library.join(name);
    if destination.exists() {
        if !force {
            return Err(AppError::usage(format!(
                "script pack '{name}' is already installed at {}; use --force to replace it",
                destination.display()
            )));
        }
        let source_canonical = std::fs::canonicalize(source).ok();
        let destination_canonical = std::fs::canonicalize(&destination).ok();
        if source_canonical.is_some() && source_canonical == destination_canonical {
            return Err(AppError::usage(format!(
                "script pack '{name}' is already installed at {}",
                destination.display()
            )));
        }
    }
    std::fs::create_dir_all(library).map_err(|error| {
        AppError::usage(format!(
            "cannot create script library {}: {error}",
            library.display()
        ))
    })?;
    let stage = staging_path(library, name);
    if stage.exists() {
        std::fs::remove_dir_all(&stage).map_err(|error| {
            AppError::usage(format!(
                "cannot clear stale script staging directory {}: {error}",
                stage.display()
            ))
        })?;
    }
    if let Err(error) = copy_tree(source, &stage) {
        let _ = std::fs::remove_dir_all(&stage);
        return Err(error);
    }
    let backup = backup_path(library, name);
    let had_destination = destination.exists();
    if had_destination {
        if backup.exists() {
            std::fs::remove_dir_all(&backup).map_err(|error| {
                AppError::usage(format!(
                    "cannot clear stale script backup directory {}: {error}",
                    backup.display()
                ))
            })?;
        }
        std::fs::rename(&destination, &backup).map_err(|error| {
            let _ = std::fs::remove_dir_all(&stage);
            AppError::usage(format!(
                "cannot stage installed pack {} for replacement: {error}",
                destination.display()
            ))
        })?;
    }
    match std::fs::rename(&stage, &destination) {
        Ok(()) => {
            if had_destination {
                let _ = std::fs::remove_dir_all(&backup);
            }
            Ok(destination)
        }
        Err(error) => {
            let _ = std::fs::remove_dir_all(&stage);
            if had_destination {
                let _ = std::fs::rename(&backup, &destination);
            }
            Err(AppError::runtime(format!(
                "cannot install script pack into {}: {error}",
                destination.display()
            )))
        }
    }
}

/// Remove an installed pack from the library. Only direct child directories
/// are addressable; names are identifier-validated.
pub fn uninstall_pack(name: &str, library: &Path) -> Result<PathBuf, AppError> {
    let _lock = LibraryLock::acquire(library)?;
    recover_library_unlocked(library)?;
    validate_library_name(name)?;
    let target = library.join(name);
    let metadata = std::fs::metadata(&target).map_err(|error| {
        AppError::usage(format!(
            "script pack '{name}' is not installed at {}: {error}",
            target.display()
        ))
    })?;
    if !metadata.is_dir() {
        return Err(AppError::usage(format!(
            "script pack '{name}' at {} is not a directory",
            target.display()
        )));
    }
    std::fs::remove_dir_all(&target).map_err(|error| {
        AppError::usage(format!(
            "cannot remove installed pack {}: {error}",
            target.display()
        ))
    })?;
    let _ = marketplace::remove_lock_entry_unlocked(library, name);
    Ok(target)
}

fn validate_library_name(name: &str) -> Result<(), AppError> {
    if name == "." || name == ".." || name.starts_with('.') {
        return Err(AppError::usage("invalid script pack name"));
    }
    validate_identifier("script pack", name)
}

fn copy_tree(source: &Path, destination: &Path) -> Result<(), AppError> {
    std::fs::create_dir_all(destination).map_err(copy_error(destination))?;
    let mut entries = 0usize;
    let mut total = 0u64;
    let mut stack = vec![(source.to_path_buf(), destination.to_path_buf())];
    while let Some((from, to)) = stack.pop() {
        for entry in std::fs::read_dir(&from).map_err(copy_error(&from))? {
            let entry = entry.map_err(copy_error(&from))?;
            let file_type = entry.file_type().map_err(copy_error(&entry.path()))?;
            if !file_type.is_file() && !file_type.is_dir() {
                return Err(AppError::usage(format!(
                    "script pack contains an unsupported entry (symlink?): {}",
                    entry.path().display()
                )));
            }
            entries += 1;
            if entries > MAX_LIBRARY_ENTRIES {
                return Err(AppError::usage(format!(
                    "script pack contains more than {MAX_LIBRARY_ENTRIES} entries"
                )));
            }
            let target = to.join(entry.file_name());
            if file_type.is_dir() {
                std::fs::create_dir_all(&target).map_err(copy_error(&target))?;
                stack.push((entry.path(), target));
            } else {
                let size = entry.metadata().map_err(copy_error(&entry.path()))?.len();
                total = total.saturating_add(size);
                if total > MAX_LIBRARY_BYTES {
                    return Err(AppError::usage(format!(
                        "script pack exceeds the {MAX_LIBRARY_BYTES}-byte install limit"
                    )));
                }
                std::fs::copy(entry.path(), &target).map_err(copy_error(&target))?;
            }
        }
    }
    Ok(())
}

fn copy_error(path: &Path) -> impl Fn(std::io::Error) -> AppError + '_ {
    move |error| {
        AppError::usage(format!(
            "cannot copy script pack entry {}: {error}",
            path.display()
        ))
    }
}

fn normalize_capabilities(
    plugin: &str,
    capabilities: Vec<Capability>,
) -> Result<Vec<Capability>, AppError> {
    let capabilities = if capabilities.is_empty() {
        vec![Capability::Metadata]
    } else {
        capabilities
    };
    if capabilities.len() != 1 {
        return Err(AppError::usage(format!(
            "script '{plugin}' must declare exactly one capability (metadata or target-tcp)"
        )));
    }
    Ok(capabilities)
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

    let capabilities = normalize_capabilities(&plugin, raw.capabilities)?;
    let (kind, command, wasm_path, module) = match (raw.command, raw.wasm) {
        (Some(_), Some(_)) => {
            return Err(AppError::usage(format!(
                "script '{plugin}' cannot set both command and wasm"
            )));
        }
        (Some(command), None) => (
            ScriptKind::Sidecar,
            compile_sidecar_command(&plugin, dir, command)?,
            None,
            None,
        ),
        (None, Some(wasm)) => {
            let (path, module) = compile_wasm_module(&plugin, dir, &wasm)?;
            (ScriptKind::Wasm, Vec::new(), Some(path), Some(module))
        }
        (None, None) => {
            return Err(AppError::usage(format!(
                "script '{plugin}' must set command or wasm"
            )));
        }
    };

    if kind == ScriptKind::Sidecar && capabilities.contains(&Capability::TargetTcp) {
        return Err(AppError::usage(format!(
            "script '{plugin}' requests target-tcp with a sidecar command; active capabilities require wasm"
        )));
    }

    /// Resolves and validates a sidecar command argv.
    fn compile_sidecar_command(
        plugin: &str,
        dir: &Path,
        command: Vec<String>,
    ) -> Result<Vec<String>, AppError> {
        if command.is_empty() || command.len() > MAX_COMMAND_ARGS {
            return Err(AppError::usage(format!(
                "script '{plugin}' command must contain 1-{MAX_COMMAND_ARGS} arguments"
            )));
        }
        let mut command = command;
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
        Ok(command)
    }

    /// Reads, size-checks, and compiles a WASM module at manifest load time.
    fn compile_wasm_module(
        plugin: &str,
        dir: &Path,
        wasm: &str,
    ) -> Result<(PathBuf, wasmtime::Module), AppError> {
        if wasm.is_empty() {
            return Err(AppError::usage(format!(
                "script '{plugin}' has an empty wasm path"
            )));
        }
        let path = dir.join(wasm);
        let size = std::fs::metadata(&path).map_err(|error| {
            AppError::usage(format!(
                "script '{plugin}' wasm module {} cannot be read: {error}",
                path.display()
            ))
        })?;
        if !size.is_file() {
            return Err(AppError::usage(format!(
                "script '{plugin}' wasm module {} is not a file",
                path.display()
            )));
        }
        if size.len() > MAX_WASM_BYTES as u64 {
            return Err(AppError::usage(format!(
                "script '{plugin}' wasm module exceeds the {MAX_WASM_BYTES}-byte limit"
            )));
        }
        let bytes = std::fs::read(&path).map_err(|error| {
            AppError::usage(format!(
                "script '{plugin}' wasm module {} cannot be read: {error}",
                path.display()
            ))
        })?;
        let module = wasmtime::Module::new(wasm_engine(), &bytes).map_err(|error| {
            AppError::usage(format!(
                "script '{plugin}' failed to compile wasm module {}: {error}",
                path.display()
            ))
        })?;
        Ok((path, module))
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
        capabilities,
        kind,
        command,
        wasm_path,
        module,
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

/// Executes a script against one open port, dispatching on its runtime kind.
async fn run_script(
    script: &CompiledScript,
    result: &PortResult,
    context: Option<&ScriptExecutionContext>,
) -> Result<(Vec<PluginFinding>, Option<Assessment>), String> {
    let fallback;
    let context = match context {
        Some(context) => context,
        None => {
            fallback = ScriptExecutionContext::new(None, false);
            &fallback
        }
    };
    match script.kind {
        ScriptKind::Sidecar => run_sidecar_script(script, result).await,
        ScriptKind::Wasm => run_wasm_script(script, result, context).await,
    }
}

/// Shared input document for sidecar and WASM scripts.
fn script_input(result: &PortResult) -> Result<Vec<u8>, String> {
    serde_json::to_vec(&ScriptInput {
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
    .map_err(|error| format!("cannot encode input: {error}"))
}

/// Validates and converts a script's JSON output document.
fn parse_script_output(
    plugin: &str,
    name: &str,
    stdout: &[u8],
) -> Result<(Vec<PluginFinding>, Option<Assessment>), String> {
    let output: ScriptOutput =
        serde_json::from_slice(stdout).map_err(|error| format!("invalid JSON output: {error}"))?;
    if output.findings.len() > MAX_FINDINGS {
        return Err(format!(
            "returned {} findings (maximum {MAX_FINDINGS})",
            output.findings.len()
        ));
    }
    let findings = output
        .findings
        .into_iter()
        .map(|raw| validate_finding(plugin, name, raw))
        .collect::<Result<Vec<_>, String>>()?;
    let assessment = match output.service {
        Some(raw) => Some(service_assessment(raw)?),
        None => None,
    };
    Ok((findings, assessment))
}

#[derive(Clone)]
struct ScriptExecutionContext {
    scope: Option<Arc<ScopeGuard>>,
    force_out_of_scope: bool,
    rate: Arc<Mutex<VecDeque<Instant>>>,
}

impl ScriptExecutionContext {
    fn new(scope: Option<&ScopeGuard>, force_out_of_scope: bool) -> Self {
        Self {
            scope: scope.cloned().map(Arc::new),
            force_out_of_scope,
            rate: Arc::new(Mutex::new(VecDeque::new())),
        }
    }
}

struct WasmHostState {
    limits: wasmtime::StoreLimits,
    plugin: String,
    target: IpAddr,
    port: u16,
    scope: Option<Arc<ScopeGuard>>,
    force_out_of_scope: bool,
    connection: Option<TcpStream>,
    attempts: u32,
    bytes_read: usize,
    bytes_written: usize,
    rate: Arc<Mutex<VecDeque<Instant>>>,
}

fn audit_active(plugin: &str, target: IpAddr, port: u16, action: &str, outcome: &str, code: i32) {
    crate::diag::event(
        crate::diag::Level::Info,
        "script",
        &[
            ("script", serde_json::json!(plugin)),
            ("capability", serde_json::json!("target-tcp")),
            ("target", serde_json::json!(target.to_string())),
            ("port", serde_json::json!(port)),
            ("action", serde_json::json!(action)),
            ("outcome", serde_json::json!(outcome)),
            ("error_code", serde_json::json!(code)),
        ],
    );
}

fn active_scope_allows(state: &WasmHostState) -> bool {
    state.force_out_of_scope
        || state
            .scope
            .as_ref()
            .is_none_or(|scope| scope.allows_ip(state.target))
}

fn active_timeout(timeout_ms: i32) -> Duration {
    Duration::from_millis(timeout_ms.clamp(1, 5000) as u64)
}

fn active_tcp_connect(
    mut caller: wasmtime::Caller<'_, WasmHostState>,
    port: i32,
    timeout_ms: i32,
) -> i32 {
    let (target, expected_port, plugin) = {
        let data = caller.data();
        (data.target, data.port, data.plugin.clone())
    };
    if port != i32::from(expected_port) {
        audit_active(
            &plugin,
            target,
            expected_port,
            "connect",
            "denied",
            ACTIVE_WRONG_PORT,
        );
        return ACTIVE_WRONG_PORT;
    }
    if timeout_ms <= 0 {
        audit_active(
            &plugin,
            target,
            expected_port,
            "connect",
            "denied",
            ACTIVE_BAD_REQUEST,
        );
        return ACTIVE_BAD_REQUEST;
    }
    if !active_scope_allows(caller.data()) {
        audit_active(
            &plugin,
            target,
            expected_port,
            "connect",
            "denied",
            ACTIVE_DENIED,
        );
        return ACTIVE_DENIED;
    }
    {
        let data = caller.data_mut();
        if data.connection.is_some() {
            audit_active(
                &plugin,
                target,
                expected_port,
                "connect",
                "denied",
                ACTIVE_NOT_OPEN,
            );
            return ACTIVE_NOT_OPEN;
        }
        if data.attempts >= ACTIVE_MAX_CONNECTIONS {
            audit_active(
                &plugin,
                target,
                expected_port,
                "connect",
                "denied",
                ACTIVE_ATTEMPT_LIMIT,
            );
            return ACTIVE_ATTEMPT_LIMIT;
        }
        data.attempts += 1;
    }
    let allowed_rate = {
        let history = caller.data().rate.clone();
        match history.lock() {
            Ok(mut history) => {
                let now = Instant::now();
                while history.front().is_some_and(|timestamp| {
                    now.duration_since(*timestamp) >= Duration::from_secs(1)
                }) {
                    history.pop_front();
                }
                if history.len() >= ACTIVE_RATE_PER_SECOND {
                    false
                } else {
                    history.push_back(now);
                    true
                }
            }
            Err(_) => false,
        }
    };
    if !allowed_rate {
        audit_active(
            &plugin,
            target,
            expected_port,
            "connect",
            "denied",
            ACTIVE_RATE_LIMIT,
        );
        return ACTIVE_RATE_LIMIT;
    }

    let address = SocketAddr::new(target, expected_port);
    match TcpStream::connect_timeout(&address, active_timeout(timeout_ms)) {
        Ok(stream) => {
            let _ = stream.set_read_timeout(Some(ACTIVE_OP_TIMEOUT));
            let _ = stream.set_write_timeout(Some(ACTIVE_OP_TIMEOUT));
            caller.data_mut().connection = Some(stream);
            audit_active(
                &plugin,
                target,
                expected_port,
                "connect",
                "allowed",
                ACTIVE_OK,
            );
            ACTIVE_OK
        }
        Err(_) => {
            audit_active(
                &plugin,
                target,
                expected_port,
                "connect",
                "failed",
                ACTIVE_IO_ERROR,
            );
            ACTIVE_IO_ERROR
        }
    }
}

fn active_tcp_read(
    mut caller: wasmtime::Caller<'_, WasmHostState>,
    handle: i32,
    buffer_ptr: i32,
    buffer_len: i32,
    timeout_ms: i32,
) -> i32 {
    let (target, port, plugin) = {
        let data = caller.data();
        (data.target, data.port, data.plugin.clone())
    };
    if handle != 0 || buffer_ptr < 0 || buffer_len < 0 || timeout_ms <= 0 {
        audit_active(&plugin, target, port, "read", "denied", ACTIVE_BAD_REQUEST);
        return ACTIVE_BAD_REQUEST;
    }
    let memory = match caller
        .get_export("memory")
        .and_then(|export| export.into_memory())
    {
        Some(memory) => memory,
        None => {
            audit_active(&plugin, target, port, "read", "denied", ACTIVE_BAD_REQUEST);
            return ACTIVE_BAD_REQUEST;
        }
    };
    let requested = buffer_len as usize;
    let remaining = ACTIVE_MAX_BYTES.saturating_sub(caller.data().bytes_read);
    if requested > remaining {
        audit_active(&plugin, target, port, "read", "denied", ACTIVE_BYTE_LIMIT);
        return ACTIVE_BYTE_LIMIT;
    }
    let mut stream = match caller.data_mut().connection.take() {
        Some(stream) => stream,
        None => {
            audit_active(&plugin, target, port, "read", "denied", ACTIVE_NOT_OPEN);
            return ACTIVE_NOT_OPEN;
        }
    };
    let _ = stream.set_read_timeout(Some(active_timeout(timeout_ms)));
    let mut buffer = vec![0u8; requested];
    let result = std::io::Read::read(&mut stream, &mut buffer);
    caller.data_mut().connection = Some(stream);
    match result {
        Ok(read) => {
            caller.data_mut().bytes_read += read;
            if memory
                .write(&mut caller, buffer_ptr as usize, &buffer[..read])
                .is_err()
            {
                audit_active(&plugin, target, port, "read", "denied", ACTIVE_BAD_REQUEST);
                return ACTIVE_BAD_REQUEST;
            }
            audit_active(&plugin, target, port, "read", "allowed", ACTIVE_OK);
            read as i32
        }
        Err(_) => {
            audit_active(&plugin, target, port, "read", "failed", ACTIVE_IO_ERROR);
            ACTIVE_IO_ERROR
        }
    }
}

fn active_tcp_write(
    mut caller: wasmtime::Caller<'_, WasmHostState>,
    handle: i32,
    buffer_ptr: i32,
    buffer_len: i32,
) -> i32 {
    let (target, port, plugin) = {
        let data = caller.data();
        (data.target, data.port, data.plugin.clone())
    };
    if handle != 0 || buffer_ptr < 0 || buffer_len < 0 {
        audit_active(&plugin, target, port, "write", "denied", ACTIVE_BAD_REQUEST);
        return ACTIVE_BAD_REQUEST;
    }
    let memory = match caller
        .get_export("memory")
        .and_then(|export| export.into_memory())
    {
        Some(memory) => memory,
        None => {
            audit_active(&plugin, target, port, "write", "denied", ACTIVE_BAD_REQUEST);
            return ACTIVE_BAD_REQUEST;
        }
    };
    let requested = buffer_len as usize;
    let remaining = ACTIVE_MAX_BYTES.saturating_sub(caller.data().bytes_written);
    if requested > remaining {
        audit_active(&plugin, target, port, "write", "denied", ACTIVE_BYTE_LIMIT);
        return ACTIVE_BYTE_LIMIT;
    }
    let mut buffer = vec![0u8; requested];
    if memory
        .read(&caller, buffer_ptr as usize, &mut buffer)
        .is_err()
    {
        audit_active(&plugin, target, port, "write", "denied", ACTIVE_BAD_REQUEST);
        return ACTIVE_BAD_REQUEST;
    }
    let mut stream = match caller.data_mut().connection.take() {
        Some(stream) => stream,
        None => {
            audit_active(&plugin, target, port, "write", "denied", ACTIVE_NOT_OPEN);
            return ACTIVE_NOT_OPEN;
        }
    };
    let _ = stream.set_write_timeout(Some(ACTIVE_OP_TIMEOUT));
    let result = std::io::Write::write(&mut stream, &buffer);
    caller.data_mut().connection = Some(stream);
    match result {
        Ok(written) => {
            caller.data_mut().bytes_written += written;
            audit_active(&plugin, target, port, "write", "allowed", ACTIVE_OK);
            written as i32
        }
        Err(_) => {
            audit_active(&plugin, target, port, "write", "failed", ACTIVE_IO_ERROR);
            ACTIVE_IO_ERROR
        }
    }
}

fn active_tcp_close(mut caller: wasmtime::Caller<'_, WasmHostState>, handle: i32) -> i32 {
    let (target, port, plugin) = {
        let data = caller.data();
        (data.target, data.port, data.plugin.clone())
    };
    if handle != 0 {
        audit_active(&plugin, target, port, "close", "denied", ACTIVE_BAD_REQUEST);
        return ACTIVE_BAD_REQUEST;
    }
    let present = caller.data_mut().connection.take();
    if present.is_none() {
        audit_active(&plugin, target, port, "close", "denied", ACTIVE_NOT_OPEN);
        return ACTIVE_NOT_OPEN;
    }
    drop(present);
    audit_active(&plugin, target, port, "close", "allowed", ACTIVE_OK);
    ACTIVE_OK
}

/// Lazily-created process-wide wasmtime engine (fuel metering enabled).
fn wasm_engine() -> &'static wasmtime::Engine {
    static ENGINE: std::sync::OnceLock<wasmtime::Engine> = std::sync::OnceLock::new();
    ENGINE.get_or_init(|| {
        let mut config = wasmtime::Config::new();
        config.consume_fuel(true);
        wasmtime::Engine::new(&config).expect("wasmtime engine initialization")
    })
}

/// Maps a WASM call failure to a stable message, preferring structured trap
/// detection over matching Wasmtime's rendered backtrace text.
fn wasm_call_error(action: &str, error: wasmtime::Error) -> String {
    if matches!(
        error.downcast_ref::<wasmtime::Trap>(),
        Some(wasmtime::Trap::OutOfFuel)
    ) {
        format!("{action} exhausted its fuel budget (possible runaway loop)")
    } else {
        format!("{action} failed: {error}")
    }
}

/// WASM module execution on a blocking thread. Fuel metering plus the store
/// limiter bound any runaway work; the wall-clock timeout is enforced by the
/// async wrapper.
fn wasm_execute(
    module: &wasmtime::Module,
    input: &[u8],
    script: &CompiledScript,
    result: &PortResult,
    context: &ScriptExecutionContext,
) -> Result<Vec<u8>, String> {
    let engine = wasm_engine();
    let mut store = wasmtime::Store::new(
        engine,
        WasmHostState {
            limits: wasmtime::StoreLimitsBuilder::new()
                .memory_size(WASM_MEMORY_BYTES)
                .memories(1)
                .tables(1)
                .table_elements(WASM_TABLE_ELEMENTS)
                .build(),
            plugin: script.plugin.clone(),
            target: result.host,
            port: result.port,
            scope: context.scope.clone(),
            force_out_of_scope: context.force_out_of_scope,
            connection: None,
            attempts: 0,
            bytes_read: 0,
            bytes_written: 0,
            rate: context.rate.clone(),
        },
    );
    store.limiter(|data| &mut data.limits);
    store
        .set_fuel(WASM_FUEL)
        .map_err(|error| format!("cannot set fuel budget: {error}"))?;

    let mut linker = wasmtime::Linker::new(engine);
    if script.capabilities.contains(&Capability::TargetTcp) {
        linker
            .func_wrap(
                "portensor.script.v1",
                "tcp_connect",
                |caller: wasmtime::Caller<'_, WasmHostState>, port: i32, timeout_ms: i32| {
                    active_tcp_connect(caller, port, timeout_ms)
                },
            )
            .map_err(|error| format!("cannot define tcp_connect: {error}"))?;
        linker
            .func_wrap(
                "portensor.script.v1",
                "tcp_read",
                |caller: wasmtime::Caller<'_, WasmHostState>,
                 handle: i32,
                 ptr: i32,
                 len: i32,
                 timeout_ms: i32| {
                    active_tcp_read(caller, handle, ptr, len, timeout_ms)
                },
            )
            .map_err(|error| format!("cannot define tcp_read: {error}"))?;
        linker
            .func_wrap(
                "portensor.script.v1",
                "tcp_write",
                |caller: wasmtime::Caller<'_, WasmHostState>, handle: i32, ptr: i32, len: i32| {
                    active_tcp_write(caller, handle, ptr, len)
                },
            )
            .map_err(|error| format!("cannot define tcp_write: {error}"))?;
        linker
            .func_wrap(
                "portensor.script.v1",
                "tcp_close",
                |caller: wasmtime::Caller<'_, WasmHostState>, handle: i32| {
                    active_tcp_close(caller, handle)
                },
            )
            .map_err(|error| format!("cannot define tcp_close: {error}"))?;
    }

    let instance = linker
        .instantiate(&mut store, module)
        .map_err(|error| format!("cannot instantiate module: {error}"))?;
    let memory = instance
        .get_memory(&mut store, "memory")
        .ok_or_else(|| "module does not export memory".to_string())?;
    let alloc = instance
        .get_typed_func::<i32, i32>(&mut store, "alloc")
        .map_err(|_| "module does not export alloc(i32) -> i32".to_string())?;
    let run = instance
        .get_typed_func::<(i32, i32), i64>(&mut store, "run")
        .map_err(|_| "module does not export run(i32, i32) -> i64".to_string())?;

    let ptr = alloc
        .call(&mut store, input.len() as i32)
        .map_err(|error| wasm_call_error("alloc", error))?;
    if ptr < 0 {
        return Err("alloc returned a negative pointer".to_string());
    }
    memory
        .write(&mut store, ptr as usize, input)
        .map_err(|_| "alloc returned an out-of-bounds pointer".to_string())?;

    let packed = run
        .call(&mut store, (ptr, input.len() as i32))
        .map_err(|error| wasm_call_error("run", error))?;

    let out_ptr = ((packed as u64) >> 32) as usize;
    let out_len = (packed as u64 & 0xFFFF_FFFF) as usize;
    if out_len > MAX_STDOUT {
        return Err(format!("output exceeds the {MAX_STDOUT}-byte limit"));
    }
    let mut output = vec![0u8; out_len];
    memory
        .read(&store, out_ptr, &mut output)
        .map_err(|_| "run returned an out-of-bounds pointer".to_string())?;
    Ok(output)
}

async fn run_wasm_script(
    script: &CompiledScript,
    result: &PortResult,
    context: &ScriptExecutionContext,
) -> Result<(Vec<PluginFinding>, Option<Assessment>), String> {
    let module = script
        .module
        .as_ref()
        .ok_or_else(|| "missing wasm module".to_string())?;
    let input = script_input(result)?;

    let task = tokio::task::spawn_blocking({
        let module = module.clone();
        let script = script.clone();
        let result = result.clone();
        let context = context.clone();
        move || wasm_execute(&module, &input, &script, &result, &context)
    });
    let output = match tokio::time::timeout(script.timeout, task).await {
        Ok(joined) => joined.map_err(|error| format!("wasm worker failed: {error}"))?,
        Err(_) => {
            return Err(format!("timed out after {} ms", script.timeout.as_millis()));
        }
    }?;

    parse_script_output(&script.plugin, &script.name, &output)
}

#[cfg(not(target_os = "linux"))]
fn sidecar_isolation() -> Result<(), String> {
    Err(
        "sidecar scripts require a verified network-deny sandbox and are disabled on this platform; use a WASM script instead"
            .to_string(),
    )
}

#[cfg(target_os = "linux")]
fn sidecar_isolation() -> Result<(), String> {
    Ok(())
}

#[cfg(target_os = "linux")]
fn sidecar_filter() -> Vec<libc::sock_filter> {
    const BPF_LD_W_ABS: u16 = 0x20;
    const BPF_JEQ_K: u16 = 0x15;
    const BPF_RET_K: u16 = 0x06;
    const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
    const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
    const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;

    #[cfg(target_arch = "x86_64")]
    const AUDIT_ARCH: u32 = 0xc000_003e;
    #[cfg(target_arch = "aarch64")]
    const AUDIT_ARCH: u32 = 0xc000_00b7;
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    compile_error!("sidecar seccomp filter supports x86_64 and aarch64 Linux only");

    fn stmt(code: u16, k: u32) -> libc::sock_filter {
        libc::sock_filter {
            code,
            jt: 0,
            jf: 0,
            k,
        }
    }
    fn jump(code: u16, k: u32, jt: u8, jf: u8) -> libc::sock_filter {
        libc::sock_filter { code, jt, jf, k }
    }

    let mut filter = Vec::with_capacity(48);
    filter.push(stmt(
        BPF_LD_W_ABS,
        std::mem::offset_of!(libc::seccomp_data, arch) as u32,
    ));
    filter.push(jump(BPF_JEQ_K, AUDIT_ARCH, 1, 0));
    filter.push(stmt(BPF_RET_K, SECCOMP_RET_KILL_PROCESS));
    filter.push(stmt(
        BPF_LD_W_ABS,
        std::mem::offset_of!(libc::seccomp_data, nr) as u32,
    ));
    let denied = [
        libc::SYS_socket,
        libc::SYS_socketpair,
        libc::SYS_connect,
        libc::SYS_bind,
        libc::SYS_listen,
        libc::SYS_accept,
        libc::SYS_accept4,
        libc::SYS_sendto,
        libc::SYS_sendmsg,
        libc::SYS_recvfrom,
        libc::SYS_recvmsg,
        libc::SYS_sendmmsg,
        libc::SYS_recvmmsg,
        libc::SYS_getsockname,
        libc::SYS_getpeername,
        libc::SYS_setsockopt,
        libc::SYS_getsockopt,
        libc::SYS_shutdown,
    ];
    for syscall in denied {
        filter.push(jump(BPF_JEQ_K, syscall as u32, 0, 1));
        filter.push(stmt(BPF_RET_K, SECCOMP_RET_ERRNO | libc::EPERM as u32));
    }
    filter.push(stmt(BPF_RET_K, SECCOMP_RET_ALLOW));
    filter
}

#[cfg(target_os = "linux")]
fn apply_sidecar_filter(filter: &[libc::sock_filter]) -> std::io::Result<()> {
    let program = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_ptr() as *mut libc::sock_filter,
    };
    // SAFETY: the filter is a valid BPF program and remains alive for the
    // duration of the prctl call. Both calls are async-signal-safe.
    unsafe {
        if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
            return Err(std::io::Error::last_os_error());
        }
        if libc::prctl(
            libc::PR_SET_SECCOMP,
            libc::SECCOMP_MODE_FILTER,
            &program as *const libc::sock_fprog,
        ) != 0
        {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

async fn run_sidecar_script(
    script: &CompiledScript,
    result: &PortResult,
) -> Result<(Vec<PluginFinding>, Option<Assessment>), String> {
    sidecar_isolation()?;
    let payload = script_input(result)?;

    let mut command = Command::new(&script.command[0]);
    command
        .args(&script.command[1..])
        .current_dir(&script.dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .env_clear()
        .env("PORTENSOR_SCRIPT_API", "1")
        .env("PORTENSOR_SCRIPT_NAME", &script.name)
        .env("PORTENSOR_SCRIPT_PLUGIN", &script.plugin)
        .env("PORTENSOR_SCRIPT_CAPABILITY", "metadata")
        .env("PORTENSOR_TARGET", result.host.to_string())
        .env("PORTENSOR_PORT", result.port.to_string())
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .env("PYTHONNOUSERSITE", "1");
    if let Some(path) = std::env::var_os("PATH") {
        command.env("PATH", path);
    }

    #[cfg(target_os = "linux")]
    {
        use std::os::unix::process::CommandExt as _;
        let filter = sidecar_filter();
        // SAFETY: the closure only installs a fixed seccomp filter, which is
        // async-signal-safe. It never allocates or inspects shared state.
        unsafe {
            command
                .as_std_mut()
                .pre_exec(move || apply_sidecar_filter(&filter));
        }
    }

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

    parse_script_output(&script.plugin, &script.name, &stdout)
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

pub(crate) fn valid_identifier(value: &str) -> bool {
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
        assert_eq!(summary.capabilities, [Capability::Metadata]);
        assert_eq!(summary.timeout_ms, DEFAULT_TIMEOUT_MS);
        assert_eq!(summary.services, ["https"]);
        assert_eq!(summary.ports, [443, 8443]);
    }

    #[test]
    fn validates_capability_declarations() {
        let mut registry = Registry::default();
        let error = registry
            .parse(
                r#"
name = "unit"
[[script]]
name = "active-sidecar"
capabilities = ["target-tcp"]
command = ["sh", "check.sh"]
"#,
                Path::new("."),
            )
            .expect_err("active sidecars must be rejected");
        assert!(
            error
                .to_string()
                .contains("active capabilities require wasm")
        );

        let mut registry = Registry::default();
        let error = registry
            .parse(
                r#"
name = "unit"
[[script]]
name = "both-capabilities"
capabilities = ["metadata", "target-tcp"]
command = ["sh", "check.sh"]
"#,
                Path::new("."),
            )
            .expect_err("multiple capabilities must be rejected");
        assert!(error.to_string().contains("exactly one capability"));

        let mut registry = Registry::default();
        let error = registry
            .parse(
                r#"
name = "unit"
[[script]]
name = "unknown"
capabilities = ["network-any"]
command = ["sh", "check.sh"]
"#,
                Path::new("."),
            )
            .expect_err("unknown capabilities must be rejected");
        assert!(error.to_string().contains("unknown variant"));

        let dir = std::env::temp_dir().join(format!(
            "portensor-script-capability-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        write_wasm_script(&dir, "active.wat", &wasm_echo_wat("{}"));
        let mut registry = Registry::default();
        registry
            .parse(
                r#"
name = "active"
[[script]]
name = "connect"
capabilities = ["target-tcp"]
wasm = "active.wat"
"#,
                &dir,
            )
            .expect("active wasm capability parses");
        assert_eq!(
            registry.summaries()[0].capabilities,
            [Capability::TargetTcp]
        );
        let _ = std::fs::remove_dir_all(&dir);
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
            std::env::temp_dir().join(format!("portensor-script-filter-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        std::fs::write(
            dir.join("emit.sh"),
            "#!/bin/sh\ncat >/dev/null\ncase \"$PORTENSOR_SCRIPT_NAME\" in\n  http-only) svc='{\"name\":\"http\",\"product\":\"Lab HTTP\",\"version\":\"9.9\"}' ;;\n  redis-only) svc='{\"name\":\"redis\"}' ;;\n  *) svc='{\"name\":\"intrusive-svc\"}' ;;\nesac\nprintf '%s\\n' \"{\\\"findings\\\":[{\\\"title\\\":\\\"Always emits\\\",\\\"severity\\\":\\\"low\\\"}],\\\"service\\\":$svc}\"\n",
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
        let dir =
            std::env::temp_dir().join(format!("portensor-script-unit-{}", std::process::id()));
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

        let (findings, assessment) = run_script(script, &result, None)
            .await
            .expect("run sidecar");
        assert!(assessment.is_none());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].title, "Test finding");
        assert_eq!(findings[0].severity, FindingSeverity::High);
        assert_eq!(findings[0].cve, ["CVE-2024-1234"]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn sidecar_network_is_denied() {
        if std::process::Command::new("python3")
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_err()
        {
            eprintln!("python3 is unavailable; skipping sidecar sandbox test");
            return;
        }
        let dir =
            std::env::temp_dir().join(format!("portensor-script-sandbox-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        std::fs::write(
            dir.join("net.py"),
            r#"import json, socket
try:
    socket.socket()
except OSError as error:
    print(json.dumps({'findings': [{'title': 'denied: ' + str(error), 'severity': 'info'}]}))
else:
    print(json.dumps({'findings': []}))
"#,
        )
        .expect("write network probe");
        let mut registry = Registry::default();
        registry
            .parse(
                r#"
name = "sandbox"
[[script]]
name = "network"
command = ["python3", "net.py"]
"#,
                &dir,
            )
            .expect("parse manifest");
        let script = &registry.scripts[0];
        let result = PortResult::new(
            "127.0.0.1".parse().expect("ip"),
            80,
            PortState::Open,
            Duration::from_millis(1),
        );
        let (findings, _) = run_script(script, &result, None)
            .await
            .expect("sandboxed sidecar should run");
        assert_eq!(findings.len(), 1);
        assert!(
            findings[0].title.starts_with("denied:"),
            "network syscall was not denied: {}",
            findings[0].title
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Builds a WAT module that writes `output` at address 0 and returns the
    /// packed pointer/length for `run` (and echoes nothing from the input).
    fn wasm_echo_wat(output: &str) -> String {
        let escaped = output.replace('\\', "\\\\").replace('"', "\\\"");
        format!(
            r#"(module
  (memory (export "memory") 1)
  (data (i32.const 0) "{escaped}")
  (global $bump (mut i32) (i32.const 1024))
  (func (export "alloc") (param $len i32) (result i32)
    (local $ptr i32)
    (local.set $ptr (global.get $bump))
    (global.set $bump (i32.add (global.get $bump) (local.get $len)))
    (local.get $ptr))
  (func (export "run") (param $in i32) (param $len i32) (result i64)
    (i64.or
      (i64.shl (i64.extend_i32_u (i32.const 0)) (i64.const 32))
      (i64.extend_i32_u (i32.const {len}))))
)"#,
            len = output.len()
        )
    }

    fn write_wasm_script(dir: &Path, name: &str, wat: &str) {
        std::fs::write(dir.join(name), wat).expect("write wasm module");
    }

    #[tokio::test]
    async fn wasm_script_runs_and_identifies_service() {
        let dir =
            std::env::temp_dir().join(format!("portensor-script-wasm-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let output = r#"{"findings":[{"title":"Wasm finding","severity":"medium","confidence":0.8,"cve":["cve-2025-9999"]}],"service":{"name":"wasmhttp","product":"Wasm Engine","version":"3.1","confidence":0.9}}"#;
        write_wasm_script(&dir, "check.wat", &wasm_echo_wat(output));
        let registry = {
            let mut registry = Registry::default();
            registry
                .parse(
                    r#"
name = "wasmunit"
[[script]]
name = "check"
wasm = "check.wat"
"#,
                    &dir,
                )
                .expect("parse manifest");
            registry
        };
        assert_eq!(registry.script_count(), 1);
        let summary = &registry.summaries()[0];
        assert_eq!(summary.kind, "wasm");
        assert!(summary.command.is_empty());
        assert!(summary.wasm_path.is_some());

        let mut results = [PortResult::new(
            "127.0.0.1".parse().expect("ip"),
            8080,
            PortState::Open,
            Duration::from_millis(1),
        )];
        let findings = registry.apply(&mut results, false, true).await;
        assert_eq!(findings, 1);
        assert_eq!(results[0].script_findings.len(), 1);
        assert_eq!(results[0].script_findings[0].title, "Wasm finding");
        assert_eq!(results[0].script_findings[0].cve, ["CVE-2025-9999"]);
        let service = results[0].service.as_ref().expect("wasm service");
        assert_eq!(service.name, "wasmhttp");
        assert_eq!(service.product.as_deref(), Some("Wasm Engine"));
        assert_eq!(results[0].detail.as_deref(), Some("script:wasmunit/check"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn wasm_manifest_validation() {
        let dir =
            std::env::temp_dir().join(format!("portensor-script-wasm-bad-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        write_wasm_script(&dir, "ok.wat", &wasm_echo_wat("{}"));

        let mut registry = Registry::default();
        let error = registry
            .parse(
                r#"
name = "bad"
[[script]]
name = "both"
wasm = "ok.wat"
command = ["sh", "x.sh"]
"#,
                &dir,
            )
            .expect_err("both runtimes must be rejected");
        assert!(error.to_string().contains("cannot set both"));

        let mut registry = Registry::default();
        let error = registry
            .parse(
                r#"
name = "bad"
[[script]]
name = "neither"
"#,
                &dir,
            )
            .expect_err("missing runtimes must be rejected");
        assert!(error.to_string().contains("must set command or wasm"));

        let mut registry = Registry::default();
        let error = registry
            .parse(
                r#"
name = "bad"
[[script]]
name = "missing"
wasm = "nope.wat"
"#,
                &dir,
            )
            .expect_err("missing module must be rejected");
        assert!(error.to_string().contains("cannot be read"));

        let mut registry = Registry::default();
        registry
            .parse(
                r#"
name = "bad"
[[script]]
name = "duplicate-module"
wasm = "ok.wat"
"#,
                &dir,
            )
            .expect("valid wasm manifest parses");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn wasm_receives_the_input_payload() {
        let dir = std::env::temp_dir().join(format!(
            "portensor-script-wasm-input-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let output = r#"{"findings":[{"title":"Input seen","severity":"info"}]}"#;
        let escaped = output.replace('\\', "\\\\").replace('"', "\\\"");
        // run() only returns the finding when the first input byte is '{',
        // proving the host wrote the JSON payload at alloc's pointer.
        std::fs::write(
            dir.join("check.wat"),
            format!(
                r#"(module
  (memory (export "memory") 1)
  (data (i32.const 0) "{escaped}")
  (global $bump (mut i32) (i32.const 4096))
  (func (export "alloc") (param $len i32) (result i32)
    (local $ptr i32)
    (local.set $ptr (global.get $bump))
    (global.set $bump (i32.add (global.get $bump) (local.get $len)))
    (local.get $ptr))
  (func (export "run") (param $in i32) (param $len i32) (result i64)
    (if (i32.and
          (i32.ne (local.get $len) (i32.const 0))
          (i32.eq (i32.load8_u (local.get $in)) (i32.const 123)))
      (then (return (i64.or
        (i64.shl (i64.extend_i32_u (i32.const 0)) (i64.const 32))
        (i64.extend_i32_u (i32.const {len})))))
      (else (return (i64.const 0))))
    (i64.const 0))
)"#,
                len = output.len()
            ),
        )
        .expect("write wasm module");
        let mut registry = Registry::default();
        registry
            .parse(
                r#"
name = "inputcheck"
[[script]]
name = "reader"
wasm = "check.wat"
"#,
                &dir,
            )
            .expect("parse manifest");
        let script = &registry.scripts[0];
        let result = PortResult::new(
            "127.0.0.1".parse().expect("ip"),
            80,
            PortState::Open,
            Duration::from_millis(1),
        );
        let (findings, _) = run_script(script, &result, None)
            .await
            .expect("module must observe its input payload");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].title, "Input seen");
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn wasm_active_wat(port: u16, connected: &str, denied: &str) -> String {
        let connected_len = connected.len();
        let denied_len = denied.len();
        let connected = connected.replace('\\', "\\\\").replace('"', "\\\"");
        let denied = denied.replace('\\', "\\\\").replace('"', "\\\"");
        let denied_ptr = 512usize;
        format!(
            r#"(module
  (import "portensor.script.v1" "tcp_connect"
    (func $connect (param i32 i32) (result i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "{connected}")
  (data (i32.const {denied_ptr}) "{denied}")
  (global $bump (mut i32) (i32.const 4096))
  (func (export "alloc") (param $len i32) (result i32)
    (local $ptr i32)
    (local.set $ptr (global.get $bump))
    (global.set $bump (i32.add (global.get $bump) (local.get $len)))
    (local.get $ptr))
  (func (export "run") (param $in i32) (param $len i32) (result i64)
    (if (i32.eqz (call $connect (i32.const {port}) (i32.const 1000)))
      (then (return (i64.or
        (i64.shl (i64.extend_i32_u (i32.const 0)) (i64.const 32))
        (i64.extend_i32_u (i32.const {connected_len})))))
      (else (return (i64.or
        (i64.shl (i64.extend_i32_u (i32.const {denied_ptr})) (i64.const 32))
        (i64.extend_i32_u (i32.const {denied_len}))))))
    (i64.const 0))
)"#,
            connected_len = connected_len,
            denied_len = denied_len
        )
    }

    fn wasm_active_rate_wat(port: u16, allowed: &str, denied: &str) -> String {
        let allowed_len = allowed.len();
        let denied_len = denied.len();
        let allowed = allowed.replace('\\', "\\\\").replace('"', "\\\"");
        let denied = denied.replace('\\', "\\\\").replace('"', "\\\"");
        format!(
            r#"(module
  (import "portensor.script.v1" "tcp_connect"
    (func $connect (param i32 i32) (result i32)))
  (import "portensor.script.v1" "tcp_close"
    (func $close (param i32) (result i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "{allowed}")
  (data (i32.const 512) "{denied}")
  (func $loop (param $remaining i32) (result i32)
    (local $code i32)
    (if (i32.eqz (local.get $remaining)) (then (return (i32.const 0))))
    (local.set $code (call $connect (i32.const {port}) (i32.const 1000)))
    (if (i32.ne (local.get $code) (i32.const 0)) (then (return (local.get $code))))
    (drop (call $close (i32.const 0)))
    (call $loop (i32.sub (local.get $remaining) (i32.const 1))))
  (func (export "alloc") (param i32) (result i32) (i32.const 1024))
  (func (export "run") (param i32) (param i32) (result i64)
    (if (i32.eqz (call $loop (i32.const 6)))
      (then (return (i64.or
        (i64.shl (i64.extend_i32_u (i32.const 0)) (i64.const 32))
        (i64.extend_i32_u (i32.const {allowed_len})))))
      (else (return (i64.or
        (i64.shl (i64.extend_i32_u (i32.const 512)) (i64.const 32))
        (i64.extend_i32_u (i32.const {denied_len}))))))
    (i64.const 0))
)"#,
            allowed_len = allowed_len,
            denied_len = denied_len
        )
    }

    fn wasm_active_bytes_wat(port: u16, allowed: &str, denied: &str) -> String {
        let allowed_len = allowed.len();
        let denied_len = denied.len();
        let allowed = allowed.replace('\\', "\\\\").replace('"', "\\\"");
        let denied = denied.replace('\\', "\\\\").replace('"', "\\\"");
        format!(
            r#"(module
  (import "portensor.script.v1" "tcp_connect"
    (func $connect (param i32 i32) (result i32)))
  (import "portensor.script.v1" "tcp_read"
    (func $read (param i32 i32 i32 i32) (result i32)))
  (import "portensor.script.v1" "tcp_write"
    (func $write (param i32 i32 i32) (result i32)))
  (import "portensor.script.v1" "tcp_close"
    (func $close (param i32) (result i32)))
  (memory (export "memory") 1)
  (data (i32.const 0) "{allowed}")
  (data (i32.const 512) "{denied}")
  (func (export "alloc") (param i32) (result i32) (i32.const 1024))
  (func (export "run") (param i32) (param i32) (result i64)
    (local $write i32)
    (local $read i32)
    (if (i32.ne (call $connect (i32.const {port}) (i32.const 1000)) (i32.const 0))
      (then (return (i64.or
        (i64.shl (i64.extend_i32_u (i32.const 512)) (i64.const 32))
        (i64.extend_i32_u (i32.const {denied_len}))))))
    (local.set $write (call $write (i32.const 0) (i32.const 0) (i32.const 1048577)))
    (local.set $read (call $read (i32.const 0) (i32.const 0) (i32.const 1048577) (i32.const 1000)))
    (drop (call $close (i32.const 0)))
    (if (i32.and
          (i32.eq (local.get $write) (i32.const -7))
          (i32.eq (local.get $read) (i32.const -7)))
      (then (return (i64.or
        (i64.shl (i64.extend_i32_u (i32.const 0)) (i64.const 32))
        (i64.extend_i32_u (i32.const {allowed_len})))))
      (else (return (i64.or
        (i64.shl (i64.extend_i32_u (i32.const 512)) (i64.const 32))
        (i64.extend_i32_u (i32.const {denied_len}))))))
    (i64.const 0))
)"#,
            allowed_len = allowed_len,
            denied_len = denied_len
        )
    }

    #[tokio::test]
    async fn active_wasm_connects_only_to_the_scanned_port() {
        let listener =
            std::net::TcpListener::bind("127.0.0.1:0").expect("bind active-script listener");
        let port = listener.local_addr().expect("listener address").port();
        let accept = std::thread::spawn(move || listener.accept().map(|_| ()));
        let dir =
            std::env::temp_dir().join(format!("portensor-script-active-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        write_wasm_script(
            &dir,
            "active.wat",
            &wasm_active_wat(
                port,
                r#"{"findings":[{"title":"connected","severity":"info"}]}"#,
                r#"{"findings":[{"title":"denied","severity":"info"}]}"#,
            ),
        );
        let mut registry = Registry::default();
        registry
            .parse(
                r#"
name = "active"
[[script]]
name = "connect"
capabilities = ["target-tcp"]
wasm = "active.wat"
timeout_ms = 3000
"#,
                &dir,
            )
            .expect("parse active manifest");
        let script = &registry.scripts[0];
        let result = PortResult::new(
            "127.0.0.1".parse().expect("ip"),
            port,
            PortState::Open,
            Duration::from_millis(1),
        );
        let (findings, _) = run_script(script, &result, None)
            .await
            .expect("active wasm script runs");
        assert_eq!(findings[0].title, "connected");
        accept
            .join()
            .expect("accept thread")
            .expect("host completed the target connection");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn active_wasm_rejects_a_different_port() {
        let dir = std::env::temp_dir().join(format!(
            "portensor-script-active-port-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        write_wasm_script(
            &dir,
            "active.wat",
            &wasm_active_wat(
                9,
                r#"{"findings":[{"title":"connected","severity":"info"}]}"#,
                r#"{"findings":[{"title":"denied","severity":"info"}]}"#,
            ),
        );
        let mut registry = Registry::default();
        registry
            .parse(
                r#"
name = "active"
[[script]]
name = "connect"
capabilities = ["target-tcp"]
wasm = "active.wat"
"#,
                &dir,
            )
            .expect("parse active manifest");
        let result = PortResult::new(
            "127.0.0.1".parse().expect("ip"),
            80,
            PortState::Open,
            Duration::from_millis(1),
        );
        let (findings, _) = run_script(&registry.scripts[0], &result, None)
            .await
            .expect("active wasm script returns a finding");
        assert_eq!(findings[0].title, "denied");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn active_wasm_rechecks_scope_before_connecting() {
        let dir = std::env::temp_dir().join(format!(
            "portensor-script-active-scope-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        write_wasm_script(
            &dir,
            "active.wat",
            &wasm_active_wat(
                9,
                r#"{"findings":[{"title":"connected","severity":"info"}]}"#,
                r#"{"findings":[{"title":"denied","severity":"info"}]}"#,
            ),
        );
        let mut registry = Registry::default();
        registry
            .parse(
                r#"
name = "active"
[[script]]
name = "connect"
capabilities = ["target-tcp"]
wasm = "active.wat"
"#,
                &dir,
            )
            .expect("parse active manifest");
        let scope = crate::scope::ScopeGuard::from_config(crate::scope::ScopeConfig {
            program: Some("unit".to_string()),
            allow: vec!["10.0.0.0/8".to_string()],
            deny: vec![],
        })
        .expect("scope");
        let context = ScriptExecutionContext::new(Some(&scope), false);
        let result = PortResult::new(
            "127.0.0.1".parse().expect("ip"),
            9,
            PortState::Open,
            Duration::from_millis(1),
        );
        let (findings, _) = run_script(&registry.scripts[0], &result, Some(&context))
            .await
            .expect("active wasm script returns a finding");
        assert_eq!(findings[0].title, "denied");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn sdk_templates_execute() {
        let base = Path::new(env!("CARGO_MANIFEST_DIR")).join("sdk");
        let result = PortResult::new(
            "127.0.0.1".parse().expect("ip"),
            80,
            PortState::Open,
            Duration::from_millis(1),
        );
        for (directory, title) in [
            ("python-metadata", "Python metadata script executed"),
            ("wasm-metadata", "WASM metadata script executed"),
        ] {
            let dir = base.join(directory);
            let manifest =
                std::fs::read_to_string(dir.join("pack.toml")).expect("read SDK manifest");
            let mut registry = Registry::default();
            registry.parse(&manifest, &dir).expect("parse SDK manifest");
            if directory == "python-metadata"
                && !std::process::Command::new("python3")
                    .arg("--version")
                    .output()
                    .is_ok_and(|output| output.status.success())
            {
                continue;
            }
            let (findings, _) = run_script(&registry.scripts[0], &result, None)
                .await
                .expect("SDK template executes");
            assert_eq!(findings[0].title, title);
        }
    }

    #[tokio::test]
    async fn active_wasm_rate_limits_reconnects() {
        let listener =
            std::net::TcpListener::bind("127.0.0.1:0").expect("bind active-rate listener");
        let port = listener.local_addr().expect("listener address").port();
        let dir = std::env::temp_dir().join(format!(
            "portensor-script-active-rate-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        write_wasm_script(
            &dir,
            "active.wat",
            &wasm_active_rate_wat(
                port,
                r#"{"findings":[{"title":"all-allowed","severity":"info"}]}"#,
                r#"{"findings":[{"title":"rate-limited","severity":"info"}]}"#,
            ),
        );
        let mut registry = Registry::default();
        registry
            .parse(
                r#"
name = "active"
[[script]]
name = "rate"
capabilities = ["target-tcp"]
wasm = "active.wat"
"#,
                &dir,
            )
            .expect("parse active manifest");
        let result = PortResult::new(
            "127.0.0.1".parse().expect("ip"),
            port,
            PortState::Open,
            Duration::from_millis(1),
        );
        let (findings, _) = run_script(&registry.scripts[0], &result, None)
            .await
            .expect("active wasm script runs");
        assert_eq!(findings[0].title, "rate-limited");
        drop(listener);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn active_wasm_enforces_byte_limits() {
        let listener =
            std::net::TcpListener::bind("127.0.0.1:0").expect("bind active-byte listener");
        let port = listener.local_addr().expect("listener address").port();
        let dir = std::env::temp_dir().join(format!(
            "portensor-script-active-bytes-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        write_wasm_script(
            &dir,
            "active.wat",
            &wasm_active_bytes_wat(
                port,
                r#"{"findings":[{"title":"byte-limited","severity":"info"}]}"#,
                r#"{"findings":[{"title":"byte-limit-missing","severity":"info"}]}"#,
            ),
        );
        let mut registry = Registry::default();
        registry
            .parse(
                r#"
name = "active"
[[script]]
name = "bytes"
capabilities = ["target-tcp"]
wasm = "active.wat"
"#,
                &dir,
            )
            .expect("parse active manifest");
        let result = PortResult::new(
            "127.0.0.1".parse().expect("ip"),
            port,
            PortState::Open,
            Duration::from_millis(1),
        );
        let (findings, _) = run_script(&registry.scripts[0], &result, None)
            .await
            .expect("active wasm script runs");
        assert_eq!(findings[0].title, "byte-limited");
        drop(listener);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn wasm_rejects_oversized_output() {
        let dir =
            std::env::temp_dir().join(format!("portensor-script-wasm-big-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        // run() claims a 200 KB output at address 0 without writing anything.
        write_wasm_script(
            &dir,
            "big.wat",
            r#"(module
  (memory (export "memory") 1)
  (func (export "alloc") (param i32) (result i32) (i32.const 1024))
  (func (export "run") (param i32) (param i32) (result i64)
    (i64.or
      (i64.shl (i64.extend_i32_u (i32.const 0)) (i64.const 32))
      (i64.extend_i32_u (i32.const 200000))))
)"#,
        );
        let mut registry = Registry::default();
        registry
            .parse(
                r#"
name = "big"
[[script]]
name = "flood"
wasm = "big.wat"
"#,
                &dir,
            )
            .expect("parse manifest");
        let mut results = [PortResult::new(
            "127.0.0.1".parse().expect("ip"),
            80,
            PortState::Open,
            Duration::from_millis(1),
        )];
        let findings = registry.apply(&mut results, false, true).await;
        assert_eq!(findings, 0, "oversized output must be rejected");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn wasm_timeout_bounds_a_runaway_module() {
        let dir =
            std::env::temp_dir().join(format!("portensor-script-wasm-loop-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        write_wasm_script(
            &dir,
            "loop.wat",
            r#"(module
  (memory (export "memory") 1)
  (func (export "alloc") (param i32) (result i32) (i32.const 1024))
  (func (export "run") (param i32) (param i32) (result i64)
    (loop $forever (br $forever))
    (i64.const 0))
)"#,
        );
        let mut registry = Registry::default();
        registry
            .parse(
                r#"
name = "loop"
[[script]]
name = "spin"
wasm = "loop.wat"
timeout_ms = 100
"#,
                &dir,
            )
            .expect("parse manifest");
        let script = &registry.scripts[0];
        let result = PortResult::new(
            "127.0.0.1".parse().expect("ip"),
            80,
            PortState::Open,
            Duration::from_millis(1),
        );
        let outcome = run_script(script, &result, None).await;
        let error = outcome.expect_err("runaway module must fail");
        assert!(
            error.contains("timed out") || error.contains("exhausted its fuel budget"),
            "unexpected error: {error}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn library_dir_prefers_the_explicit_path() {
        let explicit = std::path::Path::new("/tmp/portensor-library-explicit");
        assert_eq!(
            library_dir(Some(explicit)).expect("explicit library"),
            explicit
        );
    }

    #[test]
    fn install_and_uninstall_round_trip() {
        let base =
            std::env::temp_dir().join(format!("portensor-script-library-{}", std::process::id()));
        let source = base.join("src").join("lab-pack");
        std::fs::create_dir_all(&source).expect("create source pack");
        std::fs::write(
            source.join("check.wat"),
            wasm_echo_wat(r#"{"findings":[{"title":"Library finding"}]}"#),
        )
        .expect("write module");
        std::fs::write(
            source.join("pack.toml"),
            "name = \"lab-pack\"\n[[script]]\nname = \"check\"\nwasm = \"check.wat\"\n",
        )
        .expect("write manifest");
        let library = base.join("library");

        let installed = install_pack(&source, &library, false).expect("install pack");
        assert_eq!(installed, library.join("lab-pack"));
        assert!(installed.join("pack.toml").is_file());
        assert!(installed.join("check.wat").is_file());
        let registry = Registry::load(&library).expect("library loads");
        assert_eq!(registry.script_count(), 1);
        assert_eq!(registry.pack_count(), 1);

        let duplicate = install_pack(&source, &library, false).expect_err("duplicate install");
        assert!(duplicate.to_string().contains("already installed"));
        install_pack(&source, &library, true).expect("forced reinstall");

        let removed = uninstall_pack("lab-pack", &library).expect("uninstall pack");
        assert_eq!(removed, library.join("lab-pack"));
        assert!(!installed.exists());
        let missing = uninstall_pack("lab-pack", &library).expect_err("second uninstall");
        assert!(missing.to_string().contains("not installed"));

        for name in ["..", ".", "a/b", "a\\b"] {
            assert!(
                uninstall_pack(name, &library).is_err(),
                "name '{name}' must be rejected"
            );
        }
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn install_rejects_broken_packs_before_copying() {
        let base = std::env::temp_dir().join(format!(
            "portensor-script-library-bad-{}",
            std::process::id()
        ));
        let source = base.join("src").join("broken-pack");
        std::fs::create_dir_all(&source).expect("create source pack");
        std::fs::write(source.join("pack.toml"), "name = \"broken\"\n").expect("write manifest");
        let library = base.join("library");
        let error = install_pack(&source, &library, false).expect_err("empty pack");
        assert!(error.to_string().contains("contains no [[script]]"));
        assert!(!library.join("broken-pack").exists());

        let file_source = base.join("src").join("single.toml");
        std::fs::write(&file_source, "name = \"single\"\n").expect("write file");
        let error = install_pack(&file_source, &library, false).expect_err("file source");
        assert!(error.to_string().contains("must be a directory"));
        let _ = std::fs::remove_dir_all(&base);
    }
}
