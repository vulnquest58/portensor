//! Declarative probe packs (v2).
//!
//! A pack is a TOML file that describes one or more probes.  Probes never
//! execute code: they send optional payloads and match responses.  The v2
//! schema adds multi-step sessions, binary expectations, product/info
//! extraction, CPE tagging, and a corroboration-aware confidence ladder while
//! remaining backward compatible with single-step v1 packs.
//!
//! ```toml
//! name = "example"
//!
//! [[probe]]
//! name = "redis-info"
//! service = "redis"
//! ports = [6379]
//! product = "Redis"
//! cpe = "cpe:2.3:a:redis:redis"
//!
//! [[probe.step]]
//! send = "INFO server\r\n"
//! expect = "redis_version:"
//! timeout_ms = 800
//!
//! [probe.info]
//! redis_mode = "redis_mode:([a-z]+)"
//! os = "os:([^\r\n]+)"
//! version_regex = "redis_version:([0-9.]+)"  # probe-level extraction
//! ```
//!
//! Steps run sequentially over one TCP connection.  A step may set `send`
//! (UTF-8) or `send_hex` (binary), and one of `expect` (literal text),
//! `expect_regex`, or `expect_hex` (binary substring).  Steps without an
//! expectation are pure stimuli.  `read_until` stops reading as soon as its
//! regex matches, which keeps HTTP-style probes fast.
//!
//! Extraction patterns are applied to the full transcript.  A probe-level
//! `version_regex` wins over per-step patterns; `product_regex` and the
//! `[probe.info]` table use capture group 1 when present.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use regex::Regex;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::pki_types::ServerName;

use crate::cli::ProbesListArgs;
use crate::discovery::socket_addr;
use crate::error::AppError;
use crate::model::{PortResult, PortState};
use crate::service::ServiceInfo;

const MAX_PACK_BYTES: u64 = 256 * 1024;
const MAX_PACKS: usize = 64;
const MAX_PROBES: usize = 512;
const MAX_PAYLOAD: usize = 8192;
const MAX_REGEX_CHARS: usize = 512;
const MAX_RESPONSE: usize = 16 * 1024;
const MAX_STEPS: usize = 8;
const MIN_TIMEOUT: Duration = Duration::from_millis(100);
const MAX_TIMEOUT: Duration = Duration::from_secs(10);

/// Compile-time probe packs that ship with the binary.
pub const BUILTIN_PACKS: &[(&str, &str)] = &[
    (
        "builtin:databases",
        include_str!("../data/probes/databases.toml"),
    ),
    (
        "builtin:containers",
        include_str!("../data/probes/containers.toml"),
    ),
    (
        "builtin:industrial",
        include_str!("../data/probes/industrial.toml"),
    ),
    (
        "builtin:remote",
        include_str!("../data/probes/remote-access.toml"),
    ),
    (
        "builtin:appliances",
        include_str!("../data/probes/appliances.toml"),
    ),
    (
        "builtin:messaging",
        include_str!("../data/probes/messaging.toml"),
    ),
];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Pack {
    name: String,
    #[serde(default)]
    #[allow(dead_code)]
    description: Option<String>,
    #[serde(default, rename = "probe")]
    probes: Vec<RawProbe>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawProbe {
    name: String,
    #[serde(default)]
    service: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    description: Option<String>,
    #[serde(default)]
    ports: Vec<u16>,
    #[serde(default)]
    product: Option<String>,
    #[serde(default)]
    version: Option<String>,
    #[serde(default)]
    cpe: Option<String>,
    #[serde(default)]
    product_regex: Option<String>,
    #[serde(default)]
    version_regex: Option<String>,
    #[serde(default)]
    send: Option<String>,
    #[serde(default)]
    send_hex: Option<String>,
    #[serde(default)]
    expect: Option<String>,
    #[serde(default)]
    expect_regex: Option<String>,
    #[serde(default)]
    expect_hex: Option<String>,
    #[serde(default)]
    ignore_case: bool,
    /// Run steps over a TLS session instead of plain TCP.
    #[serde(default)]
    tls: bool,
    #[serde(default)]
    timeout_ms: Option<u64>,
    #[serde(default)]
    confidence: Option<f32>,
    #[serde(default)]
    info: BTreeMap<String, String>,
    #[serde(default, rename = "step")]
    steps: Vec<RawStep>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawStep {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    send: Option<String>,
    #[serde(default)]
    send_hex: Option<String>,
    #[serde(default)]
    expect: Option<String>,
    #[serde(default)]
    expect_regex: Option<String>,
    #[serde(default)]
    expect_hex: Option<String>,
    #[serde(default)]
    version_regex: Option<String>,
    #[serde(default)]
    read_until: Option<String>,
    #[serde(default)]
    timeout_ms: Option<u64>,
}

#[derive(Debug)]
struct CompiledProbe {
    pack: String,
    name: String,
    service: String,
    ports: Vec<u16>,
    product: Option<String>,
    version: Option<String>,
    cpe: Option<String>,
    product_regex: Option<Regex>,
    version_regex: Option<Regex>,
    info: Vec<(String, Regex)>,
    base_confidence: Option<f32>,
    ignore_case: bool,
    tls: bool,
    steps: Vec<Step>,
    timeout: Option<Duration>,
}

#[derive(Debug, Default)]
struct Step {
    name: Option<String>,
    payload: Option<Vec<u8>>,
    expect: Option<String>,
    expect_regex: Option<Regex>,
    expect_hex: Option<Vec<u8>>,
    version_regex: Option<Regex>,
    read_until: Option<Regex>,
    timeout: Option<Duration>,
}

impl Step {
    fn has_expectation(&self) -> bool {
        self.expect.is_some() || self.expect_regex.is_some() || self.expect_hex.is_some()
    }

    fn matches(&self, response: &[u8], ignore_case: bool) -> bool {
        if let Some(expect) = &self.expect {
            let text = String::from_utf8_lossy(response);
            let matched = if ignore_case {
                text.to_lowercase().contains(&expect.to_lowercase())
            } else {
                text.contains(expect)
            };
            if !matched {
                return false;
            }
        }
        if let Some(regex) = &self.expect_regex
            && !regex.is_match(&String::from_utf8_lossy(response))
        {
            return false;
        }
        if let Some(expect) = &self.expect_hex
            && !response
                .windows(expect.len())
                .any(|window| window == expect.as_slice())
        {
            return false;
        }
        true
    }
}

/// One successful probe assessment ready to merge into a result.
#[derive(Debug)]
pub(crate) struct Assessment {
    pub(crate) service: String,
    pub(crate) product: Option<String>,
    pub(crate) version: Option<String>,
    pub(crate) cpe: Option<String>,
    pub(crate) info: BTreeMap<String, String>,
    pub(crate) confidence: f32,
    banner: String,
    notes: Vec<String>,
}

impl Assessment {
    pub(crate) fn new(
        service: String,
        product: Option<String>,
        version: Option<String>,
        cpe: Option<String>,
        info: BTreeMap<String, String>,
        confidence: f32,
    ) -> Self {
        Self {
            service,
            product,
            version,
            cpe,
            info,
            confidence,
            banner: String::new(),
            notes: Vec::new(),
        }
    }
}

/// Loaded and validated probe packs.
#[derive(Debug, Default)]
pub struct Registry {
    probes: Vec<CompiledProbe>,
    packs: usize,
}

impl Registry {
    /// Load a TOML file or every `*.toml` file in a directory.
    pub fn load(path: &Path) -> Result<Self, AppError> {
        let mut registry = Self::default();
        registry.add_path(path)?;
        Ok(registry)
    }

    /// Append a TOML file or every `*.toml` file in a directory.
    pub fn add_path(&mut self, path: &Path) -> Result<(), AppError> {
        let metadata = std::fs::metadata(path).map_err(|error| {
            AppError::usage(format!(
                "cannot read plugins path {}: {error}",
                path.display()
            ))
        })?;

        let mut files = Vec::new();
        if metadata.is_dir() {
            for entry in std::fs::read_dir(path).map_err(|error| {
                AppError::usage(format!(
                    "cannot read plugins directory {}: {error}",
                    path.display()
                ))
            })? {
                let entry = entry.map_err(|error| {
                    AppError::usage(format!(
                        "cannot read plugins directory {}: {error}",
                        path.display()
                    ))
                })?;
                let file_path = entry.path();
                if file_path
                    .extension()
                    .is_some_and(|extension| extension.eq_ignore_ascii_case("toml"))
                {
                    files.push(file_path);
                }
            }
            files.sort();
            if files.is_empty() {
                return Err(AppError::usage(format!(
                    "no .toml probe packs found in {}",
                    path.display()
                )));
            }
        } else {
            files.push(path.to_path_buf());
        }

        if self.packs + files.len() > MAX_PACKS {
            return Err(AppError::usage(format!(
                "too many probe packs (maximum {MAX_PACKS})"
            )));
        }

        for file in files {
            self.load_file(&file)?;
        }
        Ok(())
    }

    /// Parse and append the probe packs embedded in the binary.
    pub fn merge_builtin(&mut self) -> Result<(), AppError> {
        for (source, text) in BUILTIN_PACKS {
            self.parse(text)
                .map_err(|error| AppError::usage(format!("{source}: {error}")))?;
        }
        Ok(())
    }

    fn load_file(&mut self, path: &Path) -> Result<(), AppError> {
        let size = std::fs::metadata(path)
            .map_err(|error| AppError::usage(format!("cannot stat {}: {error}", path.display())))?
            .len();
        if size > MAX_PACK_BYTES {
            return Err(AppError::usage(format!(
                "{} exceeds the {MAX_PACK_BYTES}-byte probe pack limit",
                path.display()
            )));
        }
        let text = std::fs::read_to_string(path)
            .map_err(|error| AppError::usage(format!("cannot read {}: {error}", path.display())))?;
        self.parse(&text)
            .map_err(|error| AppError::usage(format!("{}: {error}", path.display())))
    }

    fn parse(&mut self, text: &str) -> Result<(), AppError> {
        let pack: Pack = toml::from_str(text)
            .map_err(|error| AppError::usage(format!("invalid probe pack: {error}")))?;
        validate_name("pack", &pack.name)?;
        if pack.probes.is_empty() {
            return Err(AppError::usage(format!(
                "probe pack '{}' contains no [[probe]] entries",
                pack.name
            )));
        }
        if self.probes.len() + pack.probes.len() > MAX_PROBES {
            return Err(AppError::usage(format!(
                "too many probe entries (maximum {MAX_PROBES})"
            )));
        }

        for raw in pack.probes {
            let probe = compile_probe(&pack.name, raw)?;
            self.probes.push(probe);
        }
        self.packs += 1;
        Ok(())
    }

    pub fn is_empty(&self) -> bool {
        self.probes.is_empty()
    }

    pub fn pack_count(&self) -> usize {
        self.packs
    }

    pub fn probe_count(&self) -> usize {
        self.probes.len()
    }

    /// Probe summaries for `rayscan probes list`.
    pub fn summaries(&self) -> Vec<ProbeSummary> {
        self.probes
            .iter()
            .map(|probe| ProbeSummary {
                pack: probe.pack.clone(),
                name: probe.name.clone(),
                service: probe.service.clone(),
                ports: probe.ports.clone(),
                steps: probe.steps.len(),
                tls: probe.tls,
            })
            .collect()
    }

    /// Run matching probes against every open TCP result.
    ///
    /// Returns the number of results whose service was identified or refined.
    pub async fn apply(
        &self,
        results: &mut [PortResult],
        default_timeout: Duration,
        quiet: bool,
    ) -> usize {
        if self.is_empty() {
            return 0;
        }

        let mut matched = 0;
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
            let tls_detected = result.tls.is_some();

            for probe in &self.probes {
                if !probe.ports.is_empty() && !probe.ports.contains(&result.port) {
                    continue;
                }
                if tls_detected
                    && !probe.tls
                    && probe.steps.iter().any(|step| step.payload.is_some())
                {
                    continue;
                }
                let Some(assessment) = probe
                    .run(
                        result.host,
                        result.port,
                        result.banner.as_deref(),
                        default_timeout,
                    )
                    .await
                else {
                    continue;
                };
                let tag = format!("plugin:{}/{}", probe.pack, probe.name);
                let note = if assessment.notes.is_empty() {
                    String::new()
                } else {
                    format!(
                        " ({} step(s): {})",
                        assessment.notes.len(),
                        assessment.notes.join(", ")
                    )
                };
                let evidence_label = format!("probe match {tag}{note}");
                merge_assessment(result, &tag, &evidence_label, assessment);
                matched += 1;
                break;
            }
        }

        if matched > 0 && !quiet {
            eprintln!(
                "[probes] {} result(s) matched from {} probe(s) in {} pack(s)",
                matched,
                self.probe_count(),
                self.pack_count()
            );
        }
        matched
    }
}

/// `rayscan probes list`: print the compiled probe library.
pub fn run_cli(args: ProbesListArgs) -> Result<(), AppError> {
    let mut registry = Registry::default();
    registry.merge_builtin()?;
    if let Some(path) = &args.plugins {
        registry.add_path(path)?;
    }

    let summaries = registry.summaries();
    if args.json {
        let json = serde_json::to_string_pretty(&summaries)
            .map_err(|error| AppError::runtime(format!("cannot encode probe JSON: {error}")))?;
        println!("{json}");
        return Ok(());
    }

    println!(
        "{} pack(s), {} probe(s):",
        registry.pack_count(),
        registry.probe_count()
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
        let ports = if summary.tls {
            format!("{ports} tls")
        } else {
            ports
        };
        println!(
            "  {:<28} {:<22} {:<16} {} step(s)",
            summary.name, summary.service, ports, summary.steps
        );
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize)]
pub struct ProbeSummary {
    pub pack: String,
    pub name: String,
    pub service: String,
    pub ports: Vec<u16>,
    pub steps: usize,
    /// True when the probe runs its steps over a TLS session.
    pub tls: bool,
}

impl CompiledProbe {
    async fn run(
        &self,
        host: std::net::IpAddr,
        port: u16,
        existing_banner: Option<&str>,
        default_timeout: Duration,
    ) -> Option<Assessment> {
        let active = self.steps.iter().any(|step| step.payload.is_some());
        let transcript = if active {
            if self.tls {
                self.run_active_tls(host, port, default_timeout).await?
            } else {
                self.run_active(host, port, default_timeout).await?
            }
        } else {
            let banner = existing_banner
                .map(str::trim)
                .filter(|banner| !banner.is_empty())?;
            let response = banner.as_bytes();
            for step in &self.steps {
                if !step.matches(response, self.ignore_case) {
                    return None;
                }
            }
            banner.to_string()
        };

        if transcript.trim().is_empty() && self.steps.iter().any(Step::has_expectation) {
            return None;
        }

        let text = transcript.as_str();
        let version = self
            .version_regex
            .as_ref()
            .and_then(|regex| extract(regex, text))
            .or_else(|| {
                self.steps
                    .iter()
                    .filter_map(|step| step.version_regex.as_ref())
                    .find_map(|regex| extract(regex, text))
            })
            .or_else(|| self.version.clone());
        let product = self
            .product_regex
            .as_ref()
            .and_then(|regex| extract(regex, text))
            .or_else(|| self.product.clone());

        let mut info = BTreeMap::new();
        for (key, regex) in &self.info {
            if let Some(value) = extract(regex, text) {
                info.insert(key.clone(), value);
            }
        }

        let mut confidence = self.base_confidence.unwrap_or(match (&product, &version) {
            (_, Some(_)) => 0.98,
            (Some(_), None) => 0.85,
            (None, None) => 0.70,
        });
        let corroborating = self
            .steps
            .iter()
            .filter(|step| step.has_expectation())
            .count();
        if corroborating > 1 {
            confidence = (confidence + 0.01 * (corroborating - 1) as f32).min(0.99);
        }

        let mut notes = Vec::new();
        for step in &self.steps {
            if let Some(name) = &step.name
                && step.has_expectation()
            {
                notes.push(name.clone());
            }
        }

        Some(Assessment {
            service: self.service.clone(),
            product,
            version,
            cpe: self.cpe.clone(),
            info,
            confidence,
            banner: first_line(&transcript),
            notes,
        })
    }

    async fn run_active(
        &self,
        host: std::net::IpAddr,
        port: u16,
        default_timeout: Duration,
    ) -> Option<String> {
        let timeout = self
            .timeout
            .unwrap_or(default_timeout)
            .clamp(MIN_TIMEOUT, MAX_TIMEOUT);
        let connect = tokio::time::timeout(timeout, TcpStream::connect(socket_addr(host, port)))
            .await
            .ok()?
            .ok()?;
        let _ = connect.set_nodelay(true);
        let mut stream = connect;
        self.execute_steps(&mut stream, timeout).await
    }

    async fn run_active_tls(
        &self,
        host: std::net::IpAddr,
        port: u16,
        default_timeout: Duration,
    ) -> Option<String> {
        let timeout = self
            .timeout
            .unwrap_or(default_timeout)
            .clamp(MIN_TIMEOUT, MAX_TIMEOUT);
        let connect = tokio::time::timeout(timeout, TcpStream::connect(socket_addr(host, port)))
            .await
            .ok()?
            .ok()?;
        let _ = connect.set_nodelay(true);

        let connector = TlsConnector::from(Arc::new(crate::tls::probe_client_config()));
        let server_name = ServerName::IpAddress(host.into());
        let mut stream = tokio::time::timeout(timeout, connector.connect(server_name, connect))
            .await
            .ok()?
            .ok()?;
        self.execute_steps(&mut stream, timeout).await
    }

    async fn execute_steps<S>(&self, stream: &mut S, timeout: Duration) -> Option<String>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let mut transcript = String::new();
        for step in &self.steps {
            let step_timeout = step
                .timeout
                .unwrap_or(timeout)
                .clamp(MIN_TIMEOUT, MAX_TIMEOUT);
            if let Some(payload) = &step.payload
                && tokio::time::timeout(step_timeout, stream.write_all(payload))
                    .await
                    .ok()?
                    .is_err()
            {
                return None;
            }

            let response = read_response(stream, step, step_timeout).await?;
            if !step.matches(&response, self.ignore_case) {
                return None;
            }
            if !response.is_empty() {
                transcript.push_str(&String::from_utf8_lossy(&response));
                transcript.push('\n');
            }
        }
        Some(transcript)
    }
}

async fn read_response<S>(stream: &mut S, step: &Step, timeout: Duration) -> Option<Vec<u8>>
where
    S: AsyncRead + Unpin,
{
    let deadline = Instant::now() + timeout;
    let idle = Duration::from_millis(250).min(timeout);
    let mut response = Vec::new();
    let mut buffer = [0_u8; 4096];
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() || response.len() >= MAX_RESPONSE {
            break;
        }
        match tokio::time::timeout(idle.min(remaining), stream.read(&mut buffer)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(read)) => {
                let take = read.min(MAX_RESPONSE - response.len());
                response.extend_from_slice(&buffer[..take]);
                if let Some(until) = &step.read_until
                    && until.is_match(&String::from_utf8_lossy(&response))
                {
                    break;
                }
            }
            Ok(Err(_)) | Err(_) => break,
        }
    }
    Some(response)
}

pub(crate) fn merge_assessment(
    result: &mut PortResult,
    tag: &str,
    evidence_label: &str,
    assessment: Assessment,
) {
    let previous = result.service.take();
    let same_service = previous
        .as_ref()
        .is_some_and(|service| service.name == assessment.service);
    let product = assessment.product.or_else(|| {
        if same_service {
            previous
                .as_ref()
                .and_then(|service| service.product.clone())
        } else {
            None
        }
    });
    let version = assessment.version.or_else(|| {
        if same_service {
            previous
                .as_ref()
                .and_then(|service| service.version.clone())
        } else {
            None
        }
    });
    let previous_confidence = if same_service {
        previous
            .as_ref()
            .and_then(|service| service.confidence)
            .unwrap_or(0.0)
    } else {
        0.0
    };
    let mut info = previous
        .as_ref()
        .map(|service| service.info.clone())
        .unwrap_or_default();
    info.extend(assessment.info);

    result.service = Some(ServiceInfo {
        name: assessment.service,
        product,
        version,
        confidence: Some(assessment.confidence.max(previous_confidence)),
        cpe: assessment.cpe.or_else(|| {
            if same_service {
                previous.as_ref().and_then(|service| service.cpe.clone())
            } else {
                None
            }
        }),
        info,
    });
    if !assessment.banner.is_empty() {
        result.banner = Some(assessment.banner);
    }
    result.detail = Some(match result.detail.take() {
        Some(detail) if !detail.is_empty() && detail.split(',').any(|existing| existing == tag) => {
            detail
        }
        Some(detail) if !detail.is_empty() => format!("{detail},{tag}"),
        _ => tag.to_string(),
    });
    result.evidence = Some(match result.evidence.take() {
        Some(evidence) if !evidence.is_empty() && evidence.contains(evidence_label) => evidence,
        Some(evidence) if !evidence.is_empty() => {
            format!("{evidence} | {evidence_label}")
        }
        _ => evidence_label.to_string(),
    });
}

fn extract(regex: &Regex, text: &str) -> Option<String> {
    let captures = regex.captures(text)?;
    let value = captures
        .get(1)
        .or_else(|| captures.get(0))
        .map(|value| value.as_str().trim().to_string())?;
    if value.is_empty() {
        None
    } else {
        Some(value.chars().take(200).collect())
    }
}

fn compile_probe(pack: &str, raw: RawProbe) -> Result<CompiledProbe, AppError> {
    validate_name("probe", &raw.name)?;
    if raw.send.is_some() && raw.send_hex.is_some() {
        return Err(AppError::usage(format!(
            "probe '{pack}/{name}' cannot set both send and send_hex",
            name = raw.name
        )));
    }
    if !raw.steps.is_empty()
        && (raw.send.is_some()
            || raw.send_hex.is_some()
            || raw.expect.is_some()
            || raw.expect_regex.is_some()
            || raw.expect_hex.is_some())
    {
        return Err(AppError::usage(format!(
            "probe '{pack}/{name}' mixes single-step fields with [[probe.step]] entries",
            name = raw.name
        )));
    }
    if raw.steps.len() > MAX_STEPS {
        return Err(AppError::usage(format!(
            "probe '{pack}/{name}' exceeds {MAX_STEPS} steps",
            name = raw.name
        )));
    }

    let steps = if raw.steps.is_empty() {
        vec![compile_step(
            pack,
            &raw.name,
            None,
            RawStep {
                send: raw.send.clone(),
                send_hex: raw.send_hex.clone(),
                expect: raw.expect.clone(),
                expect_regex: raw.expect_regex.clone(),
                expect_hex: raw.expect_hex.clone(),
                timeout_ms: raw.timeout_ms,
                ..RawStep::default()
            },
            raw.ignore_case,
        )?]
    } else {
        raw.steps
            .into_iter()
            .enumerate()
            .map(|(index, step)| {
                compile_step(pack, &raw.name, Some(index + 1), step, raw.ignore_case)
            })
            .collect::<Result<Vec<_>, _>>()?
    };

    let product_regex = match raw.product_regex {
        Some(pattern) => Some(compile_regex(&pattern, raw.ignore_case, pack, &raw.name)?),
        None => None,
    };
    let version_regex = match raw.version_regex {
        Some(pattern) => Some(compile_regex(&pattern, raw.ignore_case, pack, &raw.name)?),
        None => None,
    };
    let mut info = Vec::new();
    for (key, pattern) in &raw.info {
        validate_info_key(key)?;
        info.push((
            key.clone(),
            compile_regex(pattern, raw.ignore_case, pack, &raw.name)?,
        ));
    }

    let service = raw
        .service
        .filter(|service| !service.trim().is_empty())
        .unwrap_or_else(|| raw.name.clone());
    validate_name("service", &service)?;

    let mut ports = raw.ports;
    ports.sort_unstable();
    ports.dedup();

    Ok(CompiledProbe {
        pack: pack.to_string(),
        name: raw.name,
        service,
        ports,
        product: raw.product,
        version: raw.version,
        cpe: raw.cpe,
        product_regex,
        version_regex,
        info,
        base_confidence: raw.confidence.map(|value| value.clamp(0.0, 1.0)),
        ignore_case: raw.ignore_case,
        tls: raw.tls,
        steps,
        timeout: raw.timeout_ms.map(Duration::from_millis),
    })
}

fn compile_step(
    pack: &str,
    probe: &str,
    index: Option<usize>,
    raw: RawStep,
    ignore_case: bool,
) -> Result<Step, AppError> {
    if raw.send.is_some() && raw.send_hex.is_some() {
        return Err(AppError::usage(format!(
            "probe '{pack}/{probe}' step cannot set both send and send_hex"
        )));
    }
    let payload = match (&raw.send, &raw.send_hex) {
        (Some(text), None) => Some(text.as_bytes().to_vec()),
        (None, Some(hex)) => Some(decode_hex(hex).map_err(|error| {
            AppError::usage(format!("probe '{pack}/{probe}' send_hex: {error}"))
        })?),
        (None, None) => None,
        (Some(_), Some(_)) => unreachable!("checked above"),
    };
    if let Some(payload) = &payload
        && (payload.is_empty() || payload.len() > MAX_PAYLOAD)
    {
        return Err(AppError::usage(format!(
            "probe '{pack}/{probe}' payload must be between 1 and {MAX_PAYLOAD} bytes"
        )));
    }

    let expect_hex = match &raw.expect_hex {
        Some(hex) => Some(decode_hex(hex).map_err(|error| {
            AppError::usage(format!("probe '{pack}/{probe}' expect_hex: {error}"))
        })?),
        None => None,
    };
    if let Some(hex) = &expect_hex
        && hex.is_empty()
    {
        return Err(AppError::usage(format!(
            "probe '{pack}/{probe}' expect_hex cannot be empty"
        )));
    }

    let expect_regex = match raw.expect_regex {
        Some(pattern) => Some(compile_regex(&pattern, ignore_case, pack, probe)?),
        None => None,
    };
    let version_regex = match raw.version_regex {
        Some(pattern) => Some(compile_regex(&pattern, ignore_case, pack, probe)?),
        None => None,
    };
    let read_until = match raw.read_until {
        Some(pattern) => Some(compile_regex(&pattern, ignore_case, pack, probe)?),
        None => None,
    };

    Ok(Step {
        name: raw
            .name
            .or_else(|| index.map(|index| format!("step {index}"))),
        payload,
        expect: raw.expect,
        expect_regex,
        expect_hex,
        version_regex,
        read_until,
        timeout: raw.timeout_ms.map(Duration::from_millis),
    })
}

fn validate_name(kind: &str, name: &str) -> Result<(), AppError> {
    let name = name.trim();
    if name.is_empty() {
        return Err(AppError::usage(format!("{kind} name cannot be empty")));
    }
    if name.chars().count() > 128 {
        let preview: String = name.chars().take(128).collect();
        return Err(AppError::usage(format!(
            "{kind} name '{preview}' exceeds 128 characters"
        )));
    }
    if !name
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || " ._-:/()".contains(character))
    {
        return Err(AppError::usage(format!(
            "{kind} name '{name}' contains unsupported characters"
        )));
    }
    Ok(())
}

fn validate_info_key(key: &str) -> Result<(), AppError> {
    if key.is_empty()
        || key.chars().count() > 48
        || !key.chars().all(|character| {
            character.is_ascii_lowercase() || character.is_ascii_digit() || character == '_'
        })
    {
        return Err(AppError::usage(format!(
            "info key '{key}' must be 1-48 characters of lowercase [a-z0-9_]"
        )));
    }
    Ok(())
}

fn compile_regex(
    pattern: &str,
    ignore_case: bool,
    pack: &str,
    probe: &str,
) -> Result<Regex, AppError> {
    if pattern.chars().count() > MAX_REGEX_CHARS {
        return Err(AppError::usage(format!(
            "probe '{pack}/{probe}' regex exceeds {MAX_REGEX_CHARS} characters"
        )));
    }
    let pattern = if ignore_case {
        format!("(?i:{pattern})")
    } else {
        pattern.to_string()
    };
    Regex::new(&pattern).map_err(|error| {
        AppError::usage(format!(
            "probe '{pack}/{probe}' has an invalid regex: {error}"
        ))
    })
}

fn decode_hex(input: &str) -> Result<Vec<u8>, String> {
    let cleaned: String = input
        .chars()
        .filter(|character| {
            !character.is_ascii_whitespace() && *character != ':' && *character != '-'
        })
        .collect();
    if !cleaned.len().is_multiple_of(2) {
        return Err("hex payload has an odd number of digits".to_string());
    }
    let mut bytes = Vec::with_capacity(cleaned.len() / 2);
    let chars: Vec<char> = cleaned.chars().collect();
    for pair in chars.chunks(2) {
        let pair: String = pair.iter().collect();
        let byte =
            u8::from_str_radix(&pair, 16).map_err(|_| format!("invalid hex byte '{pair}'"))?;
        bytes.push(byte);
    }
    Ok(bytes)
}

fn first_line(text: &str) -> String {
    let line = text
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .unwrap_or_default();
    let sanitized: String = line
        .chars()
        .map(|character| {
            if character.is_ascii_control() {
                ' '
            } else {
                character
            }
        })
        .collect();
    sanitized.chars().take(160).collect()
}

/// Parse a pack directly (used by tests and tooling).
pub fn parse_pack(text: &str) -> Result<Registry, AppError> {
    let mut registry = Registry::default();
    registry.parse(text)?;
    Ok(registry)
}

/// Return the default plugin directory (`<config dir>/rayscan/plugins`) when present.
pub fn default_dir() -> Option<PathBuf> {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("APPDATA").map(PathBuf::from))
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))?;
    let path = base.join("rayscan").join("plugins");
    path.is_dir().then_some(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    fn result(port: u16, banner: Option<&str>) -> PortResult {
        let mut result = PortResult::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            port,
            PortState::Open,
            Duration::ZERO,
        );
        result.banner = banner.map(str::to_string);
        result
    }

    fn tls_info() -> crate::tls::TlsInfo {
        crate::tls::TlsInfo {
            version: "TLSv1.3".to_string(),
            cipher: "TLS13_AES_256_GCM_SHA384".to_string(),
            alpn: Some("http/1.1".to_string()),
            key_algorithm: Some("RSA".to_string()),
            signature_algorithm: Some("sha256WithRSA".to_string()),
            chain: Vec::new(),
            subject: None,
            issuer: None,
            san: Vec::new(),
            serial: None,
            not_before: None,
            not_after: None,
            days_remaining: None,
            expired: false,
            not_yet_valid: false,
            self_signed: false,
            hostname_matches: false,
            chain_len: 0,
            starttls: None,
        }
    }

    #[test]
    fn compiles_literal_and_regex_probes() {
        let registry = parse_pack(
            r#"
name = "example"

[[probe]]
name = "acme"
service = "acme-admin"
ports = [8000, 8080]
expect = "Acme"
version_regex = "Version: ([0-9.]+)"
"#,
        )
        .unwrap();
        assert_eq!(registry.pack_count(), 1);
        assert_eq!(registry.probe_count(), 1);
    }

    #[test]
    fn rejects_invalid_payloads_and_regexes() {
        assert!(
            parse_pack(
                r#"
name = "bad"
[[probe]]
name = "x"
send = "a"
send_hex = "61"
"#
            )
            .is_err()
        );
        assert!(
            parse_pack(
                r#"
name = "bad"
[[probe]]
name = "x"
send_hex = "zz"
"#
            )
            .is_err()
        );
        assert!(
            parse_pack(
                r#"
name = "bad"
[[probe]]
name = "x"
expect_regex = "("
"#
            )
            .is_err()
        );
        assert!(
            parse_pack(
                r#"
name = "bad"
[[probe]]
name = "x"
send = ""
"#
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_mixed_single_and_multi_step_packs() {
        let error = parse_pack(
            r#"
name = "bad"
[[probe]]
name = "x"
send = "hello"
[[probe.step]]
send = "world"
"#,
        )
        .unwrap_err();
        assert!(error.to_string().contains("mixes"));
    }

    #[test]
    fn rejects_unknown_fields_and_bad_info_keys() {
        assert!(
            parse_pack(
                r#"
name = "bad"
[[probe]]
name = "x"
unexpected = true
"#
            )
            .is_err()
        );
        assert!(
            parse_pack(
                r#"
name = "bad"
[[probe]]
name = "x"
[probe.info]
"Bad-Key" = "([0-9]+)"
"#
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn applies_passive_probe_to_matching_open_result() {
        let registry = parse_pack(
            r#"
name = "example"
[[probe]]
name = "acme"
service = "acme-admin"
ports = [8000]
expect = "Acme"
product = "Acme Appliance"
version_regex = "Version: ([0-9.]+)"
"#,
        )
        .unwrap();
        let mut results = vec![
            result(8000, Some("Acme Version: 9.1")),
            result(8001, Some("Acme Version: 9.1")),
        ];
        let matched = registry
            .apply(&mut results, Duration::from_millis(100), true)
            .await;
        assert_eq!(matched, 1);
        let service = results[0].service.as_ref().unwrap();
        assert_eq!(service.name, "acme-admin");
        assert_eq!(service.product.as_deref(), Some("Acme Appliance"));
        assert_eq!(service.version.as_deref(), Some("9.1"));
        assert!(results[0].detail.as_deref().unwrap().contains("plugin"));
        assert!(results[1].service.is_none());
    }

    #[tokio::test]
    async fn sends_active_probe_and_reads_response() {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0_u8; 64];
            let read = stream.read(&mut request).await.unwrap();
            assert_eq!(&request[..read], b"hello");
            stream
                .write_all(b"HELLO/1.0\r\nProduct: Acme\r\n")
                .await
                .unwrap();
        });

        let registry = parse_pack(
            r#"
name = "active"
[[probe]]
name = "hello"
service = "hello"
send = "hello"
expect = "HELLO/1.0"
"#,
        )
        .unwrap();
        let mut results = vec![result(port, None)];
        let matched = registry
            .apply(&mut results, Duration::from_secs(2), true)
            .await;
        assert_eq!(matched, 1);
        assert_eq!(results[0].service.as_ref().unwrap().name, "hello");
        assert!(
            results[0]
                .banner
                .as_deref()
                .unwrap()
                .starts_with("HELLO/1.0")
        );
    }

    #[tokio::test]
    async fn multi_step_session_extracts_info_and_boosts_confidence() {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buffer = [0_u8; 128];
            let read = stream.read(&mut buffer).await.unwrap();
            assert_eq!(&buffer[..read], b"PING\r\n");
            stream.write_all(b"+PONG\r\n").await.unwrap();
            let read = stream.read(&mut buffer).await.unwrap();
            assert_eq!(&buffer[..read], b"INFO server\r\n");
            stream
                .write_all(b"redis_version:7.2.4\r\nredis_mode:standalone\r\nos:Linux 6.8\r\n")
                .await
                .unwrap();
        });

        let registry = parse_pack(
            r#"
name = "deep"
[[probe]]
name = "redis"
service = "redis"
ports = []
product = "Redis"
cpe = "cpe:2.3:a:redis:redis"
version_regex = "redis_version:([0-9.]+)"
[[probe.step]]
name = "ping"
send = "PING\r\n"
expect = "PONG"
[[probe.step]]
name = "info"
send = "INFO server\r\n"
expect = "redis_version:"
[probe.info]
mode = "redis_mode:([a-z]+)"
os = "os:([^\r\n]+)"
"#,
        )
        .unwrap();
        let mut results = vec![result(port, None)];
        let matched = registry
            .apply(&mut results, Duration::from_secs(2), true)
            .await;
        assert_eq!(matched, 1);
        let service = results[0].service.as_ref().unwrap();
        assert_eq!(service.name, "redis");
        assert_eq!(service.version.as_deref(), Some("7.2.4"));
        assert_eq!(
            service.info.get("mode").map(String::as_str),
            Some("standalone")
        );
        assert_eq!(
            service.info.get("os").map(String::as_str),
            Some("Linux 6.8")
        );
        assert_eq!(service.cpe.as_deref(), Some("cpe:2.3:a:redis:redis"));
        assert!(service.confidence.unwrap() > 0.98);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn failed_step_aborts_the_probe() {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buffer = [0_u8; 64];
            let _ = stream.read(&mut buffer).await.unwrap();
            stream.write_all(b"-DENIED\r\n").await.unwrap();
        });

        let registry = parse_pack(
            r#"
name = "deep"
[[probe]]
name = "redis"
service = "redis"
send = "PING\r\n"
expect = "PONG"
"#,
        )
        .unwrap();
        let mut results = vec![result(port, None)];
        let matched = registry
            .apply(&mut results, Duration::from_millis(500), true)
            .await;
        assert_eq!(matched, 0);
        assert!(results[0].service.is_none());
    }

    #[tokio::test]
    async fn binary_expectations_match_raw_bytes() {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buffer = [0_u8; 64];
            let _ = stream.read(&mut buffer).await.unwrap();
            stream
                .write_all(b"\x05\x64\x05\xc9\x01\x00\x00\x00")
                .await
                .unwrap();
        });

        let registry = parse_pack(
            r#"
name = "industrial"
[[probe]]
name = "dnp3"
service = "dnp3"
send_hex = "056405c90100000000"
expect_hex = "0564 05"
product = "DNP3"
"#,
        )
        .unwrap();
        let mut results = vec![result(port, None)];
        let matched = registry
            .apply(&mut results, Duration::from_secs(2), true)
            .await;
        assert_eq!(matched, 1);
        assert_eq!(
            results[0].service.as_ref().unwrap().product.as_deref(),
            Some("DNP3")
        );
    }

    #[tokio::test]
    async fn mysql_greeting_passive_probe_identifies_forks() {
        let registry = Registry::default();
        let mut registry = registry;
        registry.merge_builtin().unwrap();
        let mysql_banner =
            "\u{33}\u{0}\u{0}\u{0}\u{A}8.0.41\u{0}\u{2}\u{0}\u{0}\u{0}\u{0}caching_sha2_password";
        let maria_banner = "\u{4B}\u{0}\u{0}\u{0}\u{A}10.11.6-MariaDB\u{0}\u{2}\u{0}";
        let mut results = vec![
            result(3306, Some(mysql_banner)),
            result(3307, Some(maria_banner)),
            result(3308, Some("PLAIN HTTP/1.1 200 OK\n1234")),
        ];
        let matched = registry
            .apply(&mut results, Duration::from_millis(100), true)
            .await;
        assert_eq!(matched, 2, "plain HTTP banner must not match mysql");
        let mysql = results[0].service.as_ref().unwrap();
        assert_eq!(mysql.name, "mysql");
        assert_eq!(mysql.product.as_deref(), Some("MySQL"));
        assert_eq!(mysql.version.as_deref(), Some("8.0.41"));
        let maria = results[1].service.as_ref().unwrap();
        assert_eq!(maria.product.as_deref(), Some("MariaDB"));
        assert_eq!(maria.version.as_deref(), Some("10.11.6-MariaDB"));
    }

    #[tokio::test]
    async fn mongodb_op_query_matches_bson_hello_reply() {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buffer = [0_u8; 128];
            stream.read_exact(&mut buffer[..54]).await.unwrap();
            assert_eq!(&buffer[20..30], b"admin.$cmd");
            let reply: &[u8] = &[
                // OP_REPLY header: length 84, responseTo 1, opcode 1
                0x54, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00,
                0x00, 0x00, // responseFlags, cursorId, startingFrom, numberReturned
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
                0x00, 0x00, // BSON doc {ismaster:true, maxWireVersion:21, ok:1.0}
                0x30, 0x00, 0x00, 0x00, 0x08, 0x69, 0x73, 0x6D, 0x61, 0x73, 0x74, 0x65, 0x72, 0x00,
                0x01, 0x10, 0x6D, 0x61, 0x78, 0x57, 0x69, 0x72, 0x65, 0x56, 0x65, 0x72, 0x73, 0x69,
                0x6F, 0x6E, 0x00, 0x15, 0x00, 0x00, 0x00, 0x01, 0x6F, 0x6B, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0xF0, 0x3F, 0x00,
            ];
            stream.write_all(reply).await.unwrap();
        });

        let registry = parse_pack(
            r#"
name = "mongo"
[[probe]]
name = "hello"
service = "mongodb"
ports = []
product = "MongoDB"
cpe = "cpe:2.3:a:mongodb:mongodb"
confidence = 0.90
[[probe.step]]
send_hex = "36 00 00 00 00 00 00 00 00 00 00 00 D4 07 00 00 00 00 00 00 61 64 6D 69 6E 2E 24 63 6D 64 00 01 00 00 00 13 00 00 00 10 69 73 4D 61 73 74 65 72 00 01 00 00 00 00"
expect_regex = "maxWireVersion|ismaster"
"#,
        )
        .unwrap();
        let mut results = vec![result(port, None)];
        let matched = registry
            .apply(&mut results, Duration::from_secs(2), true)
            .await;
        assert_eq!(matched, 1);
        let service = results[0].service.as_ref().unwrap();
        assert_eq!(service.name, "mongodb");
        assert_eq!(service.product.as_deref(), Some("MongoDB"));
        assert_eq!(service.cpe.as_deref(), Some("cpe:2.3:a:mongodb:mongodb"));
    }

    #[tokio::test]
    async fn mqtt_connect_receives_connack() {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buffer = [0_u8; 64];
            stream.read_exact(&mut buffer[..21]).await.unwrap();
            assert_eq!(&buffer[..8], b"\x10\x13\x00\x04MQTT");
            stream.write_all(b"\x20\x02\x00\x00").await.unwrap();
        });

        let registry = parse_pack(
            r#"
name = "mqtt"
[[probe]]
name = "connect"
service = "mqtt"
ports = []
product = "MQTT Broker"
confidence = 0.92
[[probe.step]]
send_hex = "10 13 00 04 4D 51 54 54 04 02 00 3C 00 07 72 61 79 73 63 61 6E"
expect_hex = "20 02"
"#,
        )
        .unwrap();
        let mut results = vec![result(port, None)];
        let matched = registry
            .apply(&mut results, Duration::from_secs(2), true)
            .await;
        assert_eq!(matched, 1);
        let service = results[0].service.as_ref().unwrap();
        assert_eq!(service.name, "mqtt");
        assert_eq!(service.product.as_deref(), Some("MQTT Broker"));
    }

    #[tokio::test]
    async fn kafka_apiversions_response_matches() {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buffer = [0_u8; 64];
            stream.read_exact(&mut buffer[..14]).await.unwrap();
            assert_eq!(&buffer[4..6], b"\x00\x12");
            let response: &[u8] = &[
                0x16, 0x00, 0x00, 0x00, // length 22
                0x00, 0x00, 0x00, 0x00, // request id
                0x00, 0x00, 0x00, 0x01, // correlation id
                0x00, 0x00, // error 0
                0xFF, 0xFF, 0xFF, 0xFF, // nullable array count
                0x00, 0x00, 0x00, 0x00, 0x00, 0x0C, // key 0: min 0, max 12
                0x00, 0x12, 0x00, 0x00, 0x00, 0x05, // key 18: min 0, max 5
            ];
            stream.write_all(response).await.unwrap();
        });

        let registry = parse_pack(
            r#"
name = "kafka"
[[probe]]
name = "apiversions"
service = "kafka"
ports = []
product = "Apache Kafka"
cpe = "cpe:2.3:a:apache:kafka"
confidence = 0.90
[[probe.step]]
send_hex = "00 00 00 0A 00 12 00 00 00 00 00 01 FF FF"
expect_hex = "00 12 00 00"
"#,
        )
        .unwrap();
        let mut results = vec![result(port, None)];
        let matched = registry
            .apply(&mut results, Duration::from_secs(2), true)
            .await;
        assert_eq!(matched, 1);
        let service = results[0].service.as_ref().unwrap();
        assert_eq!(service.name, "kafka");
        assert_eq!(service.product.as_deref(), Some("Apache Kafka"));
        assert_eq!(service.cpe.as_deref(), Some("cpe:2.3:a:apache:kafka"));
    }

    #[tokio::test]
    async fn skips_plaintext_active_probes_on_tls_results() {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        let registry = parse_pack(&format!(
            r#"
name = "tls-skip"
[[probe]]
name = "plaintext"
service = "plaintext"
ports = [{port}]
send = "hello"
expect = "HELLO"
"#
        ))
        .unwrap();

        let mut results = vec![result(port, None)];
        results[0].tls = Some(tls_info());
        let matched = registry
            .apply(&mut results, Duration::from_millis(100), true)
            .await;
        assert_eq!(matched, 0);
        assert!(
            tokio::time::timeout(Duration::from_millis(100), listener.accept())
                .await
                .is_err(),
            "plaintext probe must not open a connection to a TLS result"
        );
    }

    #[test]
    fn builtin_packs_compile_and_cover_core_protocols() {
        let mut registry = Registry::default();
        registry.merge_builtin().unwrap();
        let summaries = registry.summaries();
        assert!(
            summaries.len() >= 40,
            "expected a meaningful builtin library"
        );
        assert!(
            summaries.iter().filter(|summary| summary.tls).count() >= 10,
            "expected TLS-aware builtin probes"
        );
        for service in [
            "redis",
            "postgresql",
            "mysql",
            "mongodb",
            "elasticsearch",
            "docker",
            "kubernetes",
            "etcd",
            "consul",
            "modbus",
            "s7",
            "dnp3",
            "ethernet-ip",
            "vnc",
            "mqtt",
            "kafka",
        ] {
            assert!(
                summaries.iter().any(|summary| summary.service == service),
                "missing builtin probe for {service}"
            );
        }
    }
}
