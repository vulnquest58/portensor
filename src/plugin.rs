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
//! (UTF-8) or `send_hex` (binary), and any combination of `expect` (literal
//! text), `expect_regex`, or `expect_hex` (binary substring with `??`
//! wildcards).  `expect_hex_offset` anchors the binary pattern at a zero-based
//! response offset.  Steps without an expectation are pure stimuli.
//! `read_until` stops reading as soon as its regex matches, which keeps
//! HTTP-style probes fast.
//!
//! A step can capture values from its response with `capture` (regex) or
//! `capture_hex` (raw `offset:length` bytes).  Later `send` and `send_hex`
//! payloads interpolate them as `${name}`, enabling stateful sessions that
//! echo a server-generated session ID.
//!
//! Extraction patterns are applied to the full transcript.  A probe-level
//! `version_regex` wins over per-step patterns; `product_regex` and the
//! `[probe.info]` table use capture group 1 when present.

use std::collections::{BTreeMap, BTreeSet};
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
const MAX_CAPTURES: usize = 32;
const MAX_CAPTURE_NAME: usize = 32;
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
    expect_hex_offset: Option<usize>,
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
    expect_hex_offset: Option<usize>,
    #[serde(default)]
    capture: BTreeMap<String, String>,
    #[serde(default)]
    capture_hex: BTreeMap<String, String>,
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
    payload: Option<PayloadTemplate>,
    expect: Option<String>,
    expect_regex: Option<Regex>,
    expect_hex: Option<HexPattern>,
    expect_hex_offset: Option<usize>,
    version_regex: Option<Regex>,
    read_until: Option<Regex>,
    timeout: Option<Duration>,
    captures: Vec<Capture>,
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
            && !expect.matches(response, self.expect_hex_offset)
        {
            return false;
        }
        true
    }
}

#[derive(Debug)]
struct PayloadTemplate {
    parts: Vec<PayloadPart>,
}

#[derive(Debug)]
enum PayloadPart {
    Literal(Vec<u8>),
    Variable(String),
}

impl PayloadTemplate {
    fn text(input: &str, variables: bool) -> Result<Self, String> {
        Self::compile(input, variables, false)
    }

    fn hex(input: &str, variables: bool) -> Result<Self, String> {
        Self::compile(input, variables, true)
    }

    fn compile(input: &str, variables: bool, hex: bool) -> Result<Self, String> {
        let chunks = split_payload_template(input, variables);
        let mut parts = Vec::new();
        for chunk in chunks {
            let bytes = match chunk {
                TemplateChunk::Literal(literal) => {
                    if hex {
                        decode_hex(literal)?
                    } else {
                        literal.as_bytes().to_vec()
                    }
                }
                TemplateChunk::Variable(name) => {
                    parts.push(PayloadPart::Variable(name.to_string()));
                    continue;
                }
            };
            if !bytes.is_empty() {
                parts.push(PayloadPart::Literal(bytes));
            }
        }
        Ok(Self { parts })
    }

    fn is_empty(&self) -> bool {
        self.parts.is_empty()
            || self
                .parts
                .iter()
                .all(|part| matches!(part, PayloadPart::Literal(bytes) if bytes.is_empty()))
    }

    fn variables(&self) -> impl Iterator<Item = &str> {
        self.parts.iter().filter_map(|part| match part {
            PayloadPart::Variable(name) => Some(name.as_str()),
            PayloadPart::Literal(_) => None,
        })
    }

    fn has_variables(&self) -> bool {
        self.variables().next().is_some()
    }

    fn literal_len(&self) -> usize {
        self.parts
            .iter()
            .map(|part| match part {
                PayloadPart::Literal(bytes) => bytes.len(),
                PayloadPart::Variable(_) => 0,
            })
            .sum()
    }

    fn render(&self, variables: &BTreeMap<String, Vec<u8>>) -> Option<Vec<u8>> {
        let mut payload = Vec::new();
        for part in &self.parts {
            let bytes = match part {
                PayloadPart::Literal(bytes) => bytes,
                PayloadPart::Variable(name) => variables.get(name)?,
            };
            if payload.len() + bytes.len() > MAX_PAYLOAD {
                return None;
            }
            payload.extend_from_slice(bytes);
        }
        Some(payload)
    }
}

enum TemplateChunk<'a> {
    Literal(&'a str),
    Variable(&'a str),
}

fn split_payload_template(input: &str, variables: bool) -> Vec<TemplateChunk<'_>> {
    if !variables {
        return vec![TemplateChunk::Literal(input)];
    }
    let mut chunks = Vec::new();
    let mut rest = input;
    while let Some(start) = rest.find("${") {
        if start > 0 {
            chunks.push(TemplateChunk::Literal(&rest[..start]));
        }
        let after = &rest[start + 2..];
        if let Some(end) = after.find('}')
            && is_capture_name(&after[..end])
        {
            chunks.push(TemplateChunk::Variable(&after[..end]));
            rest = &after[end + 1..];
            continue;
        }
        chunks.push(TemplateChunk::Literal("${"));
        rest = after;
    }
    if !rest.is_empty() {
        chunks.push(TemplateChunk::Literal(rest));
    }
    chunks
}

#[derive(Debug)]
struct HexPattern {
    bytes: Vec<Option<u8>>,
}

impl HexPattern {
    fn matches(&self, response: &[u8], offset: Option<usize>) -> bool {
        if self.bytes.is_empty() {
            return false;
        }
        match offset {
            Some(offset) => self.matches_at(response, offset),
            None => {
                if response.len() < self.bytes.len() {
                    return false;
                }
                (0..=response.len() - self.bytes.len())
                    .any(|offset| self.matches_at(response, offset))
            }
        }
    }

    fn matches_at(&self, response: &[u8], offset: usize) -> bool {
        let Some(end) = offset.checked_add(self.bytes.len()) else {
            return false;
        };
        let Some(window) = response.get(offset..end) else {
            return false;
        };
        self.bytes
            .iter()
            .zip(window)
            .all(|(expected, actual)| match expected {
                Some(expected) => expected == actual,
                None => true,
            })
    }
}

#[derive(Debug)]
struct Capture {
    name: String,
    source: CaptureSource,
}

#[derive(Debug)]
enum CaptureSource {
    Regex(Regex),
    Hex { offset: usize, length: usize },
}

impl Capture {
    fn extract(&self, response: &[u8]) -> Option<Vec<u8>> {
        match &self.source {
            CaptureSource::Regex(regex) => {
                extract(regex, &String::from_utf8_lossy(response)).map(String::into_bytes)
            }
            CaptureSource::Hex { offset, length } => {
                let end = offset.checked_add(*length)?;
                response.get(*offset..end).map(<[u8]>::to_vec)
            }
        }
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

    /// Probe summaries for `portensor probes list`.
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

/// `portensor probes list`: print the compiled probe library.
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
        let mut variables = BTreeMap::new();
        for step in &self.steps {
            let step_timeout = step
                .timeout
                .unwrap_or(timeout)
                .clamp(MIN_TIMEOUT, MAX_TIMEOUT);
            if let Some(template) = &step.payload {
                let payload = template.render(&variables)?;
                if payload.is_empty() {
                    return None;
                }
                if tokio::time::timeout(step_timeout, stream.write_all(&payload))
                    .await
                    .ok()?
                    .is_err()
                {
                    return None;
                }
            }

            let response = read_response(stream, step, step_timeout).await?;
            if !step.matches(&response, self.ignore_case) {
                return None;
            }
            for capture in &step.captures {
                variables.insert(capture.name.clone(), capture.extract(&response)?);
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

fn validate_step_bindings(steps: &[Step], pack: &str, probe: &str) -> Result<(), AppError> {
    let mut defined = BTreeSet::new();
    let mut total = 0;
    for step in steps {
        if let Some(payload) = &step.payload {
            for variable in payload.variables() {
                if !defined.contains(variable) {
                    return Err(AppError::usage(format!(
                        "probe '{pack}/{probe}' uses variable '{variable}' before it is captured"
                    )));
                }
            }
        }
        for capture in &step.captures {
            total += 1;
            if !defined.insert(capture.name.clone()) {
                return Err(AppError::usage(format!(
                    "probe '{pack}/{probe}' declares capture '{}' more than once",
                    capture.name
                )));
            }
        }
    }
    if total > MAX_CAPTURES {
        return Err(AppError::usage(format!(
            "probe '{pack}/{probe}' exceeds {MAX_CAPTURES} captures"
        )));
    }
    if total > 0 && !steps.iter().any(|step| step.payload.is_some()) {
        return Err(AppError::usage(format!(
            "probe '{pack}/{probe}' declares captures but no active payload"
        )));
    }
    Ok(())
}

fn is_capture_name(name: &str) -> bool {
    let mut characters = name.chars();
    matches!(characters.next(), Some(character) if character.is_ascii_lowercase())
        && characters.all(|character| {
            character.is_ascii_lowercase() || character.is_ascii_digit() || character == '_'
        })
}

fn validate_capture_name(name: &str) -> Result<(), String> {
    if name.is_empty() || name.chars().count() > MAX_CAPTURE_NAME {
        return Err(format!(
            "name must be 1-{MAX_CAPTURE_NAME} characters of lowercase [a-z][a-z0-9_]*"
        ));
    }
    if !is_capture_name(name) {
        return Err("name must start with a lowercase letter and use [a-z0-9_]".to_string());
    }
    Ok(())
}

fn parse_capture_hex(input: &str) -> Result<(usize, usize), String> {
    let input = input.trim();
    if input.is_empty() {
        return Err("capture spec cannot be empty".to_string());
    }
    let (offset, length) = match input.split_once(':') {
        Some((offset, length)) => (offset.trim(), length.trim()),
        None => (input, "1"),
    };
    let offset = offset
        .parse::<usize>()
        .map_err(|_| "offset must be a non-negative decimal byte offset".to_string())?;
    let length = length
        .parse::<usize>()
        .map_err(|_| "length must be a positive decimal byte count".to_string())?;
    if length == 0 {
        return Err("length must be at least 1".to_string());
    }
    if length > MAX_PAYLOAD {
        return Err(format!("length must not exceed {MAX_PAYLOAD} bytes"));
    }
    Ok((offset, length))
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
            || raw.expect_hex.is_some()
            || raw.expect_hex_offset.is_some())
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

    let has_captures = raw
        .steps
        .iter()
        .any(|step| !step.capture.is_empty() || !step.capture_hex.is_empty());
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
                expect_hex_offset: raw.expect_hex_offset,
                timeout_ms: raw.timeout_ms,
                ..RawStep::default()
            },
            raw.ignore_case,
            false,
        )?]
    } else {
        raw.steps
            .into_iter()
            .enumerate()
            .map(|(index, step)| {
                compile_step(
                    pack,
                    &raw.name,
                    Some(index + 1),
                    step,
                    raw.ignore_case,
                    has_captures,
                )
            })
            .collect::<Result<Vec<_>, _>>()?
    };
    validate_step_bindings(&steps, pack, &raw.name)?;

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
    has_captures: bool,
) -> Result<Step, AppError> {
    if raw.send.is_some() && raw.send_hex.is_some() {
        return Err(AppError::usage(format!(
            "probe '{pack}/{probe}' step cannot set both send and send_hex"
        )));
    }
    let payload = match (&raw.send, &raw.send_hex) {
        (Some(text), None) => {
            Some(PayloadTemplate::text(text, has_captures).map_err(|error| {
                AppError::usage(format!("probe '{pack}/{probe}' send: {error}"))
            })?)
        }
        (None, Some(hex)) => Some(PayloadTemplate::hex(hex, has_captures).map_err(|error| {
            AppError::usage(format!("probe '{pack}/{probe}' send_hex: {error}"))
        })?),
        (None, None) => None,
        (Some(_), Some(_)) => unreachable!("checked above"),
    };
    if let Some(payload) = &payload
        && (payload.is_empty() || (!payload.has_variables() && payload.literal_len() > MAX_PAYLOAD))
    {
        return Err(AppError::usage(format!(
            "probe '{pack}/{probe}' payload must be between 1 and {MAX_PAYLOAD} bytes"
        )));
    }

    if raw.expect_hex_offset.is_some() && raw.expect_hex.is_none() {
        return Err(AppError::usage(format!(
            "probe '{pack}/{probe}' expect_hex_offset requires expect_hex"
        )));
    }
    let expect_hex = match &raw.expect_hex {
        Some(hex) => Some(decode_hex_pattern(hex).map_err(|error| {
            AppError::usage(format!("probe '{pack}/{probe}' expect_hex: {error}"))
        })?),
        None => None,
    };

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

    let mut captures = Vec::new();
    let mut capture_names = BTreeSet::new();
    for (name, pattern) in &raw.capture {
        validate_capture_name(name).map_err(|error| {
            AppError::usage(format!("probe '{pack}/{probe}' capture '{name}': {error}"))
        })?;
        if !capture_names.insert(name.clone()) {
            return Err(AppError::usage(format!(
                "probe '{pack}/{probe}' declares capture '{name}' more than once"
            )));
        }
        captures.push(Capture {
            name: name.clone(),
            source: CaptureSource::Regex(compile_regex(pattern, ignore_case, pack, probe)?),
        });
    }
    for (name, spec) in &raw.capture_hex {
        validate_capture_name(name).map_err(|error| {
            AppError::usage(format!(
                "probe '{pack}/{probe}' capture_hex '{name}': {error}"
            ))
        })?;
        if !capture_names.insert(name.clone()) {
            return Err(AppError::usage(format!(
                "probe '{pack}/{probe}' declares capture '{name}' more than once"
            )));
        }
        let (offset, length) = parse_capture_hex(spec).map_err(|error| {
            AppError::usage(format!(
                "probe '{pack}/{probe}' capture_hex '{name}': {error}"
            ))
        })?;
        captures.push(Capture {
            name: name.clone(),
            source: CaptureSource::Hex { offset, length },
        });
    }

    Ok(Step {
        name: raw
            .name
            .or_else(|| index.map(|index| format!("step {index}"))),
        payload,
        expect: raw.expect,
        expect_regex,
        expect_hex,
        expect_hex_offset: raw.expect_hex_offset,
        version_regex,
        read_until,
        timeout: raw.timeout_ms.map(Duration::from_millis),
        captures,
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

fn decode_hex_pattern(input: &str) -> Result<HexPattern, String> {
    let cleaned: String = input
        .chars()
        .filter(|character| {
            !character.is_ascii_whitespace() && *character != ':' && *character != '-'
        })
        .collect();
    if cleaned.is_empty() {
        return Err("expect_hex cannot be empty".to_string());
    }
    if !cleaned.len().is_multiple_of(2) {
        return Err("hex pattern has an odd number of digits".to_string());
    }
    let chars: Vec<char> = cleaned.chars().collect();
    let mut bytes = Vec::with_capacity(chars.len() / 2);
    for pair in chars.chunks(2) {
        if pair == ['?', '?'] {
            bytes.push(None);
            continue;
        }
        let pair: String = pair.iter().collect();
        if pair.contains('?') {
            return Err(format!("invalid hex wildcard '{pair}'; use '??'"));
        }
        let byte =
            u8::from_str_radix(&pair, 16).map_err(|_| format!("invalid hex byte '{pair}'"))?;
        bytes.push(Some(byte));
    }
    if !bytes.iter().any(Option::is_some) {
        return Err("hex pattern must contain at least one literal byte".to_string());
    }
    Ok(HexPattern { bytes })
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

/// Return the default plugin directory (`<config dir>/portensor/plugins`) when present.
pub fn default_dir() -> Option<PathBuf> {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("APPDATA").map(PathBuf::from))
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))?;
    let path = base.join("portensor").join("plugins");
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
            sni: None,
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
    async fn hex_wildcards_and_offsets_match_binary_responses() {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buffer = [0_u8; 8];
            let read = stream.read(&mut buffer).await.unwrap();
            assert_eq!(&buffer[..read], b"go");
            stream
                .write_all(&[0x00, 0xAA, 0x42, 0x00, 0xD4])
                .await
                .unwrap();
        });

        let registry = parse_pack(
            r#"
name = "binary-pattern"
[[probe]]
name = "offset-wildcards"
service = "binary-pattern"
send = "go"
expect_hex = "?? 42 ?? D4"
expect_hex_offset = 1
"#,
        )
        .unwrap();
        let mut results = vec![result(port, None)];
        let matched = registry
            .apply(&mut results, Duration::from_secs(2), true)
            .await;
        assert_eq!(matched, 1);
    }

    #[tokio::test]
    async fn captures_text_from_a_response_for_the_next_step() {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buffer = [0_u8; 64];
            let read = stream.read(&mut buffer).await.unwrap();
            assert_eq!(&buffer[..read], b"HELLO");
            stream.write_all(b"token=abc123\n").await.unwrap();
            let read = stream.read(&mut buffer).await.unwrap();
            assert_eq!(&buffer[..read], b"AUTH abc123");
            stream.write_all(b"WELCOME\n").await.unwrap();
        });

        let registry = parse_pack(
            r#"
name = "stateful-text"
[[probe]]
name = "token"
service = "stateful-text"
[[probe.step]]
send = "HELLO"
capture = { token = "token=([a-z0-9]+)" }
[[probe.step]]
send = "AUTH ${token}"
expect = "WELCOME"
"#,
        )
        .unwrap();
        let mut results = vec![result(port, None)];
        let matched = registry
            .apply(&mut results, Duration::from_secs(2), true)
            .await;
        assert_eq!(matched, 1);
    }

    #[tokio::test]
    async fn captures_binary_session_id_and_reuses_it() {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buffer = [0_u8; 32];
            let read = stream.read(&mut buffer).await.unwrap();
            assert_eq!(&buffer[..read], b"init");
            let mut response = [0_u8; 24];
            response[0] = 0x81;
            response[17] = 0xAB;
            stream.write_all(&response).await.unwrap();
            let read = stream.read(&mut buffer).await.unwrap();
            assert_eq!(&buffer[..read], [0x02, 0xAB, 0x04]);
            stream.write_all(b"OK").await.unwrap();
        });

        let registry = parse_pack(
            r#"
name = "stateful-binary"
[[probe]]
name = "sid"
service = "stateful-binary"
[[probe.step]]
send = "init"
expect_hex = "81"
expect_hex_offset = 0
capture_hex = { sid = "17:1" }
[[probe.step]]
send_hex = "02 ${sid} 04"
expect_hex = "4F 4B"
"#,
        )
        .unwrap();
        let mut results = vec![result(port, None)];
        let matched = registry
            .apply(&mut results, Duration::from_secs(2), true)
            .await;
        assert_eq!(matched, 1);
    }

    #[test]
    fn dollar_braces_stay_literal_when_no_captures_exist() {
        let registry = parse_pack(
            r#"
name = "literal"
[[probe]]
name = "literal"
service = "literal"
send = "GET /${path}"
"#,
        )
        .unwrap();
        let payload = registry.probes[0].steps[0]
            .payload
            .as_ref()
            .unwrap()
            .render(&BTreeMap::new())
            .unwrap();
        assert_eq!(payload, b"GET /${path}");
    }

    #[test]
    fn hex_pattern_offsets_are_anchored() {
        let pattern = decode_hex_pattern("?? 42").unwrap();
        assert!(pattern.matches(&[0x00, 0x42], Some(0)));
        assert!(!pattern.matches(&[0x00, 0x42], Some(1)));
        assert!(pattern.matches(&[0x00, 0x00, 0x42], None));
    }

    #[test]
    fn rejects_invalid_captures_and_hex_patterns() {
        let undefined = parse_pack(
            r#"
name = "bad"
[[probe]]
name = "x"
[[probe.step]]
send = "${sid}"
[[probe.step]]
send = "next"
capture_hex = { sid = "0:1" }
"#,
        )
        .unwrap_err();
        assert!(undefined.to_string().contains("before it is captured"));

        let duplicate = parse_pack(
            r#"
name = "bad"
[[probe]]
name = "x"
[[probe.step]]
send = "first"
capture = { sid = "(.*)" }
[[probe.step]]
send = "second"
capture_hex = { sid = "0:1" }
"#,
        )
        .unwrap_err();
        assert!(duplicate.to_string().contains("more than once"));

        let offset_without_expectation = parse_pack(
            r#"
name = "bad"
[[probe]]
name = "x"
send = "hello"
expect_hex_offset = 1
"#,
        )
        .unwrap_err();
        assert!(offset_without_expectation.to_string().contains("requires"));

        for pattern in ["?1", "??"] {
            assert!(
                parse_pack(&format!(
                    r#"
name = "bad"
[[probe]]
name = "x"
send = "hello"
expect_hex = "{pattern}"
"#
                ))
                .is_err(),
                "pattern {pattern} should not compile"
            );
        }

        assert!(
            parse_pack(
                r#"
name = "bad"
[[probe]]
name = "x"
send = "hello"
capture = { "Bad" = "(.*)" }
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
send = "hello"
capture_hex = { sid = "17:0" }
"#
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn pcworx_reuses_the_plc_session_id() {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 1962))
            .await
            .unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buffer = [0_u8; 256];
            stream.read_exact(&mut buffer[..26]).await.unwrap();
            assert_eq!(&buffer[..4], b"\x01\x01\x00\x1a");
            let mut response = [0_u8; 32];
            response[0] = 0x81;
            response[17] = 0x5A;
            stream.write_all(&response).await.unwrap();

            stream.read_exact(&mut buffer[..22]).await.unwrap();
            assert_eq!(&buffer[..3], b"\x01\x05\x00");
            assert_eq!(buffer[11], 0x5A);
            stream.write_all(&response).await.unwrap();

            stream.read_exact(&mut buffer[..14]).await.unwrap();
            assert_eq!(&buffer[..3], b"\x01\x06\x00");
            assert_eq!(buffer[11], 0x5A);
            let mut info = [0_u8; 192];
            info[0] = 0x81;
            stream.write_all(&info).await.unwrap();
        });

        let mut registry = Registry::default();
        registry.merge_builtin().unwrap();
        let mut results = vec![result(1962, None)];
        let matched = registry
            .apply(&mut results, Duration::from_secs(2), true)
            .await;
        assert_eq!(matched, 1);
        let service = results[0].service.as_ref().unwrap();
        assert_eq!(service.name, "pcworx");
        assert_eq!(
            service.product.as_deref(),
            Some("Phoenix Contact PCWorx PLC")
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
    async fn ge_srtp_initialization_and_read_match() {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buffer = [0_u8; 56];
            stream.read_exact(&mut buffer).await.unwrap();
            assert_eq!(buffer, [0_u8; 56]);
            let mut init = [0_u8; 56];
            init[0] = 0x01;
            init[8] = 0x0F;
            stream.write_all(&init).await.unwrap();
            stream.read_exact(&mut buffer).await.unwrap();
            assert_eq!(buffer[0], 0x02);
            assert_eq!(&buffer[30..32], b"\x06\xc0");
            let mut read = [0_u8; 56];
            read[0] = 0x03;
            read[1] = 0x01;
            read[2] = 0x00;
            read[31] = 0xD4;
            stream.write_all(&read).await.unwrap();
        });

        let registry = parse_pack(
            r#"
name = "ge-srtp"
[[probe]]
name = "ge-srtp-info"
service = "ge-srtp"
ports = []
product = "GE SRTP PLC"
confidence = 0.90
[[probe.step]]
send_hex = "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
expect_regex = '(?s)^\x01.{7}\x0F'
timeout_ms = 1500
[[probe.step]]
send_hex = "02 00 01 00 00 00 00 00 00 01 00 00 00 00 00 00 00 01 00 00 00 00 00 00 00 00 00 00 00 00 06 C0 00 00 00 00 10 0E 00 00 01 01 04 08 00 00 01 00 00 00 00 00 00 00 00 00"
expect_regex = '(?s)^\x03\x01\x00'
expect_hex = "D4"
timeout_ms = 1500
"#,
        )
        .unwrap();
        let mut results = vec![result(port, None)];
        let matched = registry
            .apply(&mut results, Duration::from_secs(2), true)
            .await;
        assert_eq!(matched, 1);
        let service = results[0].service.as_ref().unwrap();
        assert_eq!(service.name, "ge-srtp");
        assert_eq!(service.product.as_deref(), Some("GE SRTP PLC"));
    }

    #[tokio::test]
    async fn melsec_q_cpuinfo_request_matches() {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buffer = [0_u8; 41];
            stream.read_exact(&mut buffer).await.unwrap();
            assert_eq!(buffer[0], 0x57);
            assert_eq!(&buffer[32..], b"\x04\x01\x01\x01\x00\x00\x00\x00\x01");
            let mut response = [0_u8; 60];
            response[0] = 0xD7;
            response[40..48].copy_from_slice(b"Q03UDECU");
            stream.write_all(&response).await.unwrap();
        });

        let registry = parse_pack(
            r#"
name = "melsec-q"
[[probe]]
name = "melsec-q-cpuinfo"
service = "melsec-q"
ports = []
product = "Mitsubishi MELSEC-Q PLC"
confidence = 0.90
send_hex = "57 00 00 00 00 11 11 07 00 00 FF FF 03 00 00 FE 03 00 00 14 00 1C 08 0A 08 00 00 00 00 00 00 00 04 01 01 01 00 00 00 00 01"
expect_hex = "D7 00"
timeout_ms = 1500
"#,
        )
        .unwrap();
        let mut results = vec![result(port, None)];
        let matched = registry
            .apply(&mut results, Duration::from_secs(2), true)
            .await;
        assert_eq!(matched, 1);
        let service = results[0].service.as_ref().unwrap();
        assert_eq!(service.name, "melsec-q");
        assert_eq!(service.product.as_deref(), Some("Mitsubishi MELSEC-Q PLC"));
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

    fn builtin_probes(names: &[&str], port: Option<u16>) -> Registry {
        let mut registry = Registry::default();
        registry.merge_builtin().unwrap();
        registry
            .probes
            .retain(|probe| names.contains(&probe.name.as_str()));
        assert_eq!(registry.probes.len(), names.len());
        if let Some(port) = port {
            for probe in &mut registry.probes {
                probe.ports = vec![port];
            }
        }
        registry
    }

    #[tokio::test]
    async fn rabbitmq_amqp_start_extracts_version() {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut header = [0_u8; 8];
            stream.read_exact(&mut header).await.unwrap();
            assert_eq!(&header, b"AMQP\x00\x00\x09\x01");
            let mut response = header.to_vec();
            response.extend_from_slice(
                b"product\x05S\x00\x00\x00\x08RabbitMQversion\x05S\x00\x00\x00\x063.13.7",
            );
            stream.write_all(&response).await.unwrap();
        });

        let registry = builtin_probes(&["rabbitmq-amqp-start"], Some(port));
        let mut results = vec![result(port, None)];
        let matched = registry
            .apply(&mut results, Duration::from_secs(2), true)
            .await;
        assert_eq!(matched, 1);
        let service = results[0].service.as_ref().unwrap();
        assert_eq!(service.name, "rabbitmq");
        assert_eq!(service.product.as_deref(), Some("RabbitMQ"));
        assert_eq!(service.version.as_deref(), Some("3.13.7"));
    }

    #[tokio::test]
    async fn nats_and_rsync_passive_banners_are_identified() {
        let registry = builtin_probes(&["nats-info", "rsync-greeting"], None);
        let mut results = vec![
            result(
                4222,
                Some(
                    r#"{"server_id":"abc","server_name":"nats-1","version":"2.10.7","proto":1,"go":"go1.21.5"}"#,
                ),
            ),
            result(873, Some("@RSYNCD: 31.0\n")),
        ];
        let matched = registry
            .apply(&mut results, Duration::from_millis(100), true)
            .await;
        assert_eq!(matched, 2);

        let nats = results[0].service.as_ref().unwrap();
        assert_eq!(nats.name, "nats");
        assert_eq!(nats.product.as_deref(), Some("NATS"));
        assert_eq!(nats.version.as_deref(), Some("2.10.7"));

        let rsync = results[1].service.as_ref().unwrap();
        assert_eq!(rsync.name, "rsync");
        assert_eq!(rsync.product.as_deref(), Some("rsync"));
        assert_eq!(rsync.version.as_deref(), Some("31.0"));
    }

    #[tokio::test]
    async fn zookeeper_srvr_extracts_version() {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut command = [0_u8; 6];
            stream.read_exact(&mut command).await.unwrap();
            assert_eq!(&command, b"srvr\r\n");
            stream
                .write_all(
                    b"Zookeeper version: 3.9.2-abc, built on 2024-01-01\r\nLatency min/avg/max: 0/0/0\r\n",
                )
                .await
                .unwrap();
        });

        let registry = builtin_probes(&["zookeeper-srvr"], Some(port));
        let mut results = vec![result(port, None)];
        let matched = registry
            .apply(&mut results, Duration::from_secs(2), true)
            .await;
        assert_eq!(matched, 1);
        let service = results[0].service.as_ref().unwrap();
        assert_eq!(service.name, "zookeeper");
        assert_eq!(service.product.as_deref(), Some("Apache ZooKeeper"));
        assert_eq!(service.version.as_deref(), Some("3.9.2"));
    }

    #[tokio::test]
    async fn clickhouse_and_influxdb_http_probes_extract_versions() {
        let clickhouse = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let clickhouse_port = clickhouse.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut stream, _) = clickhouse.accept().await.unwrap();
            let mut request = [0_u8; 256];
            let read = stream.read(&mut request).await.unwrap();
            assert!(String::from_utf8_lossy(&request[..read]).contains("SELECT%20version()"));
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: text/tab-separated-values\r\nConnection: close\r\n\r\n24.3.2.23\n",
                )
                .await
                .unwrap();
        });

        let influx = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let influx_port = influx.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut stream, _) = influx.accept().await.unwrap();
            let mut request = [0_u8; 256];
            let read = stream.read(&mut request).await.unwrap();
            assert!(String::from_utf8_lossy(&request[..read]).starts_with("GET /ping "));
            stream
                .write_all(
                    b"HTTP/1.1 204 No Content\r\nX-Influxdb-Version: 2.7.10\r\nConnection: close\r\n\r\n",
                )
                .await
                .unwrap();
        });

        let clickhouse_registry = builtin_probes(&["clickhouse-version"], Some(clickhouse_port));
        let influx_registry = builtin_probes(&["influxdb-ping"], Some(influx_port));

        let mut clickhouse_results = vec![result(clickhouse_port, None)];
        let matched = clickhouse_registry
            .apply(&mut clickhouse_results, Duration::from_secs(2), true)
            .await;
        assert_eq!(matched, 1);
        let service = clickhouse_results[0].service.as_ref().unwrap();
        assert_eq!(service.name, "clickhouse");
        assert_eq!(service.version.as_deref(), Some("24.3.2.23"));

        let mut influx_results = vec![result(influx_port, None)];
        let matched = influx_registry
            .apply(&mut influx_results, Duration::from_secs(2), true)
            .await;
        assert_eq!(matched, 1);
        let service = influx_results[0].service.as_ref().unwrap();
        assert_eq!(service.name, "influxdb");
        assert_eq!(service.version.as_deref(), Some("2.7.10"));
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
            "opcua",
            "iec-104",
            "niagara-fox",
            "fins",
            "hart-ip",
            "ge-srtp",
            "melsec-q",
            "pcworx",
            "vnc",
            "mqtt",
            "kafka",
            "rabbitmq",
            "nats",
            "zookeeper",
            "rsync",
            "clickhouse",
            "influxdb",
        ] {
            assert!(
                summaries.iter().any(|summary| summary.service == service),
                "missing builtin probe for {service}"
            );
        }
    }
}
