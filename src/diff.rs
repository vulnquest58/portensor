//! Differential Network State Analysis Engine (`--diff` / `--compare-to`).
//!
//! Evaluates changes between a baseline scan report and a current scan report:
//! - New open ports (`[+] NEW`)
//! - Closed/withdrawn ports (`[-] GONE`)
//! - Service version and banner modifications (`[*] CHANGED`)
//! - Defensive posture shifts (`[~] POSTURE`)

use std::collections::{BTreeMap, HashMap};
use std::io::IsTerminal;
use std::net::IpAddr;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::AppError;
use crate::model::{PortResult, PortState, ScanReport};
use crate::resume::ScanState;

/// The nature of an observed difference.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeKind {
    /// Newly opened port
    New,
    /// Previously open port that is now closed or missing
    Gone,
    /// Service name, product, or version updated
    ServiceChanged,
    /// Port state changed (e.g. filtered -> open)
    StateChanged,
    /// Noticeable confidence shift
    ConfidenceChanged,
    /// Advisory findings added, resolved, or re-scored
    AdvisoryChanged,
}

impl ChangeKind {
    pub const fn tag(self) -> &'static str {
        match self {
            Self::New => "[+] NEW",
            Self::Gone => "[-] GONE",
            Self::ServiceChanged => "[*] CHANGED",
            Self::StateChanged => "[*] CHANGED",
            Self::ConfidenceChanged => "[*] CHANGED",
            Self::AdvisoryChanged => "[*] CHANGED",
        }
    }
}

/// Stable advisory identity retained in baselines and differential output.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AdvisoryRef {
    pub id: String,
    #[serde(default)]
    pub severity: String,
    #[serde(default)]
    pub cvss: f32,
}

impl AdvisoryRef {
    fn from_match(advisory: &crate::advisory::AdvisoryMatch) -> Self {
        Self {
            id: advisory.id.clone(),
            severity: advisory.severity.label().to_ascii_lowercase(),
            cvss: advisory.cvss,
        }
    }
}

/// A differential event recorded for a specific (host, port).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PortChange {
    pub host: IpAddr,
    pub port: u16,
    pub kind: ChangeKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old_state: Option<PortState>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_state: Option<PortState>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old_service: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_service: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub old_confidence: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub new_confidence: Option<f32>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub new_advisories: Vec<AdvisoryRef>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resolved_advisories: Vec<AdvisoryRef>,
    pub summary: String,
}

/// A change in host defense posture between baseline and current scan.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct HostPostureChange {
    pub host: IpAddr,
    pub old_posture: String,
    pub new_posture: String,
    pub old_confidence: f32,
    pub new_confidence: f32,
}

/// Aggregate summary counts of detected changes.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiffSummary {
    pub new_ports: usize,
    pub gone_ports: usize,
    pub modified_ports: usize,
    pub unchanged_ports: usize,
    pub posture_changes: usize,
    #[serde(default)]
    pub critical_advisories: usize,
}

/// Complete differential analysis report.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ScanDiff {
    pub baseline_source: String,
    pub current_target: String,
    pub port_changes: Vec<PortChange>,
    pub posture_changes: Vec<HostPostureChange>,
    pub summary: DiffSummary,
}

/// Baseline port snapshot extracted from any supported report or state format.
#[derive(Clone, Debug, Default)]
pub struct BaselineEntry {
    pub state: PortState,
    pub service_label: Option<String>,
    pub confidence: Option<f32>,
    pub advisories: Vec<AdvisoryRef>,
}

/// Baseline snapshot encompassing ports and defensive posture.
#[derive(Clone, Debug, Default)]
pub struct BaselineSnapshot {
    pub ports: HashMap<(IpAddr, u16), BaselineEntry>,
    pub defense_postures: HashMap<IpAddr, (String, f32)>,
}

impl BaselineSnapshot {
    /// Build a snapshot from an active [`ScanReport`].
    pub fn from_report(report: &ScanReport) -> Self {
        let mut snapshot = Self::default();
        for res in &report.results {
            let svc = service_display(res);
            snapshot.ports.insert(
                (res.host, res.port),
                BaselineEntry {
                    state: res.state,
                    service_label: if svc.is_empty() { None } else { Some(svc) },
                    confidence: res.confidence,
                    advisories: res.advisories.iter().map(AdvisoryRef::from_match).collect(),
                },
            );
        }
        let defenses = crate::defense::analyze_defenses(report);
        for (host, assess) in defenses {
            snapshot.defense_postures.insert(
                host,
                (assess.defense_type.badge().to_string(), assess.confidence),
            );
        }
        snapshot
    }
}

impl ScanDiff {
    /// True when any port or posture difference was detected.
    pub fn changes_detected(&self) -> bool {
        self.summary.new_ports > 0
            || self.summary.gone_ports > 0
            || self.summary.modified_ports > 0
            || self.summary.posture_changes > 0
    }

    /// Compact plain-text alert suitable for log ingestion or webhook payloads.
    pub fn render_alert(&self) -> String {
        let mut out = String::new();
        out.push_str("rayscan change alert\n");
        out.push_str(&format!("baseline: {}\n", self.baseline_source));
        out.push_str(&format!("target: {}\n", self.current_target));
        out.push_str(&format!(
            "new: {}  gone: {}  modified: {}  posture: {}  critical_advisories: {}\n",
            self.summary.new_ports,
            self.summary.gone_ports,
            self.summary.modified_ports,
            self.summary.posture_changes,
            self.summary.critical_advisories
        ));
        if !self.changes_detected() {
            out.push_str("status: no changes\n");
            return out;
        }
        out.push_str("status: changes detected\n");
        for change in &self.port_changes {
            out.push_str(&format!(
                "{} {}:{} {}\n",
                change.kind.tag(),
                change.host,
                change.port,
                change.summary
            ));
        }
        for posture in &self.posture_changes {
            out.push_str(&format!(
                "[~] POSTURE {} {} -> {}\n",
                posture.host, posture.old_posture, posture.new_posture
            ));
        }
        out
    }

    /// Compute differences between two baseline snapshots.
    pub fn compute_snapshots(
        baseline_source: &str,
        current_target: &str,
        baseline: &BaselineSnapshot,
        current: &BaselineSnapshot,
    ) -> Self {
        let mut port_changes = Vec::new();
        let mut unchanged_ports = 0usize;

        let mut all_keys: BTreeMap<(IpAddr, u16), ()> = BTreeMap::new();
        for k in baseline.ports.keys() {
            all_keys.insert(*k, ());
        }
        for k in current.ports.keys() {
            all_keys.insert(*k, ());
        }

        for (host, port) in all_keys.keys().copied() {
            let base_opt = baseline.ports.get(&(host, port));
            let curr_opt = current.ports.get(&(host, port));

            match (base_opt, curr_opt) {
                // Case 1: Present in current, but absent from baseline
                (None, Some(curr)) => {
                    if curr.state == PortState::Open {
                        let conf = curr.confidence.unwrap_or(1.0);
                        let svc = curr.service_label.clone();
                        port_changes.push(PortChange {
                            host,
                            port,
                            kind: ChangeKind::New,
                            old_state: None,
                            new_state: Some(curr.state),
                            old_service: None,
                            new_service: svc.clone(),
                            old_confidence: None,
                            new_confidence: curr.confidence,
                            new_advisories: curr.advisories.clone(),
                            resolved_advisories: Vec::new(),
                            summary: format!(
                                "{} (Confidence: {:.0}%){}",
                                svc.as_deref().unwrap_or("open port"),
                                conf * 100.0,
                                advisory_note(&[], &curr.advisories)
                            ),
                        });
                    }
                }

                // Case 2: Present in baseline as Open, but absent or closed in current
                (Some(base), None) => {
                    if base.state == PortState::Open {
                        port_changes.push(PortChange {
                            host,
                            port,
                            kind: ChangeKind::Gone,
                            old_state: Some(base.state),
                            new_state: None,
                            old_service: base.service_label.clone(),
                            new_service: None,
                            old_confidence: base.confidence,
                            new_confidence: None,
                            new_advisories: Vec::new(),
                            resolved_advisories: base.advisories.clone(),
                            summary: format!(
                                "{} (Was: open){}",
                                base.service_label.as_deref().unwrap_or("open port"),
                                advisory_note(&base.advisories, &[])
                            ),
                        });
                    }
                }

                // Case 3: Present in both
                (Some(base), Some(curr)) => {
                    let base_svc = base.service_label.clone().unwrap_or_default();
                    let curr_svc = curr.service_label.clone().unwrap_or_default();

                    if base.state == PortState::Open && curr.state != PortState::Open {
                        port_changes.push(PortChange {
                            host,
                            port,
                            kind: ChangeKind::Gone,
                            old_state: Some(base.state),
                            new_state: Some(curr.state),
                            old_service: base.service_label.clone(),
                            new_service: curr.service_label.clone(),
                            old_confidence: base.confidence,
                            new_confidence: curr.confidence,
                            new_advisories: Vec::new(),
                            resolved_advisories: base.advisories.clone(),
                            summary: format!(
                                "open → {} ({}){}",
                                curr.state.as_str(),
                                base.service_label.as_deref().unwrap_or("unknown"),
                                advisory_note(&base.advisories, &[])
                            ),
                        });
                    } else if base.state != PortState::Open && curr.state == PortState::Open {
                        port_changes.push(PortChange {
                            host,
                            port,
                            kind: ChangeKind::New,
                            old_state: Some(base.state),
                            new_state: Some(curr.state),
                            old_service: if base_svc.is_empty() {
                                None
                            } else {
                                Some(base_svc)
                            },
                            new_service: if curr_svc.is_empty() {
                                None
                            } else {
                                Some(curr_svc.clone())
                            },
                            old_confidence: base.confidence,
                            new_confidence: curr.confidence,
                            new_advisories: curr.advisories.clone(),
                            resolved_advisories: Vec::new(),
                            summary: format!(
                                "{} (Was: {}){}",
                                if curr_svc.is_empty() {
                                    "open"
                                } else {
                                    &curr_svc
                                },
                                base.state.as_str(),
                                advisory_note(&[], &curr.advisories)
                            ),
                        });
                    } else if base.state == PortState::Open && curr.state == PortState::Open {
                        let svc_diff =
                            !curr_svc.is_empty() && !base_svc.is_empty() && curr_svc != base_svc;
                        let conf_diff = match (base.confidence, curr.confidence) {
                            (Some(b), Some(c)) => (b - c).abs() >= 0.20,
                            _ => false,
                        };
                        let (new_advisories, resolved_advisories) =
                            advisory_delta(&base.advisories, &curr.advisories);
                        let advisory_diff =
                            !new_advisories.is_empty() || !resolved_advisories.is_empty();
                        let advisory_text = advisory_note(&resolved_advisories, &new_advisories);

                        if svc_diff || conf_diff || advisory_diff {
                            let (kind, summary) = if svc_diff {
                                (
                                    ChangeKind::ServiceChanged,
                                    format!("{} → {}{}", base_svc, curr_svc, advisory_text),
                                )
                            } else if conf_diff {
                                (
                                    ChangeKind::ConfidenceChanged,
                                    format!(
                                        "confidence: {:.0}% → {:.0}%{}",
                                        base.confidence.unwrap_or(1.0) * 100.0,
                                        curr.confidence.unwrap_or(1.0) * 100.0,
                                        advisory_text
                                    ),
                                )
                            } else {
                                (
                                    ChangeKind::AdvisoryChanged,
                                    format!(
                                        "advisories: {} → {}{}",
                                        base.advisories.len(),
                                        curr.advisories.len(),
                                        advisory_text
                                    ),
                                )
                            };
                            port_changes.push(PortChange {
                                host,
                                port,
                                kind,
                                old_state: Some(base.state),
                                new_state: Some(curr.state),
                                old_service: if base_svc.is_empty() {
                                    None
                                } else {
                                    Some(base_svc)
                                },
                                new_service: if curr_svc.is_empty() {
                                    None
                                } else {
                                    Some(curr_svc)
                                },
                                old_confidence: base.confidence,
                                new_confidence: curr.confidence,
                                new_advisories,
                                resolved_advisories,
                                summary,
                            });
                        } else {
                            unchanged_ports += 1;
                        }
                    } else {
                        unchanged_ports += 1;
                    }
                }

                (None, None) => {}
            }
        }

        // Defensive posture comparison
        let mut posture_changes = Vec::new();
        for (host, (current_posture, current_conf)) in &current.defense_postures {
            if let Some((old_posture, old_conf)) = baseline.defense_postures.get(host)
                && current_posture != old_posture
            {
                posture_changes.push(HostPostureChange {
                    host: *host,
                    old_posture: old_posture.clone(),
                    new_posture: current_posture.clone(),
                    old_confidence: *old_conf,
                    new_confidence: *current_conf,
                });
            }
        }

        let new_ports = port_changes
            .iter()
            .filter(|c| c.kind == ChangeKind::New)
            .count();
        let gone_ports = port_changes
            .iter()
            .filter(|c| c.kind == ChangeKind::Gone)
            .count();
        let modified_ports = port_changes
            .iter()
            .filter(|c| {
                matches!(
                    c.kind,
                    ChangeKind::ServiceChanged
                        | ChangeKind::StateChanged
                        | ChangeKind::ConfidenceChanged
                        | ChangeKind::AdvisoryChanged
                )
            })
            .count();
        let posture_count = posture_changes.len();
        let critical_advisories = port_changes
            .iter()
            .flat_map(|change| &change.new_advisories)
            .filter(|advisory| advisory.severity.eq_ignore_ascii_case("critical"))
            .count();

        let summary = DiffSummary {
            new_ports,
            gone_ports,
            modified_ports,
            unchanged_ports,
            posture_changes: posture_count,
            critical_advisories,
        };

        Self {
            baseline_source: baseline_source.to_string(),
            current_target: current_target.to_string(),
            port_changes,
            posture_changes,
            summary,
        }
    }

    /// Compute differences between a loaded baseline snapshot and a current [`ScanReport`].
    pub fn compute(
        baseline_source: &str,
        target_label: &str,
        baseline: &BaselineSnapshot,
        current_report: &ScanReport,
    ) -> Self {
        let current_snapshot = BaselineSnapshot::from_report(current_report);
        Self::compute_snapshots(baseline_source, target_label, baseline, &current_snapshot)
    }

    /// Render human-readable terminal diff output matching user specifications.
    pub fn render_terminal(&self, use_color: bool) -> String {
        let mut out = String::new();

        out.push_str("\nNetwork State Differential Analysis (vs ");
        out.push_str(&self.baseline_source);
        out.push_str("):\n");
        out.push_str(&"─".repeat(70));
        out.push('\n');

        if self.port_changes.is_empty() && self.posture_changes.is_empty() {
            out.push_str(
                "No network state changes detected (targets and services are identical).\n",
            );
        } else {
            // 1. Port changes
            for c in &self.port_changes {
                let tag = c.kind.tag();
                let styled_tag = if use_color {
                    match c.kind {
                        ChangeKind::New => format!("\x1b[1;32m{}\x1b[0m", tag), // Bold Green
                        ChangeKind::Gone => format!("\x1b[1;31m{}\x1b[0m", tag), // Bold Red
                        _ => format!("\x1b[1;33m{}\x1b[0m", tag),               // Bold Yellow
                    }
                } else {
                    tag.to_string()
                };

                let target_str = format!("{}:{}", c.host, c.port);
                let svc_str = match c.kind {
                    ChangeKind::New => c.new_service.as_deref().unwrap_or(""),
                    ChangeKind::Gone => c.old_service.as_deref().unwrap_or(""),
                    _ => "",
                };

                if matches!(
                    c.kind,
                    ChangeKind::ServiceChanged
                        | ChangeKind::StateChanged
                        | ChangeKind::AdvisoryChanged
                ) {
                    out.push_str(&format!(
                        "{:<11} {:<21} {}\n",
                        styled_tag, target_str, c.summary
                    ));
                } else {
                    out.push_str(&format!(
                        "{:<11} {:<21} {:<26} ({})\n",
                        styled_tag, target_str, svc_str, c.summary
                    ));
                }
            }

            // 2. Posture changes
            for p in &self.posture_changes {
                let styled_tag = if use_color {
                    "\x1b[1;35m[~] POSTURE\x1b[0m" // Bold Magenta
                } else {
                    "[~] POSTURE"
                };
                out.push_str(&format!(
                    "{:<11} {:<21} {} → {}\n",
                    styled_tag,
                    p.host.to_string(),
                    p.old_posture,
                    p.new_posture
                ));
            }
        }

        out.push('\n');
        out.push_str(&format!(
            "Diff Summary: {} new | {} closed/gone | {} modified | {} posture shifted ({} unchanged)\n",
            self.summary.new_ports,
            self.summary.gone_ports,
            self.summary.modified_ports,
            self.summary.posture_changes,
            self.summary.unchanged_ports
        ));
        if self.summary.critical_advisories > 0 {
            out.push_str(&format!(
                "New critical advisories: {}\n",
                self.summary.critical_advisories
            ));
        }

        out
    }
}

fn advisory_delta(
    baseline: &[AdvisoryRef],
    current: &[AdvisoryRef],
) -> (Vec<AdvisoryRef>, Vec<AdvisoryRef>) {
    let base_by_id: HashMap<&str, &AdvisoryRef> = baseline
        .iter()
        .map(|advisory| (advisory.id.as_str(), advisory))
        .collect();
    let current_by_id: HashMap<&str, &AdvisoryRef> = current
        .iter()
        .map(|advisory| (advisory.id.as_str(), advisory))
        .collect();

    let mut added = Vec::new();
    let mut resolved = Vec::new();
    for advisory in current {
        match base_by_id.get(advisory.id.as_str()) {
            None => added.push(advisory.clone()),
            Some(old) if advisory_materially_changed(old, advisory) => {
                resolved.push((*old).clone());
                added.push(advisory.clone());
            }
            Some(_) => {}
        }
    }
    for advisory in baseline {
        if !current_by_id.contains_key(advisory.id.as_str()) {
            resolved.push(advisory.clone());
        }
    }
    added.sort_by(|left, right| left.id.cmp(&right.id));
    resolved.sort_by(|left, right| left.id.cmp(&right.id));
    (added, resolved)
}

fn advisory_materially_changed(old: &AdvisoryRef, new: &AdvisoryRef) -> bool {
    !old.severity.eq_ignore_ascii_case(&new.severity) || (old.cvss - new.cvss).abs() >= 0.1
}

fn advisory_note(resolved: &[AdvisoryRef], added: &[AdvisoryRef]) -> String {
    if resolved.is_empty() && added.is_empty() {
        String::new()
    } else {
        format!("; advisories +{} -{}", added.len(), resolved.len())
    }
}

/// Helper to render service product/version string from PortResult.
fn service_display(res: &PortResult) -> String {
    let Some(svc) = &res.service else {
        return res.banner.clone().unwrap_or_default();
    };
    let mut out = svc.name.clone();
    if let Some(prod) = &svc.product {
        out.push(' ');
        out.push_str(prod);
    }
    if let Some(ver) = &svc.version {
        out.push('/');
        out.push_str(ver);
    }
    out
}

struct XmlTag {
    name: String,
    closing: bool,
    self_closing: bool,
    attrs: Vec<(String, String)>,
}

impl XmlTag {
    fn attr(&self, name: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }
}

struct NmapPort {
    port: u16,
    state: Option<PortState>,
    service_label: Option<String>,
}

fn invalid_nmap_xml(path: &Path, detail: &str) -> AppError {
    AppError::usage(format!(
        "baseline file {} is not a valid Nmap XML report: {detail}",
        path.display()
    ))
}

fn find_xml_tag_end(text: &str, offset: usize) -> Result<usize, String> {
    let bytes = text.as_bytes();
    let mut quote = None;
    let mut index = offset;
    while index < bytes.len() {
        let byte = bytes[index];
        if let Some(active) = quote {
            if byte == active {
                quote = None;
            }
        } else {
            match byte {
                b'"' | b'\'' => quote = Some(byte),
                b'>' => return Ok(index),
                _ => {}
            }
        }
        index += 1;
    }
    Err("unterminated XML tag".to_string())
}

fn parse_xml_tag(inner: &str) -> Result<XmlTag, String> {
    let mut body = inner.trim();
    if body.is_empty() {
        return Err("empty XML tag".to_string());
    }
    let closing = body.starts_with('/');
    if closing {
        body = body[1..].trim_start();
    }
    let self_closing = body.ends_with('/');
    if self_closing {
        body = body[..body.len() - 1].trim_end();
    }
    let name_end = body
        .find(|character: char| character.is_whitespace())
        .unwrap_or(body.len());
    let name = &body[..name_end];
    if name.is_empty() {
        return Err("XML tag has no name".to_string());
    }

    let mut attrs = Vec::new();
    let bytes = body.as_bytes();
    let mut cursor = name_end;
    while cursor < bytes.len() {
        while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
            cursor += 1;
        }
        if cursor >= bytes.len() {
            break;
        }
        let key_start = cursor;
        while cursor < bytes.len() && !bytes[cursor].is_ascii_whitespace() && bytes[cursor] != b'='
        {
            cursor += 1;
        }
        if cursor == key_start {
            return Err("XML attribute has no name".to_string());
        }
        let key = &body[key_start..cursor];
        while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
            cursor += 1;
        }
        let value = if cursor < bytes.len() && bytes[cursor] == b'=' {
            cursor += 1;
            while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
                cursor += 1;
            }
            if cursor >= bytes.len() {
                return Err(format!("XML attribute {key} has no value"));
            }
            let quote = bytes[cursor];
            if quote == b'"' || quote == b'\'' {
                cursor += 1;
                let value_start = cursor;
                while cursor < bytes.len() && bytes[cursor] != quote {
                    cursor += 1;
                }
                if cursor >= bytes.len() {
                    return Err(format!("XML attribute {key} is unterminated"));
                }
                let value = &body[value_start..cursor];
                cursor += 1;
                value
            } else {
                let value_start = cursor;
                while cursor < bytes.len() && !bytes[cursor].is_ascii_whitespace() {
                    cursor += 1;
                }
                &body[value_start..cursor]
            }
        } else {
            ""
        };
        attrs.push((key.to_string(), decode_xml_entities(value)));
    }

    Ok(XmlTag {
        name: name.rsplit(':').next().unwrap_or(name).to_string(),
        closing,
        self_closing,
        attrs,
    })
}

fn decode_xml_entities(value: &str) -> String {
    let mut decoded = String::with_capacity(value.len());
    let mut rest = value;
    while let Some(index) = rest.find('&') {
        decoded.push_str(&rest[..index]);
        let candidate = &rest[index + 1..];
        let Some(end) = candidate.find(';') else {
            decoded.push('&');
            rest = candidate;
            continue;
        };
        let entity = &candidate[..end];
        let replacement = match entity {
            "amp" => Some('&'),
            "lt" => Some('<'),
            "gt" => Some('>'),
            "quot" => Some('"'),
            "apos" => Some('\''),
            _ => entity
                .strip_prefix("#x")
                .or_else(|| entity.strip_prefix("#X"))
                .and_then(|digits| u32::from_str_radix(digits, 16).ok())
                .or_else(|| {
                    entity
                        .strip_prefix('#')
                        .and_then(|digits| digits.parse::<u32>().ok())
                })
                .and_then(char::from_u32),
        };
        if let Some(character) = replacement {
            decoded.push(character);
        } else {
            decoded.push('&');
            decoded.push_str(entity);
            decoded.push(';');
        }
        rest = &candidate[end + 1..];
    }
    decoded.push_str(rest);
    decoded
}

fn parse_xml_tags(xml: &str) -> Result<Vec<XmlTag>, String> {
    let mut tags = Vec::new();
    let mut cursor = 0usize;
    while let Some(relative) = xml[cursor..].find('<') {
        let start = cursor + relative;
        let rest = &xml[start..];
        if rest.starts_with("<!--") {
            let end = rest
                .find("-->")
                .ok_or_else(|| "unterminated XML comment".to_string())?;
            cursor = start + end + 3;
        } else if rest.starts_with("<?") {
            let end = rest
                .find("?>")
                .ok_or_else(|| "unterminated XML declaration".to_string())?;
            cursor = start + end + 2;
        } else if rest.starts_with("<!") {
            let end = find_xml_tag_end(rest, 2)?;
            cursor = start + end + 1;
        } else {
            let end = find_xml_tag_end(rest, 1)?;
            tags.push(parse_xml_tag(&rest[1..end])?);
            cursor = start + end + 1;
        }
    }
    Ok(tags)
}

fn nmap_port_state(value: &str) -> Option<PortState> {
    match value {
        "open" => Some(PortState::Open),
        "closed" => Some(PortState::Closed),
        "filtered" | "open|filtered" | "closed|filtered" => Some(PortState::Filtered),
        "unfiltered" => Some(PortState::Unfiltered),
        _ => None,
    }
}

fn nmap_service_label(tag: &XmlTag) -> Option<String> {
    let name = tag.attr("name").unwrap_or_default().trim();
    let product = tag.attr("product").unwrap_or_default().trim();
    let version = tag.attr("version").unwrap_or_default().trim();
    let mut label = String::new();
    if !name.is_empty() {
        label.push_str(name);
    }
    if !product.is_empty() {
        if !label.is_empty() {
            label.push(' ');
        }
        label.push_str(product);
    }
    if !version.is_empty() {
        label.push('/');
        label.push_str(version);
    }
    (!label.is_empty()).then_some(label)
}

fn load_nmap_xml(content: &str, path: &Path) -> Result<BaselineSnapshot, AppError> {
    let tags = parse_xml_tags(content).map_err(|reason| invalid_nmap_xml(path, &reason))?;
    let Some(root) = tags.first() else {
        return Err(invalid_nmap_xml(path, "no XML elements found"));
    };
    if root.name != "nmaprun" || root.closing {
        return Err(invalid_nmap_xml(path, "missing <nmaprun> root element"));
    }
    if !tags.iter().any(|tag| tag.name == "nmaprun" && tag.closing) {
        return Err(invalid_nmap_xml(path, "unterminated <nmaprun> element"));
    }

    let mut snapshot = BaselineSnapshot::default();
    let mut host = None;
    let mut port: Option<NmapPort> = None;

    for tag in &tags {
        match tag.name.as_str() {
            "host" if tag.closing || !tag.self_closing => {
                host = None;
                port = None;
            }
            "address" if !tag.closing && host.is_none() => {
                let addr_type = tag.attr("addrtype").unwrap_or_default();
                if matches!(addr_type, "ipv4" | "ipv6")
                    && let Some(address) = tag
                        .attr("addr")
                        .and_then(|value| value.parse::<IpAddr>().ok())
                {
                    host = Some(address);
                }
            }
            "port" if !tag.closing && !tag.self_closing => {
                port = None;
                if host.is_some()
                    && tag
                        .attr("protocol")
                        .is_some_and(|value| value.eq_ignore_ascii_case("tcp"))
                    && let Some(portid) = tag
                        .attr("portid")
                        .and_then(|value| value.parse::<u16>().ok())
                {
                    port = Some(NmapPort {
                        port: portid,
                        state: None,
                        service_label: None,
                    });
                }
            }
            "state" if !tag.closing && port.is_some() => {
                if let Some(active) = port.as_mut() {
                    active.state = tag.attr("state").and_then(nmap_port_state);
                }
            }
            "service" if !tag.closing && port.is_some() => {
                if let Some(active) = port.as_mut() {
                    active.service_label = nmap_service_label(tag);
                }
            }
            "port" if tag.closing => {
                if let (Some(host), Some(active)) = (host, port.take())
                    && let Some(state) = active.state
                {
                    snapshot.ports.insert(
                        (host, active.port),
                        BaselineEntry {
                            state,
                            service_label: active.service_label,
                            confidence: None,
                            advisories: Vec::new(),
                        },
                    );
                }
            }
            _ => {}
        }
    }

    Ok(snapshot)
}

/// Parse any supported baseline file (rayscan JSON report, state file, or Nmap XML).
pub fn load_baseline(path: &Path) -> Result<BaselineSnapshot, AppError> {
    let content = std::fs::read_to_string(path).map_err(|e| {
        AppError::runtime(format!(
            "failed to read baseline diff file {}: {e}",
            path.display()
        ))
    })?;

    let trimmed = content
        .strip_prefix('\u{feff}')
        .unwrap_or(&content)
        .trim_start();
    if trimmed.starts_with('<') {
        return load_nmap_xml(trimmed, path);
    }

    // Try parsing as standard rayscan JSON report
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(&content) {
        let mut snapshot = BaselineSnapshot::default();

        // 1. Parse open or all results
        let default_host = value
            .get("target")
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse::<IpAddr>().ok());

        let results_array = value
            .get("results")
            .and_then(|v| v.as_array())
            .or_else(|| value.get("open").and_then(|v| v.as_array()));
        let looks_like_report = results_array.is_some();
        if looks_like_report && let Some(arr) = results_array {
            for item in arr {
                let host = item
                    .get("host")
                    .and_then(|v| v.as_str())
                    .and_then(|s| s.parse::<IpAddr>().ok())
                    .or(default_host);
                let Some(host) = host else {
                    continue;
                };
                let Some(port) = item.get("port").and_then(|v| v.as_u64()) else {
                    continue;
                };

                let state = item
                    .get("state")
                    .and_then(|v| v.as_str())
                    .and_then(|s| match s {
                        "open" => Some(PortState::Open),
                        "closed" => Some(PortState::Closed),
                        "filtered" => Some(PortState::Filtered),
                        "unfiltered" => Some(PortState::Unfiltered),
                        "silent" => Some(PortState::Silent),
                        "unreachable" => Some(PortState::Unreachable),
                        "error" => Some(PortState::Error),
                        _ => None,
                    })
                    .unwrap_or(PortState::Open);

                let mut service_label = None;
                if let Some(svc) = item.get("service") {
                    if let Some(s_str) = svc.as_str() {
                        let mut label = s_str.to_string();
                        if let Some(p) = item.get("product").and_then(|v| v.as_str()) {
                            label.push(' ');
                            label.push_str(p);
                        }
                        if let Some(v) = item.get("version").and_then(|v| v.as_str()) {
                            label.push('/');
                            label.push_str(v);
                        }
                        if !label.is_empty() {
                            service_label = Some(label);
                        }
                    } else if let Some(obj) = svc.as_object() {
                        let name = obj.get("name").and_then(|v| v.as_str()).unwrap_or("");
                        let product = obj.get("product").and_then(|v| v.as_str());
                        let version = obj.get("version").and_then(|v| v.as_str());
                        let mut label = name.to_string();
                        if let Some(p) = product {
                            label.push(' ');
                            label.push_str(p);
                        }
                        if let Some(v) = version {
                            label.push('/');
                            label.push_str(v);
                        }
                        if !label.is_empty() {
                            service_label = Some(label);
                        }
                    }
                }

                let confidence = item
                    .get("confidence")
                    .and_then(|v| v.as_f64())
                    .map(|f| f as f32);

                let advisories = item
                    .get("advisories")
                    .and_then(|v| v.as_array())
                    .map(|items| {
                        items
                            .iter()
                            .filter_map(|advisory| {
                                let id = advisory.get("id")?.as_str()?.to_string();
                                let severity = advisory
                                    .get("severity")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("unknown")
                                    .to_string();
                                let cvss =
                                    advisory.get("cvss").and_then(|v| v.as_f64()).unwrap_or(0.0)
                                        as f32;
                                Some(AdvisoryRef { id, severity, cvss })
                            })
                            .collect()
                    })
                    .unwrap_or_default();

                snapshot.ports.insert(
                    (host, port as u16),
                    BaselineEntry {
                        state,
                        service_label,
                        confidence,
                        advisories,
                    },
                );
            }
        }

        // 2. Parse defense postures if present
        if let Some(defense_map) = value.get("defense").and_then(|v| v.as_object()) {
            for (h_str, assess) in defense_map {
                if let Ok(host) = h_str.parse::<IpAddr>() {
                    let d_type = assess.get("defense_type").and_then(|v| v.as_str());
                    let conf = assess
                        .get("confidence")
                        .and_then(|v| v.as_f64())
                        .unwrap_or(1.0) as f32;
                    let badge = match d_type {
                        Some("direct_host") | Some("DirectHost") | Some("Direct") => {
                            "[CLEAN] Direct Host"
                        }
                        Some("rate_limiting") | Some("RateLimiting") | Some("RateLimited") => {
                            "[NOTICE] Rate-Limiting Active"
                        }
                        Some("tarpit") | Some("Tarpit") => "[WARNING] TCP Tarpit Active",
                        Some("syn_proxy") | Some("SynProxy") => {
                            "[WARNING] SYN-Proxy Middlebox Detected"
                        }
                        Some("waf_or_dpi") | Some("WafOrDpi") => {
                            "[WARNING] Layer-7 WAF / DPI Detected"
                        }
                        Some("multi_layer_defense") | Some("MultiLayerDefense") => {
                            "[CRITICAL] Heavy Middlebox / Deception Detected"
                        }
                        _ => "[CLEAN] Direct Host",
                    };
                    snapshot
                        .defense_postures
                        .insert(host, (badge.to_string(), conf));
                }
            }
        }

        if !snapshot.ports.is_empty() || looks_like_report {
            return Ok(snapshot);
        }
    }

    // Try parsing as ScanState (--save-state file)
    if let Ok(state) = serde_json::from_str::<ScanState>(&content) {
        let mut snapshot = BaselineSnapshot::default();
        for r in state.results {
            if let Ok(host) = r.host.parse::<IpAddr>() {
                let st = match r.state.as_str() {
                    "open" => PortState::Open,
                    "closed" => PortState::Closed,
                    "filtered" => PortState::Filtered,
                    "unfiltered" => PortState::Unfiltered,
                    "silent" => PortState::Silent,
                    "unreachable" => PortState::Unreachable,
                    "error" => PortState::Error,
                    _ => PortState::Closed,
                };
                snapshot.ports.insert(
                    (host, r.port),
                    BaselineEntry {
                        state: st,
                        service_label: r.service,
                        confidence: None,
                        advisories: Vec::new(),
                    },
                );
            }
        }
        return Ok(snapshot);
    }

    Err(AppError::usage(format!(
        "baseline file {} is not a valid rayscan JSON report, state file, or Nmap XML report",
        path.display()
    )))
}

/// Write a concise diff alert to `path`, creating parent directories as needed.
pub fn write_alert(path: &Path, diff: &ScanDiff) -> Result<(), AppError> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).map_err(|error| {
            AppError::runtime(format!(
                "cannot create alert directory {}: {error}",
                parent.display()
            ))
        })?;
    }
    std::fs::write(path, diff.render_alert())
        .map_err(|error| AppError::runtime(format!("cannot write {}: {error}", path.display())))
}

/// CLI entry point for the standalone `rayscan diff <BASELINE> <CURRENT>` command.
pub fn run_cli(
    args: crate::cli::DiffArgs,
    theme: Option<crate::theme::Theme>,
) -> Result<(), AppError> {
    let base = load_baseline(&args.baseline)?;
    let curr = load_baseline(&args.current)?;
    let diff = ScanDiff::compute_snapshots(
        &args.baseline.display().to_string(),
        &args.current.display().to_string(),
        &base,
        &curr,
    );

    if args.json {
        let json = serde_json::to_string_pretty(&diff)
            .map_err(|e| AppError::runtime(format!("cannot encode JSON diff: {e}")))?;
        println!("{json}");
    } else {
        let stdout_is_tty = std::io::stdout().is_terminal();
        let use_color = crate::theme::color_enabled(theme.unwrap_or_default(), stdout_is_tty);
        print!("{}", diff.render_terminal(use_color));
    }

    if let Some(path) = &args.alert_file {
        write_alert(path, &diff)?;
    }
    if args.fail_on_change && diff.changes_detected() {
        return Err(AppError::silent(1));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::advisory::AdvisoryMatch;
    use crate::model::StateCounts;
    use crate::service::ServiceInfo;
    use std::time::Duration;

    #[test]
    fn alert_text_is_compact_and_marks_no_changes() {
        let empty = ScanDiff {
            baseline_source: "base.json".to_string(),
            current_target: "192.0.2.10".to_string(),
            port_changes: Vec::new(),
            posture_changes: Vec::new(),
            summary: DiffSummary::default(),
        };
        assert!(!empty.changes_detected());
        let alert = empty.render_alert();
        assert!(alert.contains("status: no changes"));
        assert!(!alert.contains("[+] NEW"));

        let host: IpAddr = "192.0.2.10".parse().unwrap();
        let changed = ScanDiff {
            baseline_source: "base.json".to_string(),
            current_target: "192.0.2.10".to_string(),
            port_changes: vec![PortChange {
                host,
                port: 8080,
                kind: ChangeKind::New,
                old_state: None,
                new_state: Some(PortState::Open),
                old_service: None,
                new_service: Some("http nginx/1.24".to_string()),
                old_confidence: None,
                new_confidence: Some(1.0),
                new_advisories: Vec::new(),
                resolved_advisories: Vec::new(),
                summary: "http nginx/1.24 (Confidence: 100%)".to_string(),
            }],
            posture_changes: Vec::new(),
            summary: DiffSummary {
                new_ports: 1,
                ..Default::default()
            },
        };
        assert!(changed.changes_detected());
        let alert = changed.render_alert();
        assert!(alert.contains("status: changes detected"));
        assert!(alert.contains("[+] NEW 192.0.2.10:8080"));
        assert!(alert.contains("new: 1"));
    }

    #[test]
    fn detects_new_and_gone_and_modified_ports() {
        let host: IpAddr = "192.168.1.10".parse().unwrap();

        // Baseline has: port 21 (open vsftpd), port 22 (open OpenSSH 7.4)
        let mut baseline = BaselineSnapshot::default();
        baseline.ports.insert(
            (host, 21),
            BaselineEntry {
                state: PortState::Open,
                service_label: Some("ftp vsftpd/2.3.4".to_string()),
                confidence: Some(1.0),
                advisories: Vec::new(),
            },
        );
        baseline.ports.insert(
            (host, 22),
            BaselineEntry {
                state: PortState::Open,
                service_label: Some("ssh OpenSSH/7.4".to_string()),
                confidence: Some(1.0),
                advisories: Vec::new(),
            },
        );

        // Current report has: port 22 (open OpenSSH 8.9), port 80 (open Apache), port 21 (closed)
        let mut r22 = PortResult::new(host, 22, PortState::Open, Duration::from_millis(2));
        r22.service = Some(ServiceInfo {
            name: "ssh".to_string(),
            product: Some("OpenSSH".to_string()),
            version: Some("8.9".to_string()),
            confidence: Some(0.98),
            ..Default::default()
        });
        r22.confidence = Some(1.0);

        let mut r80 = PortResult::new(host, 80, PortState::Open, Duration::from_millis(1));
        r80.service = Some(ServiceInfo {
            name: "http".to_string(),
            product: Some("Apache".to_string()),
            version: Some("2.4.52".to_string()),
            confidence: Some(0.98),
            ..Default::default()
        });
        r80.confidence = Some(0.95);

        let r21 = PortResult::new(host, 21, PortState::Closed, Duration::from_millis(1));

        let report = ScanReport {
            targets: 1,
            ports: 3,
            jobs: 3,
            workers: 2,
            elapsed: Duration::from_millis(100),
            counts: StateCounts {
                open: 2,
                closed: 1,
                ..Default::default()
            },
            results: vec![r21, r22, r80],
            os_fingerprints: HashMap::new(),
            probed_ports: vec![21, 22, 80],
            host_progress: Default::default(),
            partial: false,
            defense_observations: Vec::new(),
        };

        let diff = ScanDiff::compute("baseline.json", "192.168.1.10", &baseline, &report);

        assert_eq!(diff.summary.new_ports, 1); // Port 80
        assert_eq!(diff.summary.gone_ports, 1); // Port 21
        assert_eq!(diff.summary.modified_ports, 1); // Port 22 service changed

        let rendered = diff.render_terminal(false);
        assert!(rendered.contains("[+] NEW"));
        assert!(rendered.contains("192.168.1.10:80"));
        assert!(rendered.contains("[-] GONE"));
        assert!(rendered.contains("192.168.1.10:21"));
        assert!(rendered.contains("[*] CHANGED"));
        assert!(rendered.contains("OpenSSH/7.4 → ssh OpenSSH/8.9"));
    }

    #[test]
    fn advisory_changes_are_reported_and_counted() {
        let host: IpAddr = "192.0.2.5".parse().unwrap();
        let mut baseline = BaselineSnapshot::default();
        baseline.ports.insert(
            (host, 443),
            BaselineEntry {
                state: PortState::Open,
                service_label: Some("https nginx/1.18.0".to_string()),
                confidence: Some(1.0),
                advisories: vec![AdvisoryRef {
                    id: "CVE-2021-0001".to_string(),
                    severity: "medium".to_string(),
                    cvss: 5.0,
                }],
            },
        );

        let mut result = PortResult::new(host, 443, PortState::Open, Duration::from_millis(1));
        result.service = Some(ServiceInfo {
            name: "https".to_string(),
            product: Some("nginx".to_string()),
            version: Some("1.18.0".to_string()),
            confidence: Some(0.98),
            ..Default::default()
        });
        result.confidence = Some(1.0);
        result.advisories = vec![
            AdvisoryMatch {
                id: "CVE-2021-0001".to_string(),
                title: "rescored".to_string(),
                severity: crate::advisory::Severity::High,
                cvss: 8.1,
                cisa_kev: false,
                epss: None,
                source: "nvd",
            },
            AdvisoryMatch {
                id: "CVE-2024-9999".to_string(),
                title: "new critical issue".to_string(),
                severity: crate::advisory::Severity::Critical,
                cvss: 9.8,
                cisa_kev: true,
                epss: Some(0.95),
                source: "nvd",
            },
        ];

        let report = ScanReport {
            targets: 1,
            ports: 1,
            jobs: 1,
            workers: 1,
            elapsed: Duration::from_millis(5),
            counts: StateCounts {
                open: 1,
                ..Default::default()
            },
            results: vec![result],
            os_fingerprints: HashMap::new(),
            probed_ports: vec![443],
            host_progress: Default::default(),
            partial: false,
            defense_observations: Vec::new(),
        };

        let diff = ScanDiff::compute("baseline.json", "192.0.2.5", &baseline, &report);
        assert_eq!(diff.summary.modified_ports, 1);
        assert_eq!(diff.summary.critical_advisories, 1);
        let change = &diff.port_changes[0];
        assert_eq!(change.kind, ChangeKind::AdvisoryChanged);
        assert_eq!(change.new_advisories.len(), 2);
        assert_eq!(change.resolved_advisories.len(), 1);
        let rendered = diff.render_terminal(false);
        assert!(rendered.contains("advisories +2 -1"));
        assert!(rendered.contains("New critical advisories: 1"));
    }

    #[test]
    fn nmap_xml_baseline_imports_tcp_ports_and_services() {
        let path =
            std::env::temp_dir().join(format!("rayscan-nmap-baseline-{}.xml", std::process::id()));
        std::fs::write(
            &path,
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sS 192.0.2.0/24" start="1" version="7.94" xmloutputversion="1.05">
  <host starttime="1" endtime="2">
    <status state="up" reason="syn-ack"/>
    <address addr="AA:BB:CC:DD:EE:FF" addrtype="mac"/>
    <address addr="192.0.2.10" addrtype="ipv4"/>
    <ports>
      <extraports state="closed" count="997"/>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack" reason_ttl="64"/>
        <service name="ssh" product="OpenSSH" version="8.9p1" method="probed" conf="10"/>
      </port>
      <port protocol="tcp" portid="8080">
        <state state="open|filtered" reason="no-response" reason_ttl="0"/>
        <service name="http" product="Caddy &amp; Co" version="2.7.6"/>
      </port>
      <port protocol="udp" portid="53">
        <state state="open" reason="udp-response"/>
        <service name="domain"/>
      </port>
    </ports>
  </host>
  <host starttime="1" endtime="2">
    <address addr="2001:db8::10" addrtype="ipv6"/>
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open" reason="syn-ack"/>
        <service name="https" product="nginx" version="1.24.0"/>
      </port>
    </ports>
  </host>
  <runstats><finished time="2" elapsed="1.00"/></runstats>
</nmaprun>"#,
        )
        .expect("write Nmap XML baseline");

        let snapshot = load_baseline(&path).expect("Nmap XML must load");
        assert_eq!(snapshot.ports.len(), 3);

        let host: IpAddr = "192.0.2.10".parse().unwrap();
        let ssh = snapshot.ports.get(&(host, 22)).expect("port 22");
        assert_eq!(ssh.state, PortState::Open);
        assert_eq!(ssh.service_label.as_deref(), Some("ssh OpenSSH/8.9p1"));
        assert_eq!(ssh.confidence, None);

        let filtered = snapshot.ports.get(&(host, 8080)).expect("port 8080");
        assert_eq!(filtered.state, PortState::Filtered);
        assert_eq!(
            filtered.service_label.as_deref(),
            Some("http Caddy & Co/2.7.6")
        );

        let ipv6: IpAddr = "2001:db8::10".parse().unwrap();
        let https = snapshot.ports.get(&(ipv6, 443)).expect("port 443");
        assert_eq!(https.state, PortState::Open);
        assert_eq!(https.service_label.as_deref(), Some("https nginx/1.24.0"));
        assert!(!snapshot.ports.contains_key(&(host, 53)));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn rejects_xml_that_is_not_an_nmap_report() {
        let path = std::env::temp_dir().join(format!(
            "rayscan-invalid-nmap-baseline-{}.xml",
            std::process::id()
        ));
        std::fs::write(
            &path,
            r#"<report><host><address addr="192.0.2.10" addrtype="ipv4"/></host></report>"#,
        )
        .expect("write invalid XML baseline");
        let error = load_baseline(&path).expect_err("non-Nmap XML must fail");
        assert!(error.to_string().contains("Nmap XML"));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn empty_json_report_is_a_valid_baseline() {
        let path = std::env::temp_dir().join(format!(
            "rayscan-empty-baseline-{}.json",
            std::process::id()
        ));
        std::fs::write(
            &path,
            r#"{"target":"192.0.2.1","targets":1,"ports":2,"jobs":2,"workers":2,"open":[],"summary":{"open":0,"closed":2,"filtered":0,"silent":0,"unreachable":0,"error":0},"elapsed_ms":1.0}"#,
        )
        .expect("write empty baseline");
        let snapshot = load_baseline(&path).expect("empty report must load");
        assert!(snapshot.ports.is_empty());
        let _ = std::fs::remove_file(&path);
    }
}
