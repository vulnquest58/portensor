//! Offline vulnerability advisory correlation.
//!
//! Matches detected service identity (product name, version, and optional
//! banner context) against two sources:
//!
//! 1. the local NVD database maintained by `rayscan db update` (see
//!    [`crate::db`]), which covers all CVE years through the current year; and
//! 2. a small bundled curated database in `data/advisories.json` that adds
//!    context-sensitive mappings (for example Debian/Ubuntu SSH banners).
//!
//! Correlation is advisory only: confirm findings against current vendor
//! advisories before acting.

use std::cmp::Ordering;
use std::collections::HashMap;
use std::sync::{OnceLock, RwLock};

use serde::{Deserialize, Serialize};

use crate::db::LocalIndex;
use crate::model::{PortResult, PortState, ScanReport};

const DATABASE_JSON: &str = include_str!("../data/advisories.json");
const CISA_KEV_JSON: &str = include_str!("../data/cisa_kev.json");

/// One bundled or downloaded threat-intelligence record.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
pub struct ThreatIntelEntry {
    pub id: String,
    #[serde(default)]
    pub cisa_kev: bool,
    #[serde(default)]
    pub epss: Option<f32>,
}

/// A threat-intelligence indicator for one CVE.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
pub struct ThreatIndicator {
    pub cisa_kev: bool,
    pub epss: Option<f32>,
}

type ThreatIntelTable = HashMap<String, ThreatIndicator>;

fn threat_intel() -> &'static RwLock<ThreatIntelTable> {
    static THREAT_INTEL: OnceLock<RwLock<ThreatIntelTable>> = OnceLock::new();
    THREAT_INTEL.get_or_init(|| RwLock::new(bundled_threat_intel()))
}

fn bundled_threat_intel() -> ThreatIntelTable {
    let entries: Vec<ThreatIntelEntry> = serde_json::from_str(CISA_KEV_JSON).unwrap_or_default();
    entries
        .into_iter()
        .map(|entry| {
            (
                entry.id,
                ThreatIndicator {
                    cisa_kev: entry.cisa_kev,
                    epss: entry.epss,
                },
            )
        })
        .collect()
}

/// Return the small curated threat-intelligence set compiled into the binary.
pub fn bundled_threat_intel_entries() -> Vec<ThreatIntelEntry> {
    serde_json::from_str(CISA_KEV_JSON).unwrap_or_default()
}

/// Merge downloaded threat intelligence into the process-wide lookup table.
///
/// Bundled entries remain available for CVEs absent from the downloaded feed.
/// Reinstalling an overlay simply replaces indicator values for matching CVEs.
pub fn install_threat_intel(entries: impl IntoIterator<Item = ThreatIntelEntry>) {
    let mut table = threat_intel()
        .write()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    for entry in entries {
        table.insert(
            entry.id,
            ThreatIndicator {
                cisa_kev: entry.cisa_kev,
                epss: entry.epss,
            },
        );
    }
}

/// Lookup threat intelligence indicators (CISA KEV membership and FIRST.org EPSS score).
pub fn lookup_threat_intel(cve_id: &str) -> (bool, Option<f32>) {
    threat_intel()
        .read()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .get(cve_id)
        .map(|indicator| (indicator.cisa_kev, indicator.epss))
        .unwrap_or((false, None))
}

/// Qualitative severity derived from the advisory's CVSS score.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub const fn from_cvss(cvss: f32) -> Self {
        if cvss >= 9.0 {
            Self::Critical
        } else if cvss >= 7.0 {
            Self::High
        } else if cvss >= 4.0 {
            Self::Medium
        } else {
            Self::Low
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::Critical => "CRITICAL",
            Self::High => "HIGH",
            Self::Medium => "MEDIUM",
            Self::Low => "LOW",
        }
    }
}

/// One advisory matched to a port result.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct AdvisoryMatch {
    pub id: String,
    pub title: String,
    pub severity: Severity,
    pub cvss: f32,
    #[serde(default)]
    pub cisa_kev: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub epss: Option<f32>,
    /// Where the match came from: `curated` or `nvd`.
    pub source: String,
    /// Confidence in the advisory match after combining evidence quality with
    /// the detected service identification confidence.
    #[serde(default)]
    pub confidence: f32,
    /// Match basis: `curated`, `exact_version`, `version_range`, or
    /// `all_versions`.
    #[serde(default)]
    pub evidence: String,
}

#[derive(Clone, Debug, Deserialize)]
struct Advisory {
    id: String,
    title: String,
    cvss: f32,
    #[serde(default)]
    products: Vec<String>,
    #[serde(default)]
    version: VersionRule,
    #[serde(default)]
    banner_any: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum VersionRule {
    #[default]
    Any,
    Eq {
        value: String,
    },
    Lt {
        value: String,
    },
    Range {
        #[serde(default)]
        min: Option<String>,
        #[serde(default)]
        max_exclusive: Option<String>,
    },
}

impl VersionRule {
    fn matches(&self, detected: Option<&Version>) -> bool {
        let Some(detected) = detected else {
            return matches!(self, Self::Any);
        };
        match self {
            Self::Any => true,
            Self::Eq { value } => parse_version(value).is_some_and(|rule| detected == &rule),
            Self::Lt { value } => parse_version(value).is_some_and(|rule| detected < &rule),
            Self::Range { min, max_exclusive } => {
                let above_min = match min {
                    Some(value) => parse_version(value).is_some_and(|rule| detected >= &rule),
                    None => true,
                };
                let below_max = match max_exclusive {
                    Some(value) => parse_version(value).is_some_and(|rule| detected < &rule),
                    None => true,
                };
                above_min && below_max
            }
        }
    }
}

impl Advisory {
    fn matches(
        &self,
        identities: &[String],
        version: Option<&Version>,
        banner: Option<&str>,
    ) -> bool {
        if self.products.is_empty()
            || !self
                .products
                .iter()
                .any(|product| identities.iter().any(|identity| identity == product))
        {
            return false;
        }

        if !self.version.matches(version) {
            return false;
        }

        if self.banner_any.is_empty() {
            return true;
        }
        let Some(banner) = banner else {
            return false;
        };
        self.banner_any
            .iter()
            .any(|term| banner.contains(term.as_str()))
    }
}

fn database() -> &'static [Advisory] {
    static DATABASE: OnceLock<Vec<Advisory>> = OnceLock::new();
    DATABASE.get_or_init(|| serde_json::from_str(DATABASE_JSON).unwrap_or_default())
}

/// Correlate a single port result with the bundled advisory database.
pub fn correlate(result: &PortResult) -> Vec<AdvisoryMatch> {
    correlate_with(result, None)
}

/// Correlate a single port result with the bundled and local databases.
///
/// Only open results that carry service metadata are evaluated.  Matches are
/// deduplicated by CVE identifier (curated entries take precedence) and
/// ordered with curated findings first, then by severity (critical first) and
/// advisory identifier within each source.
pub fn correlate_with(result: &PortResult, index: Option<&LocalIndex>) -> Vec<AdvisoryMatch> {
    if result.state != PortState::Open {
        return Vec::new();
    }
    let Some(service) = &result.service else {
        return Vec::new();
    };

    let mut identities = Vec::with_capacity(2);
    identities.push(service.name.to_ascii_lowercase());
    if let Some(product) = &service.product {
        identities.push(product.to_ascii_lowercase());
    }

    let service_confidence = service_identity_confidence(service);
    let cpe = service.cpe.as_deref().and_then(crate::db::parse_cpe);
    let cpe_version = cpe
        .as_ref()
        .and_then(|(_, version)| version.as_deref())
        .and_then(parse_version);
    let version = service
        .version
        .as_deref()
        .and_then(parse_version)
        .or(cpe_version);
    let banner = result.banner.as_deref().map(str::to_ascii_lowercase);

    let mut matches: Vec<AdvisoryMatch> = database()
        .iter()
        .filter(|advisory| advisory.matches(&identities, version.as_ref(), banner.as_deref()))
        .map(|advisory| {
            let (cisa_kev, epss) = lookup_threat_intel(&advisory.id);
            AdvisoryMatch {
                id: advisory.id.clone(),
                title: advisory.title.clone(),
                severity: Severity::from_cvss(advisory.cvss),
                cvss: advisory.cvss,
                cisa_kev,
                epss,
                source: "curated".to_string(),
                confidence: match_confidence(CURATED_MATCH_CONFIDENCE, service_confidence),
                evidence: "curated".to_string(),
            }
        })
        .collect();

    if let Some(index) = index {
        let found = if let Some((identity, _)) = &cpe {
            // A plugin-supplied CPE is an exact identity; do not broaden it
            // through the product alias table.
            index.advisories_for_identity(&identity.vendor, &identity.product, version.as_ref())
        } else if let Some(product) = service.product.as_deref() {
            index.advisories_for(product, version.as_ref())
        } else {
            Vec::new()
        };
        for mut advisory in found {
            advisory.confidence = match_confidence(advisory.confidence, service_confidence);
            if !matches.iter().any(|existing| existing.id == advisory.id) {
                matches.push(advisory);
            }
        }
    }

    // Low-confidence all-version NVD entries are a common source of noise when
    // the service identity is weak.  Keep only matches with enough combined
    // identification and evidence confidence.
    matches.retain(|advisory| advisory.confidence >= MIN_ADVISORY_CONFIDENCE);
    sort_matches(&mut matches);
    matches
}

const CURATED_MATCH_CONFIDENCE: f32 = 0.99;
const MIN_ADVISORY_CONFIDENCE: f32 = 0.55;

fn service_identity_confidence(service: &crate::service::ServiceInfo) -> f32 {
    service
        .confidence
        .filter(|confidence| confidence.is_finite())
        .map(|confidence| confidence.clamp(0.0, 1.0))
        .unwrap_or(if service.cpe.is_some() || service.product.is_some() {
            0.85
        } else {
            0.70
        })
}

fn match_confidence(evidence_confidence: f32, service_confidence: f32) -> f32 {
    ((evidence_confidence * service_confidence * 100.0).round() / 100.0).clamp(0.0, 1.0)
}

fn sort_matches(matches: &mut [AdvisoryMatch]) {
    matches.sort_by(|left, right| {
        let rank = |source: &str| u8::from(source != "curated");
        rank(left.source.as_str())
            .cmp(&rank(right.source.as_str()))
            .then_with(|| right.severity.cmp(&left.severity))
            .then_with(|| left.id.cmp(&right.id))
    });
}

/// Correlate every open service in a scan report.
pub fn apply_advisories(report: &mut ScanReport) {
    apply_advisories_with(report, None);
}

/// Correlate every open service against both advisory sources.
pub fn apply_advisories_with(report: &mut ScanReport, index: Option<&LocalIndex>) {
    for result in &mut report.results {
        result.advisories = correlate_with(result, index);
    }
}

/// Filter advisory findings according to CISA KEV presence and minimum EPSS threshold.
pub fn filter_advisories(report: &mut ScanReport, kev_only: bool, min_epss: Option<f32>) {
    if !kev_only && min_epss.is_none() {
        return;
    }
    for result in &mut report.results {
        result.advisories.retain(|adv| {
            if kev_only && !adv.cisa_kev {
                return false;
            }
            if let Some(threshold) = min_epss
                && !adv.epss.is_some_and(|score| score >= threshold)
            {
                return false;
            }
            true
        });
    }
}

/// Normalized version with numeric and alphabetic tokens.
///
/// Numeric segments compare numerically, alphabetic suffixes compare
/// lexically, and common prerelease markers (`rc`, `beta`, ...) sort before
/// the final release.  This preserves information that the previous
/// numeric-only parser discarded, such as the `p1` in `4.7p1` or the `u` in
/// `1.0.2u`, while still treating `2.3` and `2.3.0` as equivalent.
#[derive(Clone, Debug)]
pub(crate) struct Version {
    tokens: Vec<VersionToken>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum VersionToken {
    Number(u64),
    /// A prerelease marker separated from the release by punctuation (for
    /// example `1.0.0-rc1`) or a recognized attached marker such as `rc2`.
    Text(String),
    /// An attached alphabetic release suffix such as `4.7p1`, `1.0.2u`, or
    /// `2.4.49c`. These sort after the bare release.
    Suffix(String),
}

fn is_prerelease_marker(text: &str) -> bool {
    matches!(
        text,
        "alpha" | "beta" | "rc" | "pre" | "preview" | "dev" | "snapshot" | "nightly" | "milestone"
    )
}

impl PartialEq for Version {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for Version {}

impl PartialOrd for Version {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Version {
    fn cmp(&self, other: &Self) -> Ordering {
        let common = self.tokens.len().min(other.tokens.len());
        for index in 0..common {
            let ordering = match (&self.tokens[index], &other.tokens[index]) {
                (VersionToken::Number(left), VersionToken::Number(right)) => left.cmp(right),
                (VersionToken::Text(left), VersionToken::Text(right)) => left.cmp(right),
                (VersionToken::Suffix(left), VersionToken::Suffix(right)) => left.cmp(right),
                (VersionToken::Text(_), VersionToken::Suffix(_)) => Ordering::Less,
                (VersionToken::Suffix(_), VersionToken::Text(_)) => Ordering::Greater,
                (VersionToken::Text(_) | VersionToken::Suffix(_), VersionToken::Number(_)) => {
                    Ordering::Less
                }
                (VersionToken::Number(_), VersionToken::Text(_) | VersionToken::Suffix(_)) => {
                    Ordering::Greater
                }
            };
            if ordering != Ordering::Equal {
                return ordering;
            }
        }

        if self.tokens.len() == other.tokens.len() {
            return Ordering::Equal;
        }

        let (left_longer, longer, shorter_len) = if self.tokens.len() > other.tokens.len() {
            (true, self, other.tokens.len())
        } else {
            (false, other, self.tokens.len())
        };
        let first_extra = &longer.tokens[shorter_len];
        let extra_is_release = matches!(
            first_extra,
            VersionToken::Number(_) | VersionToken::Suffix(_)
        );
        match (left_longer, extra_is_release) {
            (true, true) => Ordering::Greater,
            (true, false) => Ordering::Less,
            (false, true) => Ordering::Less,
            (false, false) => Ordering::Greater,
        }
    }
}

const MAX_VERSION_TOKENS: usize = 32;
const MAX_VERSION_TOKEN_CHARS: usize = 64;
const MAX_VERSION_CHARS: usize = 256;

pub(crate) fn parse_version(version: &str) -> Option<Version> {
    let mut text = version.trim();
    if text.is_empty() || text.len() > MAX_VERSION_CHARS || text.contains('*') || text.contains('?')
    {
        return None;
    }
    if text.starts_with('v') || text.starts_with('V') {
        let rest = &text[1..];
        if rest.as_bytes().first().is_some_and(u8::is_ascii_digit) {
            text = rest;
        }
    }

    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut current_is_digit: Option<bool> = None;
    let mut current_attached = false;
    let mut previous_was_alphanumeric = false;
    for character in text.chars() {
        if character.is_ascii_alphanumeric() {
            let is_digit = character.is_ascii_digit();
            if let Some(previous) = current_is_digit
                && previous != is_digit
            {
                push_version_token(&mut tokens, &mut current, previous, current_attached)?;
            }
            if current.is_empty() {
                current_attached = previous_was_alphanumeric;
            }
            current_is_digit = Some(is_digit);
            current.push(character.to_ascii_lowercase());
            if current.len() > MAX_VERSION_TOKEN_CHARS {
                return None;
            }
            previous_was_alphanumeric = true;
        } else {
            if let Some(previous) = current_is_digit.take() {
                push_version_token(&mut tokens, &mut current, previous, current_attached)?;
            }
            previous_was_alphanumeric = false;
        }
    }
    if let Some(previous) = current_is_digit {
        push_version_token(&mut tokens, &mut current, previous, current_attached)?;
    }

    if tokens.len() > MAX_VERSION_TOKENS || !matches!(tokens.first(), Some(VersionToken::Number(_)))
    {
        return None;
    }
    while tokens.len() > 1 && matches!(tokens.last(), Some(VersionToken::Number(0))) {
        tokens.pop();
    }
    let raw = std::mem::take(&mut tokens);
    let mut index = 0;
    while index < raw.len() {
        if index > 0 && matches!(raw[index], VersionToken::Number(0)) {
            let start = index;
            let mut end = index;
            while end < raw.len() && matches!(raw[end], VersionToken::Number(0)) {
                end += 1;
            }
            if end < raw.len()
                && matches!(raw[end], VersionToken::Text(_) | VersionToken::Suffix(_))
            {
                index = end;
                continue;
            }
            tokens.extend_from_slice(&raw[start..start + 1]);
            index += 1;
            continue;
        }
        tokens.push(raw[index].clone());
        index += 1;
    }
    Some(Version { tokens })
}

fn push_version_token(
    tokens: &mut Vec<VersionToken>,
    current: &mut String,
    is_digit: bool,
    attached: bool,
) -> Option<()> {
    if is_digit {
        tokens.push(VersionToken::Number(current.parse().ok()?));
    } else if attached && !is_prerelease_marker(current) {
        tokens.push(VersionToken::Suffix(std::mem::take(current)));
    } else {
        tokens.push(VersionToken::Text(std::mem::take(current)));
    }
    current.clear();
    Some(())
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;
    use std::time::Duration;

    use super::*;
    use crate::db::{AffectedProduct, DbPaths, Manifest, StoredEntry, VersionRange};
    use crate::service::ServiceInfo;

    struct TempDb {
        paths: DbPaths,
    }

    impl TempDb {
        fn new(name: &str) -> Self {
            let root = std::env::temp_dir().join(format!(
                "rayscan-advisory-{name}-{}-{}",
                std::process::id(),
                crate::db::now_unix()
            ));
            let _ = std::fs::remove_dir_all(&root);
            std::fs::create_dir_all(&root).unwrap();
            Self {
                paths: DbPaths::at(root),
            }
        }
    }

    impl Drop for TempDb {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.paths.root);
        }
    }

    fn exact_range(version: &str) -> VersionRange {
        VersionRange {
            start_incl: Some(version.to_string()),
            start_excl: None,
            end_incl: Some(version.to_string()),
            end_excl: None,
        }
    }

    fn nvd_entry(
        id: &str,
        vendor: &str,
        product: &str,
        all_versions: bool,
        ranges: Vec<VersionRange>,
    ) -> StoredEntry {
        StoredEntry {
            id: id.to_string(),
            title: format!("{id} title"),
            cvss: 9.8,
            affected: vec![AffectedProduct {
                vendor: vendor.to_string(),
                product: product.to_string(),
                all_versions,
                ranges,
            }],
        }
    }

    fn install_nvd(name: &str, entries: &[StoredEntry]) -> (TempDb, LocalIndex) {
        let db = TempDb::new(name);
        let state = crate::db::index::write_year(&db.paths, 2024, entries).unwrap();
        let mut manifest = Manifest {
            schema: crate::db::SCHEMA_VERSION,
            ..Manifest::default()
        };
        manifest.years.insert(2024, state);
        manifest.cve_count = entries.len() as u64;
        manifest.entry_count = entries
            .iter()
            .map(|entry| entry.affected.len() as u64)
            .sum();
        crate::db::save_manifest(&db.paths, &manifest).unwrap();
        let index = LocalIndex::load(&db.paths).expect("index loads");
        (db, index)
    }

    fn sample(
        name: &str,
        product: Option<&str>,
        version: Option<&str>,
        banner: Option<&str>,
    ) -> PortResult {
        let host: IpAddr = "192.168.100.37".parse().unwrap();
        let mut result = PortResult::new(host, 21, PortState::Open, Duration::from_millis(3));
        result.service = Some(ServiceInfo {
            name: name.to_string(),
            product: product.map(str::to_string),
            version: version.map(str::to_string),
            confidence: None,
            ..Default::default()
        });
        result.banner = banner.map(str::to_string);
        result
    }

    #[test]
    fn bundled_database_loads() {
        assert!(!database().is_empty(), "bundled advisory DB must parse");
    }

    #[test]
    fn matches_vsftpd_backdoor() {
        let result = sample(
            "ftp",
            Some("vsFTPd"),
            Some("2.3.4"),
            Some("220 (vsFTPd 2.3.4)"),
        );
        let matches = correlate(&result);
        assert!(matches.iter().any(|m| m.id == "CVE-2011-2523"));
        assert_eq!(matches[0].severity, Severity::Critical);
        assert_eq!(matches[0].source, "curated");
        assert_eq!(matches[0].evidence, "curated");
        assert!(matches[0].confidence >= 0.8);
    }

    #[test]
    fn patched_vsftpd_is_clean() {
        let result = sample("ftp", Some("vsFTPd"), Some("3.0.5"), None);
        assert!(correlate(&result).is_empty());
    }

    #[test]
    fn debian_openssh_prng_requires_debian_or_ubuntu_banner() {
        let debian = sample(
            "ssh",
            Some("OpenSSH"),
            Some("4.7p1"),
            Some("SSH-2.0-OpenSSH_4.7p1 Debian-8ubuntu1"),
        );
        assert!(correlate(&debian).iter().any(|m| m.id == "CVE-2008-0166"));

        let upstream = sample(
            "ssh",
            Some("OpenSSH"),
            Some("4.7p1"),
            Some("SSH-2.0-OpenSSH_4.7p1"),
        );
        assert!(!correlate(&upstream).iter().any(|m| m.id == "CVE-2008-0166"));
    }

    #[test]
    fn apache_coyote_does_not_match_httpd_advisories() {
        let result = sample(
            "http",
            Some("Apache-Coyote"),
            Some("1.1"),
            Some("HTTP/1.1 200 OK"),
        );
        assert!(correlate(&result).is_empty());
    }

    #[test]
    fn apache_228_matches_slowloris_and_range_dos() {
        let result = sample(
            "http",
            Some("Apache"),
            Some("2.2.8"),
            Some("HTTP/1.1 200 OK"),
        );
        let ids: Vec<String> = correlate(&result).into_iter().map(|m| m.id).collect();
        assert!(ids.contains(&"CVE-2007-6750".to_string()));
        assert!(ids.contains(&"CVE-2011-3192".to_string()));
    }

    #[test]
    fn modern_apache_is_clean() {
        let result = sample(
            "http",
            Some("Apache"),
            Some("2.4.62"),
            Some("HTTP/1.1 200 OK"),
        );
        assert!(correlate(&result).is_empty());
    }

    #[test]
    fn plugin_cpe_identity_enables_nvd_matches_without_product() {
        let entries = vec![nvd_entry(
            "CVE-2024-9000",
            "redis",
            "redis",
            false,
            vec![exact_range("7.0.0")],
        )];
        let (_db, index) = install_nvd("cpe-identity", &entries);

        let mut result = sample("redis", None, Some("7.0.0"), None);
        let service = result.service.as_mut().unwrap();
        service.cpe = Some("cpe:2.3:a:redis:redis".to_string());
        service.confidence = Some(0.98);

        let matches = correlate_with(&result, Some(&index));
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].id, "CVE-2024-9000");
        assert_eq!(matches[0].source, "nvd");
        assert_eq!(matches[0].evidence, "exact_version");
        assert_eq!(matches[0].confidence, 0.88);
    }

    #[test]
    fn plugin_cpe_vendor_prevents_alias_false_positives() {
        let entries = vec![nvd_entry(
            "CVE-2024-9001",
            "apache",
            "http_server",
            false,
            vec![exact_range("9.9")],
        )];
        let (_db, index) = install_nvd("cpe-vendor", &entries);

        let mut result = sample("http", Some("Apache"), Some("9.9"), None);
        let service = result.service.as_mut().unwrap();
        service.cpe = Some("cpe:2.3:a:oracle:http_server".to_string());
        service.confidence = Some(0.98);

        assert!(correlate_with(&result, Some(&index)).is_empty());
    }

    #[test]
    fn low_confidence_all_version_matches_are_suppressed() {
        let entries = vec![nvd_entry(
            "CVE-2024-9002",
            "redis",
            "redis",
            true,
            Vec::new(),
        )];
        let (_db, index) = install_nvd("all-versions", &entries);

        let mut product_only = sample("redis", Some("Redis"), None, None);
        let service = product_only.service.as_mut().unwrap();
        service.cpe = Some("cpe:2.3:a:redis:redis".to_string());
        service.confidence = Some(0.85);
        assert!(correlate_with(&product_only, Some(&index)).is_empty());

        let mut versioned = sample("redis", Some("Redis"), Some("7.0"), None);
        let service = versioned.service.as_mut().unwrap();
        service.cpe = Some("cpe:2.3:a:redis:redis".to_string());
        service.confidence = Some(0.98);
        let matches = correlate_with(&versioned, Some(&index));
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].evidence, "all_versions");
        assert_eq!(matches[0].confidence, 0.59);
    }

    #[test]
    fn curated_matches_rank_before_nvd_matches() {
        let mut matches = vec![
            AdvisoryMatch {
                id: "CVE-2024-0002".to_string(),
                title: "nvd critical".to_string(),
                severity: Severity::Critical,
                cvss: 9.8,
                cisa_kev: false,
                epss: None,
                source: "nvd".to_string(),
                confidence: 0.88,
                evidence: "exact_version".to_string(),
            },
            AdvisoryMatch {
                id: "CVE-2024-0001".to_string(),
                title: "curated medium".to_string(),
                severity: Severity::Medium,
                cvss: 5.0,
                cisa_kev: false,
                epss: None,
                source: "curated".to_string(),
                confidence: 0.9,
                evidence: "curated".to_string(),
            },
        ];
        sort_matches(&mut matches);
        assert_eq!(matches[0].source, "curated");
        assert_eq!(matches[1].source, "nvd");
    }

    #[test]
    fn version_parsing_preserves_patch_and_prerelease_semantics() {
        let base = parse_version("4.7").unwrap();
        let patch = parse_version("4.7p1").unwrap();
        assert!(patch > base);
        assert_eq!(patch, parse_version("4.7p1").unwrap());
        assert!(parse_version("4.7p2").unwrap() > patch);
        assert_ne!(base, patch);

        assert_eq!(parse_version("2.3"), parse_version("2.3.0"));
        assert!(parse_version("1.10").unwrap() > parse_version("1.9").unwrap());
        assert!(parse_version("2.4.49c").unwrap() > parse_version("2.4.49").unwrap());
        assert!(parse_version("1.0.0-rc1").unwrap() < parse_version("1.0.0").unwrap());
        assert_eq!(parse_version("v1.2.3"), parse_version("1.2.3"));
        assert_eq!(parse_version("garbage"), None);
        assert_eq!(parse_version("1.0.*"), None);
        assert!(parse_version("5.0.51a-3ubuntu5").is_some());
    }

    #[test]
    fn malformed_range_bounds_do_not_widen_matches() {
        let detected = parse_version("9.0").unwrap();
        let rule = VersionRule::Range {
            min: Some("garbage".to_string()),
            max_exclusive: None,
        };
        assert!(!rule.matches(Some(&detected)));
        let rule = VersionRule::Range {
            min: None,
            max_exclusive: Some("garbage".to_string()),
        };
        assert!(!rule.matches(Some(&detected)));
    }

    #[test]
    fn apply_advisories_annotates_only_open_services() {
        let host: IpAddr = "192.168.100.37".parse().unwrap();
        let mut ftp = sample("ftp", Some("vsFTPd"), Some("2.3.4"), None);
        ftp.port = 21;
        let mut closed = PortResult::new(host, 22, PortState::Closed, Duration::from_millis(1));
        closed.service = Some(ServiceInfo {
            name: "ssh".to_string(),
            product: Some("OpenSSH".to_string()),
            version: Some("4.7p1".to_string()),
            confidence: Some(0.98),
            ..Default::default()
        });

        let mut report = ScanReport {
            targets: 1,
            ports: 2,
            jobs: 2,
            workers: 1,
            elapsed: Duration::from_millis(10),
            counts: crate::model::StateCounts {
                open: 1,
                closed: 1,
                ..Default::default()
            },
            results: vec![ftp, closed],
            os_fingerprints: std::collections::HashMap::new(),
            probed_ports: vec![21, 22],
            host_progress: Default::default(),
            partial: false,
            defense_observations: Vec::new(),
        };

        apply_advisories(&mut report);
        assert_eq!(report.results[0].advisories.len(), 1);
        assert!(report.results[1].advisories.is_empty());
    }

    #[test]
    fn cisa_kev_and_epss_enrichment_and_filtering() {
        let mut ftp = sample("ftp", Some("vsFTPd"), Some("2.3.4"), None);
        ftp.port = 21;
        let matches = correlate(&ftp);
        assert!(!matches.is_empty());
        let first = &matches[0];
        assert_eq!(first.id, "CVE-2011-2523");
        assert!(
            first.cisa_kev,
            "vsftpd backdoor must be flagged as CISA KEV"
        );
        assert!(
            first.epss.is_some_and(|e| e > 0.9),
            "vsftpd backdoor must have high EPSS"
        );

        let mut report = ScanReport {
            targets: 1,
            ports: 1,
            jobs: 1,
            workers: 1,
            elapsed: Duration::from_millis(5),
            counts: crate::model::StateCounts {
                open: 1,
                ..Default::default()
            },
            results: vec![ftp],
            os_fingerprints: std::collections::HashMap::new(),
            probed_ports: vec![21],
            host_progress: Default::default(),
            partial: false,
            defense_observations: Vec::new(),
        };

        apply_advisories(&mut report);
        assert_eq!(report.results[0].advisories.len(), 1);

        // Filter with high EPSS threshold (e.g. 0.99 which exceeds 0.941)
        filter_advisories(&mut report, false, Some(0.99));
        assert!(report.results[0].advisories.is_empty());
    }
}
