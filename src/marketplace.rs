//! Remote script pack marketplace.
//!
//! A registry is a plain JSON document published over HTTP(S):
//!
//! ```json
//! {
//!   "schema": 1,
//!   "packs": [
//!     {
//!       "name": "web-audit",
//!       "version": "1.2.0",
//!       "description": "Checks for exposed admin surfaces",
//!       "tags": ["http", "discovery"],
//!       "url": "packs/web-audit-1.2.0.tar.gz",
//!       "sha256": "…64 hex characters…"
//!     }
//!   ]
//! }
//! ```
//!
//! `url` may be absolute or relative to the index location. Every archive is
//! a gzip-compressed tarball with a single top-level directory named after the
//! pack; the digest is mandatory and verified before extraction. Extraction
//! rejects absolute paths, parent traversal, links, and device nodes, and the
//! regular local library validation runs after extraction, so a registry can
//! never drop files outside the pack directory or install a pack that would
//! not pass `rayscan scripts list`.

use std::fs;
use std::io::{Cursor, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use flate2::read::GzDecoder;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use tar::Archive;

use crate::cli::ScriptsSearchArgs;
use crate::error::AppError;
use crate::script::{self, Registry};

/// Environment fallback for `--registry` on `scripts search` and `install`.
pub const REGISTRY_ENV: &str = "RAYSCAN_SCRIPT_REGISTRY";

const INDEX_SCHEMA: u32 = 1;
const MAX_INDEX_BYTES: u64 = 1024 * 1024;
const MAX_INDEX_PACKS: usize = 256;
/// Compressed archive ceiling; the extracted tree is separately capped at the
/// library limits enforced by [`script::install_pack`].
const MAX_PACK_BYTES: u64 = 64 * 1024 * 1024;
const MAX_EXTRACTED_BYTES: u64 = 512 * 1024 * 1024;
const MAX_ARCHIVE_ENTRIES: usize = 4096;
const MAX_URL_CHARS: usize = 2048;
const MAX_VERSION_CHARS: usize = 64;
const MAX_DESCRIPTION_CHARS: usize = 500;
const MAX_TAGS: usize = 8;
const MAX_TAG_CHARS: usize = 32;
const MAX_LISTED_NAMES: usize = 12;

#[derive(Debug, Deserialize)]
struct IndexFile {
    schema: u32,
    packs: Vec<IndexEntry>,
}

#[derive(Clone, Debug, Deserialize)]
struct IndexEntry {
    name: String,
    version: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    tags: Vec<String>,
    url: String,
    sha256: String,
    #[serde(skip)]
    resolved_url: String,
}

/// A parsed registry index. Entries are validated and URLs resolved when the
/// index is parsed so installs never reinterpret registry-supplied paths.
#[derive(Debug)]
pub struct Index {
    entries: Vec<IndexEntry>,
}

impl Index {
    pub fn parse(base: &str, text: &str) -> Result<Self, AppError> {
        validate_http_url(base)?;
        let file: IndexFile = serde_json::from_str(text).map_err(|error| {
            AppError::usage(format!("invalid script registry index {base}: {error}"))
        })?;
        if file.schema != INDEX_SCHEMA {
            return Err(AppError::usage(format!(
                "script registry index uses unsupported schema {} (expected {INDEX_SCHEMA})",
                file.schema
            )));
        }
        if file.packs.len() > MAX_INDEX_PACKS {
            return Err(AppError::usage(format!(
                "script registry index lists more than {MAX_INDEX_PACKS} packs"
            )));
        }
        let mut entries = Vec::with_capacity(file.packs.len());
        for mut entry in file.packs {
            validate_entry(&mut entry, base)?;
            if entries.iter().any(|existing: &IndexEntry| {
                existing.name == entry.name && existing.version == entry.version
            }) {
                return Err(AppError::usage(format!(
                    "script registry lists pack '{}' version '{}' more than once",
                    entry.name, entry.version
                )));
            }
            entries.push(entry);
        }
        Ok(Self { entries })
    }

    /// Pick the highest version of `name` using numeric-aware ordering, so
    /// `1.10.0` sorts above `1.9.0`.
    fn find(&self, name: &str) -> Result<&IndexEntry, AppError> {
        if !script::valid_identifier(name) {
            return Err(AppError::usage(format!(
                "invalid script pack name '{name}'"
            )));
        }
        let mut candidates: Vec<&IndexEntry> = self
            .entries
            .iter()
            .filter(|entry| entry.name == name)
            .collect();
        candidates.sort_by(|left, right| compare_versions(&left.version, &right.version));
        if let Some(best) = candidates.pop() {
            return Ok(best);
        }
        let mut names: Vec<&str> = self
            .entries
            .iter()
            .map(|entry| entry.name.as_str())
            .collect();
        names.sort_unstable();
        names.dedup();
        let listed = names
            .iter()
            .take(MAX_LISTED_NAMES)
            .copied()
            .collect::<Vec<_>>()
            .join(", ");
        let available = if names.is_empty() {
            "the registry contains no packs".to_string()
        } else {
            format!("available packs: {listed}")
        };
        Err(AppError::usage(format!(
            "script pack '{name}' is not in the registry ({available})"
        )))
    }

    fn search(&self, query: Option<&str>) -> Vec<&IndexEntry> {
        let needle = query.map(str::to_ascii_lowercase);
        let mut matches: Vec<&IndexEntry> = self
            .entries
            .iter()
            .filter(|entry| match &needle {
                None => true,
                Some(needle) => {
                    entry.name.to_ascii_lowercase().contains(needle)
                        || entry.description.to_ascii_lowercase().contains(needle)
                        || entry
                            .tags
                            .iter()
                            .any(|tag| tag.to_ascii_lowercase().contains(needle))
                }
            })
            .collect();
        matches.sort_by(|left, right| {
            left.name
                .cmp(&right.name)
                .then_with(|| compare_versions(&right.version, &left.version))
        });
        matches
    }
}

fn validate_entry(entry: &mut IndexEntry, base: &str) -> Result<(), AppError> {
    if !script::valid_identifier(&entry.name) {
        return Err(AppError::usage(format!(
            "script registry lists invalid pack name '{}'",
            entry.name
        )));
    }
    if entry.version.is_empty()
        || entry.version.chars().count() > MAX_VERSION_CHARS
        || entry.version.chars().any(|character| {
            !(character.is_ascii_alphanumeric() || matches!(character, '.' | '-' | '_' | '+'))
        })
    {
        return Err(AppError::usage(format!(
            "script pack '{}' has an invalid version '{}'",
            entry.name, entry.version
        )));
    }
    if entry.description.chars().count() > MAX_DESCRIPTION_CHARS {
        return Err(AppError::usage(format!(
            "script pack '{}' description exceeds {MAX_DESCRIPTION_CHARS} characters",
            entry.name
        )));
    }
    if entry.description.chars().any(char::is_control) {
        return Err(AppError::usage(format!(
            "script pack '{}' description contains control characters",
            entry.name
        )));
    }
    if entry.tags.len() > MAX_TAGS {
        return Err(AppError::usage(format!(
            "script pack '{}' lists more than {MAX_TAGS} tags",
            entry.name
        )));
    }
    let mut tags = Vec::with_capacity(entry.tags.len());
    for tag in &entry.tags {
        if tag.is_empty()
            || tag.chars().count() > MAX_TAG_CHARS
            || !tag.chars().all(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '.' | '-' | '_')
            })
        {
            return Err(AppError::usage(format!(
                "script pack '{}' has an invalid tag '{tag}'",
                entry.name
            )));
        }
        if !tags.contains(tag) {
            tags.push(tag.clone());
        }
    }
    entry.tags = tags;
    entry.sha256 = normalize_sha256(&entry.sha256)?;
    entry.resolved_url = resolve_url(base, &entry.url)?;
    Ok(())
}

fn validate_http_url(url: &str) -> Result<(), AppError> {
    if url.is_empty() || url.chars().count() > MAX_URL_CHARS {
        return Err(AppError::usage(
            "script registry URL must be 1-2048 characters",
        ));
    }
    if url
        .chars()
        .any(|character| character.is_control() || character.is_whitespace())
    {
        return Err(AppError::usage(
            "script registry URL contains whitespace or control characters",
        ));
    }
    let lower = url.to_ascii_lowercase();
    if !lower.starts_with("http://") && !lower.starts_with("https://") {
        return Err(AppError::usage(format!(
            "script registry URL '{url}' must start with http:// or https://"
        )));
    }
    let authority = &url[url.find("://").map_or(0, |index| index + 3)..];
    let host = authority.split(['/', '?', '#']).next().unwrap_or_default();
    if host.is_empty() {
        return Err(AppError::usage(format!(
            "script registry URL '{url}' has no host"
        )));
    }
    Ok(())
}

fn resolve_url(base: &str, reference: &str) -> Result<String, AppError> {
    let reference = reference.trim();
    if reference.is_empty() || reference.chars().count() > MAX_URL_CHARS {
        return Err(AppError::usage(
            "script registry entry URL must be 1-2048 characters",
        ));
    }
    if reference
        .chars()
        .any(|character| character.is_control() || character.is_whitespace())
    {
        return Err(AppError::usage(
            "script registry entry URL contains whitespace or control characters",
        ));
    }
    let resolved = if is_remote_url(reference) {
        reference.to_string()
    } else if reference.starts_with("//") {
        let scheme = base.split("://").next().unwrap_or("https");
        format!("{scheme}:{reference}")
    } else {
        let scheme_end = base.find("://").map_or(0, |index| index + 3);
        let after_scheme = &base[scheme_end..];
        let authority_end = after_scheme
            .find('/')
            .map_or(base.len(), |index| scheme_end + index);
        let authority = &base[..authority_end];
        let base_path = &base[authority_end..];
        let base_path = base_path
            .split_once(['?', '#'])
            .map_or(base_path, |(path, _)| path);
        let directory = &base_path[..base_path.rfind('/').map_or(0, |index| index + 1)];
        let (reference_path, suffix) = split_url_suffix(reference);
        let joined = format!("{directory}{reference_path}");
        let normalized = normalize_path(&joined)?;
        let separator = if normalized.starts_with('/') { "" } else { "/" };
        format!("{authority}{separator}{normalized}{suffix}")
    };
    validate_http_url(&resolved)?;
    Ok(resolved)
}

fn split_url_suffix(reference: &str) -> (&str, &str) {
    let index = reference.find(['?', '#']).unwrap_or(reference.len());
    reference.split_at(index)
}

fn normalize_path(path: &str) -> Result<String, AppError> {
    let leading_slash = path.starts_with('/');
    let mut parts: Vec<&str> = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                if parts.pop().is_none() {
                    return Err(AppError::usage(
                        "script registry entry URL escapes its host",
                    ));
                }
            }
            other => parts.push(other),
        }
    }
    let mut normalized = String::new();
    if leading_slash {
        normalized.push('/');
    }
    normalized.push_str(&parts.join("/"));
    if path.ends_with('/') && !normalized.ends_with('/') {
        normalized.push('/');
    }
    Ok(normalized)
}

fn normalize_sha256(value: &str) -> Result<String, AppError> {
    let value = value.trim();
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(AppError::usage(format!(
            "script registry digest '{value}' is not a 64-character hex SHA-256"
        )));
    }
    Ok(value.to_ascii_lowercase())
}

fn compare_versions(left: &str, right: &str) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    let mut left = left
        .split(|character: char| !character.is_ascii_alphanumeric())
        .filter(|part| !part.is_empty());
    let mut right = right
        .split(|character: char| !character.is_ascii_alphanumeric())
        .filter(|part| !part.is_empty());
    loop {
        match (left.next(), right.next()) {
            (None, None) => return Ordering::Equal,
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
            (Some(left), Some(right)) => {
                let ordering = if left.bytes().all(|byte| byte.is_ascii_digit())
                    && right.bytes().all(|byte| byte.is_ascii_digit())
                {
                    let left = left.trim_start_matches('0');
                    let right = right.trim_start_matches('0');
                    left.len().cmp(&right.len()).then_with(|| left.cmp(right))
                } else {
                    left.cmp(right)
                };
                if ordering != Ordering::Equal {
                    return ordering;
                }
            }
        }
    }
}

pub fn is_remote_url(source: &str) -> bool {
    let lower = source.to_ascii_lowercase();
    lower.starts_with("http://") || lower.starts_with("https://")
}

fn warn_plain_http(url: &str) {
    if url.to_ascii_lowercase().starts_with("http://") {
        eprintln!("warning: {url} uses unencrypted HTTP; integrity depends on the SHA-256 digest");
    }
}

pub fn fetch_index(registry_url: &str) -> Result<Index, AppError> {
    validate_http_url(registry_url)?;
    warn_plain_http(registry_url);
    let agent = crate::db::feed::agent();
    let response = agent.get(registry_url).call().map_err(|error| {
        AppError::runtime(format!(
            "script registry request failed for {registry_url}: {error}"
        ))
    })?;
    let mut bytes = Vec::new();
    response
        .into_reader()
        .take(MAX_INDEX_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| {
            AppError::runtime(format!("cannot read script registry index: {error}"))
        })?;
    if bytes.len() as u64 > MAX_INDEX_BYTES {
        return Err(AppError::runtime(format!(
            "script registry index exceeds the {MAX_INDEX_BYTES}-byte limit"
        )));
    }
    let text = String::from_utf8(bytes)
        .map_err(|_| AppError::runtime("script registry index is not valid UTF-8"))?;
    Index::parse(registry_url, &text)
}

fn download(url: &str) -> Result<Vec<u8>, AppError> {
    validate_http_url(url)?;
    warn_plain_http(url);
    let agent = crate::db::feed::agent();
    let response = agent.get(url).call().map_err(|error| {
        AppError::runtime(format!("script pack download failed for {url}: {error}"))
    })?;
    if let Some(length) = response.header("content-length")
        && let Ok(length) = length.parse::<u64>()
        && length > MAX_PACK_BYTES
    {
        return Err(AppError::runtime(format!(
            "script pack archive exceeds the {MAX_PACK_BYTES}-byte limit"
        )));
    }
    let mut bytes = Vec::new();
    response
        .into_reader()
        .take(MAX_PACK_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| AppError::runtime(format!("cannot read script pack archive: {error}")))?;
    if bytes.len() as u64 > MAX_PACK_BYTES {
        return Err(AppError::runtime(format!(
            "script pack archive exceeds the {MAX_PACK_BYTES}-byte limit"
        )));
    }
    Ok(bytes)
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    for byte in digest {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}

fn verify_sha256(bytes: &[u8], expected: &str) -> Result<(), AppError> {
    let actual = sha256_hex(bytes);
    if !actual.eq_ignore_ascii_case(expected) {
        return Err(AppError::runtime(format!(
            "script pack failed SHA-256 verification (expected {expected}, got {actual})"
        )));
    }
    Ok(())
}

static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Scratch directory removed on drop.
struct TempWorkspace {
    path: PathBuf,
}

impl TempWorkspace {
    fn new() -> Result<Self, AppError> {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or(0);
        let counter = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "rayscan-pack-{}-{counter}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(&path).map_err(|error| {
            AppError::runtime(format!(
                "cannot create marketplace workspace {}: {error}",
                path.display()
            ))
        })?;
        Ok(Self { path })
    }
}

impl Drop for TempWorkspace {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn extract_archive(bytes: &[u8], destination: &Path) -> Result<(), AppError> {
    let decoder = GzDecoder::new(Cursor::new(bytes));
    let mut archive = Archive::new(decoder);
    let entries = archive
        .entries()
        .map_err(|error| AppError::runtime(format!("cannot read script pack archive: {error}")))?;
    let mut count = 0usize;
    let mut total = 0u64;
    for entry in entries {
        let mut entry = entry.map_err(|error| {
            AppError::runtime(format!("cannot read script pack archive entry: {error}"))
        })?;
        let (kind, size, mode) = {
            let header = entry.header();
            let kind = header.entry_type();
            let size = header
                .size()
                .map_err(|error| AppError::runtime(format!("invalid tar entry size: {error}")))?;
            let mode = header.mode().unwrap_or(0o644);
            (kind, size, mode)
        };
        if kind.is_pax_global_extensions()
            || kind.is_pax_local_extensions()
            || kind.is_gnu_longname()
            || kind.is_gnu_longlink()
        {
            continue;
        }
        if !kind.is_file() && !kind.is_dir() {
            return Err(AppError::usage(
                "script pack archive contains a link or special file; only regular files and directories are allowed",
            ));
        }
        let entry_path = entry.path().map_err(|error| {
            AppError::runtime(format!("cannot read script pack archive path: {error}"))
        })?;
        let path = safe_relative_path(&entry_path)?;
        count += 1;
        if count > MAX_ARCHIVE_ENTRIES {
            return Err(AppError::usage(format!(
                "script pack archive contains more than {MAX_ARCHIVE_ENTRIES} entries"
            )));
        }
        let target = destination.join(path);
        if kind.is_dir() {
            fs::create_dir_all(&target).map_err(|error| {
                AppError::runtime(format!(
                    "cannot create pack directory {}: {error}",
                    target.display()
                ))
            })?;
            continue;
        }
        total = total.saturating_add(size);
        if total > MAX_EXTRACTED_BYTES {
            return Err(AppError::usage(format!(
                "script pack archive expands beyond the {MAX_EXTRACTED_BYTES}-byte limit"
            )));
        }
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).map_err(|error| {
                AppError::runtime(format!(
                    "cannot create pack directory {}: {error}",
                    parent.display()
                ))
            })?;
        }
        let mut file = fs::File::create(&target).map_err(|error| {
            AppError::runtime(format!(
                "cannot write pack file {}: {error}",
                target.display()
            ))
        })?;
        let copied = std::io::copy(&mut entry, &mut file).map_err(|error| {
            AppError::runtime(format!(
                "cannot extract pack file {}: {error}",
                target.display()
            ))
        })?;
        if copied != size {
            return Err(AppError::runtime(format!(
                "script pack archive entry {} is truncated",
                target.display()
            )));
        }
        file.flush().map_err(|error| {
            AppError::runtime(format!(
                "cannot flush pack file {}: {error}",
                target.display()
            ))
        })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let mode = mode & 0o777;
            if mode != 0 {
                let _ = fs::set_permissions(&target, fs::Permissions::from_mode(mode));
            }
        }
        #[cfg(not(unix))]
        let _ = mode;
    }
    Ok(())
}

fn safe_relative_path(path: &Path) -> Result<&Path, AppError> {
    if path.as_os_str().is_empty() {
        return Err(AppError::usage(
            "script pack archive contains an empty path",
        ));
    }
    for component in path.components() {
        match component {
            Component::Normal(_) | Component::CurDir => {}
            _ => {
                return Err(AppError::usage(format!(
                    "script pack archive contains an unsafe path: {}",
                    path.display()
                )));
            }
        }
    }
    Ok(path)
}

/// Extract an archive into a scratch workspace and return the single
/// top-level pack directory. `expected_name` pins the directory name for
/// registry installs.
fn unpack_archive(
    bytes: &[u8],
    expected_name: Option<&str>,
) -> Result<(TempWorkspace, PathBuf), AppError> {
    let workspace = TempWorkspace::new()?;
    let destination = workspace.path.join("extract");
    fs::create_dir_all(&destination).map_err(|error| {
        AppError::runtime(format!(
            "cannot create pack extraction directory {}: {error}",
            destination.display()
        ))
    })?;
    extract_archive(bytes, &destination)?;
    let mut roots: Vec<PathBuf> = Vec::new();
    for entry in fs::read_dir(&destination)
        .map_err(|error| AppError::runtime(format!("cannot inspect extracted pack: {error}")))?
    {
        let entry = entry.map_err(|error| {
            AppError::runtime(format!("cannot inspect extracted pack entry: {error}"))
        })?;
        roots.push(entry.path());
    }
    if roots.is_empty() {
        return Err(AppError::usage("downloaded script pack archive is empty"));
    }
    if roots.len() != 1 {
        return Err(AppError::usage(
            "script pack archive must contain a single top-level directory named after the pack",
        ));
    }
    let root = roots.pop().expect("non-empty");
    let is_directory = fs::metadata(&root)
        .map_err(|error| AppError::runtime(format!("cannot inspect pack root: {error}")))?
        .is_dir();
    if !is_directory {
        return Err(AppError::usage(
            "script pack archive must contain a single top-level directory named after the pack",
        ));
    }
    let name = root
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| AppError::usage("script pack directory has no usable name"))?
        .to_string();
    if let Some(expected) = expected_name
        && name != expected
    {
        return Err(AppError::usage(format!(
            "script pack archive root '{name}' does not match the registry name '{expected}'"
        )));
    }
    Ok((workspace, root))
}

fn validate_downloaded_pack(root: &Path, name: &str) -> Result<(), AppError> {
    let registry = Registry::load(root).map_err(|error| {
        AppError::usage(format!(
            "downloaded script pack '{name}' failed validation: {error}"
        ))
    })?;
    if let Some(summary) = registry
        .summaries()
        .iter()
        .find(|summary| summary.pack != name)
    {
        return Err(AppError::usage(format!(
            "downloaded script pack directory '{name}' declares manifest pack '{}'; the directory and manifest names must match",
            summary.pack
        )));
    }
    Ok(())
}

/// Install the highest-versioned `name` from `registry_url`.
pub fn install_named(
    registry_url: &str,
    name: &str,
    library: &Path,
    force: bool,
) -> Result<PathBuf, AppError> {
    let index = fetch_index(registry_url)?;
    let entry = index.find(name)?;
    let bytes = download(&entry.resolved_url)?;
    verify_sha256(&bytes, &entry.sha256)?;
    let (_workspace, root) = unpack_archive(&bytes, Some(&entry.name))?;
    validate_downloaded_pack(&root, &entry.name)?;
    script::install_pack(&root, library, force)
}

/// Install a directly linked archive after verifying the caller-supplied
/// SHA-256 digest. The pack name comes from the archive's top-level directory.
pub fn install_url(
    url: &str,
    sha256: &str,
    library: &Path,
    force: bool,
) -> Result<PathBuf, AppError> {
    let expected = normalize_sha256(sha256)?;
    let bytes = download(url)?;
    verify_sha256(&bytes, &expected)?;
    let (_workspace, root) = unpack_archive(&bytes, None)?;
    let name = root
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| AppError::usage("script pack directory has no usable name"))?
        .to_string();
    validate_downloaded_pack(&root, &name)?;
    script::install_pack(&root, library, force)
}

pub fn search_cli(args: ScriptsSearchArgs) -> Result<(), AppError> {
    let registry = args
        .registry
        .or_else(|| {
            std::env::var(REGISTRY_ENV)
                .ok()
                .filter(|value| !value.trim().is_empty())
        })
        .ok_or_else(|| {
            AppError::usage(format!(
                "scripts search requires --registry URL or {REGISTRY_ENV}"
            ))
        })?;
    let index = fetch_index(&registry)?;
    let matches = index.search(args.query.as_deref());
    if args.json {
        let packs: Vec<serde_json::Value> = matches
            .iter()
            .map(|entry| {
                serde_json::json!({
                    "name": entry.name,
                    "version": entry.version,
                    "description": entry.description,
                    "tags": entry.tags,
                    "url": entry.resolved_url,
                    "sha256": entry.sha256,
                })
            })
            .collect();
        let payload = serde_json::json!({
            "registry": registry,
            "count": packs.len(),
            "packs": packs,
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&payload).map_err(|error| AppError::runtime(format!(
                "cannot encode registry JSON: {error}"
            )))?
        );
        return Ok(());
    }
    println!("{} pack(s) in {registry}", matches.len());
    for entry in &matches {
        println!(
            "  {:<28} {:<12} {}",
            entry.name, entry.version, entry.description
        );
        if !entry.tags.is_empty() {
            println!("    tags: {}", entry.tags.join(", "));
        }
    }
    if matches.is_empty() {
        println!("no packs matched the query");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::sync::Arc;
    use std::sync::atomic::AtomicBool;
    use std::thread;
    use std::time::Duration;

    fn demo_manifest(name: &str) -> String {
        format!(
            "name = \"{name}\"\n[[script]]\nname = \"check\"\ncommand = [\"python3\", \"check.py\"]\n"
        )
    }

    fn append_file(
        builder: &mut tar::Builder<flate2::write::GzEncoder<Vec<u8>>>,
        path: &str,
        bytes: &[u8],
    ) {
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, path, bytes)
            .expect("append tar entry");
    }

    fn build_archive(name: &str) -> Vec<u8> {
        let encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        let mut builder = tar::Builder::new(encoder);
        append_file(
            &mut builder,
            &format!("{name}/pack.toml"),
            demo_manifest(name).as_bytes(),
        );
        append_file(
            &mut builder,
            &format!("{name}/check.py"),
            b"print('demo')\n",
        );
        builder
            .into_inner()
            .expect("finish tar")
            .finish()
            .expect("finish gzip")
    }

    fn index_json(name: &str, url: &str, sha256: &str) -> String {
        format!(
            r#"{{"schema":1,"packs":[{{"name":"{name}","version":"1.0.0","description":"Demo pack","tags":["demo"],"url":"{url}","sha256":"{sha256}"}}]}}"#
        )
    }

    struct RegistryServer {
        port: u16,
        stop: Arc<AtomicBool>,
        handle: Option<thread::JoinHandle<()>>,
    }

    impl RegistryServer {
        fn start(index: Vec<u8>, archive: Vec<u8>) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind registry");
            let port = listener.local_addr().expect("local addr").port();
            listener.set_nonblocking(true).expect("nonblocking");
            let stop = Arc::new(AtomicBool::new(false));
            let thread_stop = Arc::clone(&stop);
            let handle = thread::spawn(move || {
                while !thread_stop.load(Ordering::Relaxed) {
                    match listener.accept() {
                        Ok((mut stream, _)) => {
                            let mut request = [0u8; 4096];
                            let read = stream.read(&mut request).unwrap_or(0);
                            let request = String::from_utf8_lossy(&request[..read]);
                            let path = request.split_whitespace().nth(1).unwrap_or("/");
                            let body: &[u8] = match path {
                                "/index.json" => &index,
                                "/pack.tar.gz" => &archive,
                                _ => b"not found",
                            };
                            let status = if path == "/index.json" || path == "/pack.tar.gz" {
                                "200 OK"
                            } else {
                                "404 Not Found"
                            };
                            let head = format!(
                                "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                                body.len()
                            );
                            let _ = stream.write_all(head.as_bytes());
                            let _ = stream.write_all(body);
                            let _ = stream.flush();
                        }
                        Err(ref error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(5));
                        }
                        Err(_) => break,
                    }
                }
            });
            Self {
                port,
                stop,
                handle: Some(handle),
            }
        }

        fn url(&self, path: &str) -> String {
            format!("http://127.0.0.1:{}{path}", self.port)
        }
    }

    impl Drop for RegistryServer {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Relaxed);
            if let Some(handle) = self.handle.take() {
                let _ = handle.join();
            }
        }
    }

    #[test]
    fn index_picks_the_highest_version() {
        let text = r#"{"schema":1,"packs":[
            {"name":"demo","version":"1.9.0","url":"a.tar.gz","sha256":"0000000000000000000000000000000000000000000000000000000000000000"},
            {"name":"demo","version":"1.10.0","url":"b.tar.gz","sha256":"1111111111111111111111111111111111111111111111111111111111111111"},
            {"name":"demo","version":"2.0.0-beta","url":"c.tar.gz","sha256":"2222222222222222222222222222222222222222222222222222222222222222"}
        ]}"#;
        let index = Index::parse("https://registry.example/index.json", text).expect("parse index");
        let entry = index.find("demo").expect("find demo");
        assert_eq!(entry.version, "2.0.0-beta");
        assert!(index.find("missing").is_err());
    }

    #[test]
    fn index_rejects_bad_schema_digest_and_duplicates() {
        let base = "https://registry.example/index.json";
        let bad_schema = r#"{"schema":2,"packs":[]}"#;
        assert!(Index::parse(base, bad_schema).is_err());

        let bad_digest = r#"{"schema":1,"packs":[{"name":"demo","version":"1.0.0","url":"a.tar.gz","sha256":"abc"}]}"#;
        assert!(Index::parse(base, bad_digest).is_err());

        let duplicate = r#"{"schema":1,"packs":[
            {"name":"demo","version":"1.0.0","url":"a.tar.gz","sha256":"0000000000000000000000000000000000000000000000000000000000000000"},
            {"name":"demo","version":"1.0.0","url":"b.tar.gz","sha256":"1111111111111111111111111111111111111111111111111111111111111111"}
        ]}"#;
        assert!(Index::parse(base, duplicate).is_err());
    }

    #[test]
    fn relative_archive_urls_resolve_against_the_index() {
        assert_eq!(
            resolve_url(
                "https://registry.example/registry/index.json",
                "packs/demo.tar.gz"
            )
            .expect("relative"),
            "https://registry.example/registry/packs/demo.tar.gz"
        );
        assert_eq!(
            resolve_url("https://registry.example/index.json", "/packs/demo.tar.gz")
                .expect("absolute path"),
            "https://registry.example/packs/demo.tar.gz"
        );
        assert_eq!(
            resolve_url(
                "https://registry.example/registry/sub/index.json",
                "../packs/demo.tar.gz"
            )
            .expect("parent"),
            "https://registry.example/registry/packs/demo.tar.gz"
        );
        assert_eq!(
            resolve_url(
                "https://registry.example/index.json",
                "https://mirror.example/demo.tar.gz"
            )
            .expect("absolute"),
            "https://mirror.example/demo.tar.gz"
        );
        assert!(
            resolve_url(
                "https://registry.example/index.json",
                "../../../demo.tar.gz"
            )
            .is_err()
        );
    }

    #[test]
    fn extraction_rejects_traversal_and_links() {
        let encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        let mut builder = tar::Builder::new(encoder);
        let mut header = tar::Header::new_gnu();
        header.set_size(4);
        header.set_mode(0o644);
        let name = b"../escaped.txt";
        let gnu = header.as_gnu_mut().expect("gnu header");
        gnu.name[..name.len()].copy_from_slice(name);
        header.set_cksum();
        builder
            .append(&header, &b"nope"[..])
            .expect("append raw tar entry");
        let bytes = builder
            .into_inner()
            .expect("finish tar")
            .finish()
            .expect("finish gzip");
        let destination = TempWorkspace::new().expect("workspace");
        let error = extract_archive(&bytes, &destination.path).expect_err("traversal");
        assert!(error.to_string().contains("unsafe path"), "{error}");

        let encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        let mut builder = tar::Builder::new(encoder);
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_size(0);
        header.set_mode(0o777);
        header.set_link_name("/etc/passwd").expect("link name");
        header.set_cksum();
        builder
            .append_data(&mut header, "demo/link", std::io::empty())
            .expect("append link");
        let bytes = builder
            .into_inner()
            .expect("finish tar")
            .finish()
            .expect("finish gzip");
        let destination = TempWorkspace::new().expect("workspace");
        let error = extract_archive(&bytes, &destination.path).expect_err("symlink");
        assert!(error.to_string().contains("link"), "{error}");
    }

    #[test]
    fn archives_require_a_single_named_root_directory() {
        let archive = build_archive("demo-pack");
        let (_workspace, root) = unpack_archive(&archive, Some("demo-pack")).expect("unpack");
        assert!(root.join("pack.toml").is_file());
        assert!(unpack_archive(&archive, Some("other-pack")).is_err());

        let encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        let mut builder = tar::Builder::new(encoder);
        append_file(&mut builder, "pack.toml", b"name = \"flat\"");
        let flat = builder
            .into_inner()
            .expect("finish tar")
            .finish()
            .expect("finish gzip");
        assert!(unpack_archive(&flat, None).is_err());
    }

    #[test]
    fn checksum_mismatch_and_manifest_name_mismatch_are_rejected() {
        assert!(verify_sha256(b"payload", &"00".repeat(32)).is_err());
        let archive = build_archive("demo-pack");
        assert!(verify_sha256(&archive, &sha256_hex(&archive)).is_ok());

        let workspace = TempWorkspace::new().expect("workspace");
        let root = workspace.path.join("demo-pack");
        fs::create_dir_all(&root).expect("create root");
        fs::write(root.join("pack.toml"), demo_manifest("other-pack")).expect("write manifest");
        assert!(validate_downloaded_pack(&root, "demo-pack").is_err());
    }

    #[test]
    fn remote_install_end_to_end() {
        let archive = build_archive("demo-pack");
        let digest = sha256_hex(&archive);
        let index = index_json("demo-pack", "/pack.tar.gz", &digest).into_bytes();
        let server = RegistryServer::start(index, archive);
        let base = std::env::temp_dir().join(format!(
            "rayscan-market-e2e-{}-{}",
            std::process::id(),
            server.port
        ));
        let library = base.join("library");
        let installed = install_named(&server.url("/index.json"), "demo-pack", &library, false)
            .expect("install from registry");
        assert!(installed.ends_with("demo-pack"));
        assert!(library.join("demo-pack").join("pack.toml").is_file());
        assert!(library.join("demo-pack").join("check.py").is_file());
        assert!(
            install_named(&server.url("/index.json"), "demo-pack", &library, false).is_err(),
            "reinstall must require --force"
        );
        assert!(install_named(&server.url("/index.json"), "missing", &library, false).is_err());
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn search_filters_name_description_and_tags() {
        let text = r#"{"schema":1,"packs":[
            {"name":"alpha","version":"1.0.0","description":"Redis checks","tags":["database"],"url":"a.tar.gz","sha256":"0000000000000000000000000000000000000000000000000000000000000000"},
            {"name":"beta","version":"1.0.0","description":"Web audit","tags":["http"],"url":"b.tar.gz","sha256":"1111111111111111111111111111111111111111111111111111111111111111"}
        ]}"#;
        let index = Index::parse("https://registry.example/index.json", text).expect("index");
        assert_eq!(index.search(None).len(), 2);
        assert_eq!(index.search(Some("redis"))[0].name, "alpha");
        assert_eq!(index.search(Some("HTTP"))[0].name, "beta");
        assert_eq!(index.search(Some("database"))[0].name, "alpha");
        assert!(index.search(Some("missing")).is_empty());
    }

    #[test]
    fn direct_url_install_verifies_the_digest() {
        let archive = build_archive("direct-pack");
        let digest = sha256_hex(&archive);
        let index = index_json("direct-pack", "/pack.tar.gz", &digest).into_bytes();
        let server = RegistryServer::start(index, archive);
        let base = std::env::temp_dir().join(format!(
            "rayscan-market-url-{}-{}",
            std::process::id(),
            server.port
        ));
        let library = base.join("library");
        let installed = install_url(&server.url("/pack.tar.gz"), &digest, &library, false)
            .expect("install direct URL");
        assert!(installed.ends_with("direct-pack"));
        assert!(library.join("direct-pack").join("pack.toml").is_file());
        let error = install_url(
            &server.url("/pack.tar.gz"),
            &"00".repeat(32),
            &library,
            true,
        )
        .expect_err("bad digest");
        assert!(error.to_string().contains("SHA-256"), "{error}");
        assert!(
            library.join("direct-pack").is_dir(),
            "failed install must not remove a good pack"
        );
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn remote_install_rejects_a_bad_digest() {
        let archive = build_archive("demo-pack");
        let bad = "00".repeat(32);
        let index = index_json("demo-pack", "/pack.tar.gz", &bad).into_bytes();
        let server = RegistryServer::start(index, archive);
        let base = std::env::temp_dir().join(format!(
            "rayscan-market-bad-{}-{}",
            std::process::id(),
            server.port
        ));
        let library = base.join("library");
        let error = install_named(&server.url("/index.json"), "demo-pack", &library, false)
            .expect_err("bad digest");
        assert!(error.to_string().contains("SHA-256"), "{error}");
        assert!(!library.join("demo-pack").exists());
        let _ = fs::remove_dir_all(&base);
    }
}
