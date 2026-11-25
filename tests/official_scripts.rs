use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde_json::Value;

fn pack_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("packs")
        .join("official-baseline")
}

fn run_check(name: &str, context: &str) -> Value {
    let mut child = Command::new("python3")
        .arg(pack_dir().join("checks.py"))
        .arg(name)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start official check");
    child
        .stdin
        .take()
        .expect("stdin")
        .write_all(context.as_bytes())
        .expect("write script input");
    let output = child.wait_with_output().expect("run official check");
    assert!(
        output.status.success(),
        "official check {name} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("official check JSON")
}

fn finding_ids(payload: &Value) -> Vec<&str> {
    payload["findings"]
        .as_array()
        .expect("findings array")
        .iter()
        .map(|finding| finding["id"].as_str().expect("finding id"))
        .collect()
}

fn python_available() -> bool {
    Command::new("python3")
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

#[test]
fn official_pack_lists_read_only_checks() {
    let manifest = pack_dir().join("pack.toml");
    let output = Command::new(env!("CARGO_BIN_EXE_portensor"))
        .args([
            "scripts",
            "list",
            manifest.to_str().expect("manifest path"),
            "--json",
        ])
        .output()
        .expect("run scripts list");
    assert!(
        output.status.success(),
        "scripts list failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let scripts: Value = serde_json::from_slice(&output.stdout).expect("script JSON");
    let scripts = scripts.as_array().expect("script array");
    let plugins: Vec<&str> = scripts
        .iter()
        .map(|script| script["plugin"].as_str().expect("plugin id"))
        .collect();
    assert!(
        plugins.len() >= 20,
        "expected at least 20 official scripts, found {}",
        plugins.len()
    );
    for expected in [
        "official-baseline/tls-certificate",
        "official-baseline/tls-weak-protocol",
        "official-baseline/tls-weak-cipher",
        "official-baseline/tls-hostname-mismatch",
        "official-baseline/smb-hardening",
        "official-baseline/redis-unauthenticated",
        "official-baseline/docker-unauthenticated",
        "official-baseline/cleartext-ftp",
        "official-baseline/cleartext-telnet",
        "official-baseline/cleartext-http",
        "official-baseline/ssh-version-disclosure",
        "official-baseline/vnc-exposed",
        "official-baseline/rdp-exposed",
        "official-baseline/elasticsearch-exposed",
    ] {
        assert!(plugins.contains(&expected), "missing {expected}");
    }
    for script in scripts {
        assert_eq!(script["danger"], "safe");
        assert_eq!(script["capabilities"][0], "metadata");
        assert_eq!(script["timeout_ms"], 3000);
        assert_eq!(script["kind"], "sidecar");
        assert_eq!(script["command"][1], "checks.py");
        assert_eq!(
            script["command"][2].as_str().expect("check argument"),
            script["name"].as_str().expect("script name")
        );
        assert!(
            !script["services"]
                .as_array()
                .expect("services array")
                .is_empty()
        );
    }
    assert_eq!(scripts[0]["category"], "compliance");
    assert!(
        scripts[0]["services"]
            .as_array()
            .expect("services array")
            .iter()
            .any(|service| service == "tls")
    );

    let fixtures: Value = serde_json::from_slice(
        &std::fs::read(pack_dir().join("fixtures.json")).expect("fixtures file"),
    )
    .expect("fixture JSON");
    let fixtures = fixtures.as_object().expect("fixture object");
    assert_eq!(
        fixtures.len(),
        plugins.len(),
        "every official script needs fixtures"
    );
    for plugin in &plugins {
        let name = plugin
            .strip_prefix("official-baseline/")
            .expect("official plugin prefix");
        let fixture = fixtures.get(name).expect("fixture for script");
        for mode in ["positive", "negative"] {
            assert!(
                fixture[mode]["input"].is_object(),
                "{name} is missing a {mode} fixture"
            );
            assert!(
                fixture[mode]["findings"].is_array(),
                "{name} is missing expected {mode} findings"
            );
        }
    }
}

#[test]
fn official_fixtures_match_expected_findings() {
    if !python_available() {
        eprintln!("python3 is unavailable; skipping official fixture test");
        return;
    }
    let fixtures: Value = serde_json::from_slice(
        &std::fs::read(pack_dir().join("fixtures.json")).expect("fixtures file"),
    )
    .expect("fixture JSON");
    for (name, fixture) in fixtures.as_object().expect("fixture object") {
        for mode in ["positive", "negative"] {
            let input = fixture[mode]["input"].to_string();
            let expected: Vec<String> = fixture[mode]["findings"]
                .as_array()
                .expect("expected findings")
                .iter()
                .map(|value| value.as_str().expect("finding id").to_string())
                .collect();
            let output = run_check(name, &input);
            let actual: Vec<String> = finding_ids(&output)
                .into_iter()
                .map(str::to_string)
                .collect();
            assert_eq!(actual, expected, "{name} {mode} fixture mismatch");
        }
    }
}

#[test]
fn official_checks_report_expected_findings() {
    if !python_available() {
        eprintln!("python3 is unavailable; skipping official check behavior test");
        return;
    }

    let clean = run_check(
        "tls-certificate",
        r#"{"api":1,"tls":{"version":"TLSv1.3","cipher":"TLS13_AES_256_GCM_SHA384","expired":false,"not_yet_valid":false,"self_signed":false,"hostname_matches":true,"chain_len":2,"days_remaining":200,"signature_algorithm":"sha256WithRSA"}}"#,
    );
    assert!(finding_ids(&clean).is_empty());

    let expired = run_check(
        "tls-certificate",
        r#"{"api":1,"tls":{"version":"TLSv1.3","cipher":"TLS13_AES_256_GCM_SHA384","expired":true,"not_yet_valid":false,"self_signed":false,"hostname_matches":true,"chain_len":2,"days_remaining":-3,"not_after":1700000000,"signature_algorithm":"sha256WithRSA"}}"#,
    );
    assert_eq!(finding_ids(&expired), vec!["tls-certificate-expired"]);
    assert_eq!(expired["findings"][0]["severity"], "high");

    let not_yet_valid = run_check(
        "tls-certificate",
        r#"{"api":1,"tls":{"version":"TLSv1.3","cipher":"TLS13_AES_256_GCM_SHA384","expired":false,"not_yet_valid":true,"self_signed":false,"hostname_matches":true,"chain_len":2,"days_remaining":20,"not_before":4102444800,"signature_algorithm":"sha256WithRSA"}}"#,
    );
    assert_eq!(
        finding_ids(&not_yet_valid),
        vec!["tls-certificate-not-yet-valid"]
    );

    let hygiene = run_check(
        "tls-certificate",
        r#"{"api":1,"tls":{"version":"TLSv1.3","cipher":"TLS13_AES_256_GCM_SHA384","expired":false,"not_yet_valid":false,"self_signed":true,"hostname_matches":false,"chain_len":1,"days_remaining":10,"not_after":1800000000,"subject":"CN=legacy","issuer":"CN=legacy","signature_algorithm":"sha1WithRSA"}}"#,
    );
    assert_eq!(
        finding_ids(&hygiene),
        vec![
            "tls-certificate-expiring",
            "tls-certificate-self-signed",
            "tls-certificate-weak-signature",
        ]
    );

    let smb_off = run_check(
        "smb-hardening",
        r#"{"api":1,"port":445,"service":{"name":"smb","info":{"smb_signing":"off","smb_dialect":"3.1.1"}}}"#,
    );
    assert_eq!(finding_ids(&smb_off), vec!["smb-signing-not-required"]);
    assert_eq!(smb_off["findings"][0]["severity"], "high");

    let smb_legacy = run_check(
        "smb-hardening",
        r#"{"api":1,"port":445,"service":{"name":"smb","info":{"smb_signing":"off","smb_os":"Windows Server 2008 R2","smb_lan_manager":"Windows Server 2008 R2 6.1"}}}"#,
    );
    assert_eq!(
        finding_ids(&smb_legacy),
        vec!["smb-v1-negotiation-accepted"]
    );

    let redis = run_check(
        "redis-unauthenticated",
        r#"{"api":1,"port":6379,"service":{"name":"redis","product":"Redis","version":"7.2.4","info":{"mode":"standalone","config_file":""}}}"#,
    );
    assert_eq!(finding_ids(&redis), vec!["redis-unauthenticated"]);
    assert_eq!(redis["findings"][0]["severity"], "high");

    let docker = run_check(
        "docker-unauthenticated",
        r#"{"api":1,"port":2376,"service":{"name":"docker-tls","product":"Docker Engine","info":{"api_version":"1.47","min_api_version":"1.24"}}}"#,
    );
    assert_eq!(finding_ids(&docker), vec!["docker-api-unauthenticated"]);

    let irrelevant = run_check(
        "docker-unauthenticated",
        r#"{"api":1,"port":443,"service":{"name":"https","product":"nginx"}}"#,
    );
    assert!(finding_ids(&irrelevant).is_empty());

    let port_label_only = run_check(
        "docker-unauthenticated",
        r#"{"api":1,"port":2376,"service":{"name":"docker-tls","product":"nginx"}}"#,
    );
    assert!(finding_ids(&port_label_only).is_empty());

    let redis_name_only = run_check(
        "redis-unauthenticated",
        r#"{"api":1,"port":6379,"service":{"name":"redis"}}"#,
    );
    assert!(finding_ids(&redis_name_only).is_empty());
}
