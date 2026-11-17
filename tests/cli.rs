use std::io::Write;
use std::net::TcpListener;
use std::process::Command;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;

use serde_json::Value;

fn rayscan() -> Command {
    Command::new(env!("CARGO_BIN_EXE_rayscan"))
}

struct BannerServer {
    port: u16,
    stop: Arc<AtomicBool>,
    handle: Option<thread::JoinHandle<()>>,
}

impl BannerServer {
    fn port(&self) -> u16 {
        self.port
    }

    fn stop(mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            handle.join().expect("test server thread");
        }
    }
}

/// Serve the same banner on every connection until [`BannerServer::stop`].
/// The scanner opens more than one connection per port (the probe plus the
/// post-scan local recheck), so a listener that stops after the first accept
/// would be reported closed by the recheck.
fn banner_server() -> BannerServer {
    banner_server_with(b"HTTP/1.1 200 OK\r\nServer: rayscan-lab\r\nContent-Length: 0\r\n\r\n")
}

/// Serve `banner` on every connection until [`BannerServer::stop`].
fn banner_server_with(banner: &[u8]) -> BannerServer {
    let banner = banner.to_vec();
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind test listener");
    listener
        .set_nonblocking(true)
        .expect("nonblocking test listener");
    let port = listener.local_addr().expect("listener address").port();
    let stop = Arc::new(AtomicBool::new(false));
    let thread_stop = Arc::clone(&stop);
    let handle = thread::spawn(move || {
        while !thread_stop.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let _ = stream.write_all(&banner);
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(std::time::Duration::from_millis(5));
                }
                Err(_) => break,
            }
        }
    });
    BannerServer {
        port,
        stop,
        handle: Some(handle),
    }
}

#[test]
fn version_is_reported() {
    let output = rayscan().arg("--version").output().expect("run rayscan");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("utf-8 output");
    assert!(stdout.starts_with("rayscan "));
    assert!(stdout.contains(env!("CARGO_PKG_VERSION")));
}

#[test]
fn help_describes_the_scan_command() {
    let output = rayscan().arg("--help").output().expect("run rayscan");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("utf-8 output");
    assert!(stdout.contains("Usage: rayscan"));
    assert!(stdout.contains("accuracy-first"));
    assert!(stdout.contains("scan"));
}

#[test]
fn no_arguments_shows_help() {
    let output = rayscan().output().expect("run rayscan");
    assert!(!output.status.success());
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(combined.contains("Usage: rayscan"));
}

#[test]
fn empty_shard_emits_a_valid_report() {
    let count = 64;
    let owner = rayscan::shard::shard_for("127.0.0.1".parse().unwrap(), count);
    let empty = (owner + 1) % count;
    let output = rayscan()
        .args([
            "scan",
            "--target",
            "127.0.0.1",
            "--ports",
            "9",
            "--shard-index",
            &empty.to_string(),
            "--shard-count",
            &count.to_string(),
            "--json",
            "--no-db-update",
            "--no-service-detection",
            "--timeout",
            "1",
            "--quiet",
        ])
        .output()
        .expect("run empty shard");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let payload: Value = serde_json::from_slice(&output.stdout).expect("empty shard JSON");
    assert_eq!(payload["targets"], 0);
    assert_eq!(payload["open"].as_array().unwrap().len(), 0);
}

#[test]
fn distributed_plan_prints_shards_and_merge() {
    let output = rayscan()
        .args([
            "distributed",
            "plan",
            "--shards",
            "3",
            "--shell",
            "bash",
            "--",
            "scan",
            "--target",
            "192.0.2.0/30",
            "--ports",
            "80",
        ])
        .output()
        .expect("run distributed plan");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let script = String::from_utf8(output.stdout).expect("utf-8 script");
    assert!(script.contains("--shard-index 0"));
    assert!(script.contains("--shard-index 2"));
    assert!(script.contains("rayscan merge shards/shard-*.json"));
}

#[test]
fn json_scan_reports_an_open_port() {
    let server = banner_server();
    let port = server.port();
    let output = rayscan()
        .args([
            "scan",
            "--target",
            "127.0.0.1",
            "--ports",
            &port.to_string(),
            "--json",
            "--timeout",
            "1",
            "--quiet",
        ])
        .output()
        .expect("run rayscan scan");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let payload: Value = serde_json::from_slice(&output.stdout).expect("valid JSON output");
    assert_eq!(payload["open"][0]["host"], "127.0.0.1");
    assert_eq!(payload["open"][0]["port"], port);
    assert_eq!(payload["open"][0]["service"]["name"], "http");
    assert_eq!(payload["open"][0]["service"]["product"], "rayscan-lab");
    assert_eq!(payload["summary"]["open"], 1);
    server.stop();
}

#[test]
fn quiet_scan_emits_no_progress_on_stderr() {
    let server = banner_server();
    let port = server.port();
    let output = rayscan()
        .args([
            "scan",
            "--target",
            "127.0.0.1",
            "--ports",
            &port.to_string(),
            "--json",
            "--quiet",
        ])
        .output()
        .expect("run rayscan scan");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stderr.is_empty(),
        "quiet mode must not emit progress on stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    server.stop();
}

#[test]
fn no_service_detection_keeps_the_open_set_without_metadata() {
    let server = banner_server();
    let port = server.port();
    let output = rayscan()
        .args([
            "scan",
            "--target",
            "127.0.0.1",
            "--ports",
            &port.to_string(),
            "--json",
            "--timeout",
            "1",
            "--no-service-detection",
            "--quiet",
        ])
        .output()
        .expect("run rayscan scan");

    assert!(output.status.success());
    let payload: Value = serde_json::from_slice(&output.stdout).expect("valid JSON output");
    assert_eq!(payload["open"].as_array().unwrap().len(), 1);
    assert!(payload["open"][0].get("service").is_none());
    assert!(payload["open"][0].get("banner").is_none());
    server.stop();
}

#[test]
fn json_scan_reports_a_closed_port_without_listing_it() {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind test listener");
    let port = listener.local_addr().expect("listener address").port();
    drop(listener);

    let output = rayscan()
        .args([
            "scan",
            "--target",
            "127.0.0.1",
            "--ports",
            &port.to_string(),
            "--json",
            "--timeout",
            "1",
            "--quiet",
        ])
        .output()
        .expect("run rayscan scan");

    assert!(output.status.success());
    let payload: Value = serde_json::from_slice(&output.stdout).expect("valid JSON output");
    assert_eq!(payload["open"].as_array().unwrap().len(), 0);
    assert_eq!(payload["summary"]["closed"], 1);
}

#[test]
fn doctor_json_reports_capability_checks() {
    let output = rayscan()
        .args(["doctor", "--json"])
        .output()
        .expect("run rayscan doctor");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let payload: Value = serde_json::from_slice(&output.stdout).expect("valid JSON output");
    assert_eq!(payload["version"], env!("CARGO_PKG_VERSION"));
    let checks = payload["checks"].as_array().expect("checks array");
    assert!(checks.iter().any(|check| check["name"] == "raw-syn"));
    assert!(checks.iter().any(|check| check["name"] == "config"));
}

#[test]
fn interactive_requires_a_terminal() {
    let output = rayscan()
        .arg("interactive")
        .output()
        .expect("run rayscan interactive");

    assert_eq!(output.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("interactive mode requires a terminal")
    );
}

#[test]
fn invalid_ports_exit_with_usage_status() {
    let output = rayscan()
        .args(["scan", "--target", "127.0.0.1", "--ports", "0", "--json"])
        .output()
        .expect("run rayscan scan");

    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("out of range"));
}

#[test]
fn os_probes_requires_os_and_is_bounded() {
    let missing_os = rayscan()
        .args([
            "scan",
            "--target",
            "127.0.0.1",
            "--ports",
            "9",
            "--os-probes",
            "3",
            "--json",
        ])
        .output()
        .expect("run rayscan scan");
    assert_eq!(missing_os.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&missing_os.stderr).contains("--os-probes")
            || String::from_utf8_lossy(&missing_os.stderr).contains("requires")
    );

    let out_of_range = rayscan()
        .args([
            "scan",
            "--target",
            "127.0.0.1",
            "--ports",
            "9",
            "--os",
            "--os-probes",
            "0",
            "--json",
        ])
        .output()
        .expect("run rayscan scan");
    assert_eq!(out_of_range.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&out_of_range.stderr)
            .contains("--os-probes must be between 1 and 8")
    );
}

#[test]
fn ack_conflicts_and_unsupported_formats_are_rejected() {
    for extra in [
        vec!["--syn"],
        vec!["--os"],
        vec!["--udp"],
        vec!["--tls"],
        vec!["--verify"],
        vec!["--connect-only"],
        vec!["--discover-only"],
        vec!["--decoys", "192.0.2.10"],
        vec!["--scripts", "pack.toml"],
        vec!["--plugins", "probes.toml"],
    ] {
        let mut command = rayscan();
        command.args(["scan", "--target", "127.0.0.1", "--ports", "9", "--ack"]);
        command.args(&extra);
        command.arg("--json");
        let output = command.output().expect("run rayscan scan");
        assert_eq!(
            output.status.code(),
            Some(2),
            "expected a usage error for {extra:?}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let port_list = rayscan()
        .args([
            "scan",
            "--target",
            "127.0.0.1",
            "--ports",
            "9",
            "--ack",
            "--format",
            "port-list",
        ])
        .output()
        .expect("run rayscan scan");
    assert_eq!(port_list.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&port_list.stderr)
            .contains("--ack cannot be used with --format port-list or host-port")
    );
}

#[test]
fn probe_shaping_flags_are_validated() {
    let zero_ttl = rayscan()
        .args([
            "scan",
            "--target",
            "127.0.0.1",
            "--ports",
            "9",
            "--syn",
            "--ttl",
            "0",
            "--json",
        ])
        .output()
        .expect("run rayscan scan");
    assert_eq!(zero_ttl.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&zero_ttl.stderr).contains("--ttl must be between 1 and 255"));

    let ttl_without_raw = rayscan()
        .args([
            "scan",
            "--target",
            "127.0.0.1",
            "--ports",
            "9",
            "--ttl",
            "64",
            "--json",
        ])
        .output()
        .expect("run rayscan scan");
    assert_eq!(ttl_without_raw.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&ttl_without_raw.stderr)
            .contains("--ttl requires --syn, --ack, or --os")
    );

    let reversed_range = rayscan()
        .args([
            "scan",
            "--target",
            "127.0.0.1",
            "--ports",
            "9",
            "--syn",
            "--source-port-range",
            "40001-40000",
            "--json",
        ])
        .output()
        .expect("run rayscan scan");
    assert_eq!(reversed_range.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&reversed_range.stderr)
            .contains("--source-port-range requires 1 <= MIN <= MAX <= 65535")
    );

    let range_without_syn = rayscan()
        .args([
            "scan",
            "--target",
            "127.0.0.1",
            "--ports",
            "9",
            "--source-port-range",
            "40000-40100",
            "--json",
        ])
        .output()
        .expect("run rayscan scan");
    assert_eq!(range_without_syn.status.code(), Some(2));
}

#[test]
fn omitted_ports_defaults_to_well_known_range() {
    let output = rayscan()
        .args([
            "scan",
            "--target",
            "127.0.0.1",
            "--rate",
            "10000",
            "--workers",
            "50",
            "--timeout",
            "0.1",
            "--json",
            "--quiet",
        ])
        .output()
        .expect("run rayscan scan");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let payload: Value = serde_json::from_slice(&output.stdout).expect("valid JSON output");
    assert_eq!(payload["ports"], 1024);
}

#[test]
fn ot_preset_alias_expands_to_the_control_plane_port_set() {
    let output = rayscan()
        .args([
            "scan",
            "--target",
            "127.0.0.1",
            "--preset",
            "ics",
            "--rate",
            "10000",
            "--workers",
            "50",
            "--timeout",
            "0.1",
            "--json",
            "--quiet",
        ])
        .output()
        .expect("run rayscan scan");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let payload: Value = serde_json::from_slice(&output.stdout).expect("valid JSON output");
    assert_eq!(payload["ports"], 22);
}

#[test]
fn stealth_flag_runs_scan() {
    let server = banner_server();
    let port = server.port();
    let output = rayscan()
        .args([
            "scan",
            "--target",
            "127.0.0.1",
            "--ports",
            &port.to_string(),
            "--stealth",
            "--json",
            "--quiet",
        ])
        .output()
        .expect("run rayscan scan");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let payload: Value = serde_json::from_slice(&output.stdout).expect("valid JSON output");
    assert_eq!(payload["open"][0]["port"], port);
    assert_eq!(payload["summary"]["open"], 1);
    server.stop();
}

#[test]
fn scope_guard_blocks_unauthorized_target() {
    let temp_dir = std::env::temp_dir();
    let scope_path = temp_dir.join("test_scope_block.toml");
    std::fs::write(
        &scope_path,
        r#"
[scope]
program = "Engagement Alpha"
allow = ["10.0.0.0/8"]
"#,
    )
    .expect("write scope");

    let output = rayscan()
        .args([
            "scan",
            "--target",
            "127.0.0.1",
            "--ports",
            "80",
            "--scope",
            scope_path.to_str().unwrap(),
        ])
        .output()
        .expect("run rayscan scan");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("SCOPE VIOLATION"));
    assert!(stderr.contains("Engagement Alpha"));

    // Overriding with --force-out-of-scope succeeds
    let override_output = rayscan()
        .args([
            "scan",
            "--target",
            "127.0.0.1",
            "--ports",
            "80",
            "--scope",
            scope_path.to_str().unwrap(),
            "--force-out-of-scope",
            "--json",
            "--quiet",
        ])
        .output()
        .expect("run rayscan scan");

    assert!(override_output.status.success());
    let _ = std::fs::remove_file(scope_path);
}

#[test]
fn scope_guard_allows_authorized_target() {
    let server = banner_server();
    let port = server.port();
    let temp_dir = std::env::temp_dir();
    let scope_path = temp_dir.join("test_scope_allow.toml");
    std::fs::write(
        &scope_path,
        r#"
[scope]
program = "Localhost Lab"
allow = ["127.0.0.0/8"]
"#,
    )
    .expect("write scope");

    let output = rayscan()
        .args([
            "scan",
            "--target",
            "127.0.0.1",
            "--ports",
            &port.to_string(),
            "--scope",
            scope_path.to_str().unwrap(),
            "--json",
            "--quiet",
        ])
        .output()
        .expect("run rayscan scan");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let payload: Value = serde_json::from_slice(&output.stdout).expect("valid JSON output");
    assert_eq!(payload["open"][0]["port"], port);
    let _ = std::fs::remove_file(scope_path);
    server.stop();
}

#[test]
fn scope_guard_checks_domains_from_target_files() {
    let temp_dir = std::env::temp_dir();
    let scope_path = temp_dir.join("test_scope_file.toml");
    let targets_path = temp_dir.join("test_scope_targets.txt");
    std::fs::write(
        &scope_path,
        r#"
[scope]
program = "File Scope"
allow = ["127.0.0.0/8"]
deny = ["localhost"]
"#,
    )
    .expect("write scope");
    std::fs::write(&targets_path, "localhost\n").expect("write targets");

    let output = rayscan()
        .args([
            "scan",
            "--target-file",
            targets_path.to_str().unwrap(),
            "--ports",
            "80",
            "--scope",
            scope_path.to_str().unwrap(),
        ])
        .output()
        .expect("run rayscan scan");

    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("SCOPE VIOLATION"));
    let _ = std::fs::remove_file(scope_path);
    let _ = std::fs::remove_file(targets_path);
}

#[test]
fn stream_flag_emits_jsonl_records() {
    let server = banner_server();
    let port = server.port();
    let output = rayscan()
        .args([
            "scan",
            "--target",
            "127.0.0.1",
            "--ports",
            &port.to_string(),
            "--stream",
        ])
        .output()
        .expect("run rayscan scan");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut found_port = false;
    for line in stdout.lines() {
        if let Ok(parsed) = serde_json::from_str::<Value>(line)
            && parsed["port"] == port
            && parsed["state"] == "open"
        {
            found_port = true;
            break;
        }
    }
    assert!(
        found_port,
        "Stream output must contain line-by-line JSON with port {port}: {stdout}"
    );
    server.stop();
}

#[test]
fn host_port_format_lists_open_ports_for_pipelines() {
    let server = banner_server();
    let port = server.port();
    let output = rayscan()
        .args([
            "scan",
            "--target",
            "127.0.0.1",
            "--ports",
            &port.to_string(),
            "--format",
            "host-port",
            "--timeout",
            "1",
            "--quiet",
        ])
        .output()
        .expect("run rayscan scan");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout).trim(),
        format!("127.0.0.1:{port}")
    );
    server.stop();
}

#[test]
fn port_list_format_stdout_stays_machine_readable() {
    let server = banner_server();
    let port = server.port();
    let output = rayscan()
        .args([
            "scan",
            "--target",
            "127.0.0.1",
            "--ports",
            &port.to_string(),
            "--format",
            "port-list",
            "--tls",
            "--os",
            "--defense",
            "--timeout",
            "1",
        ])
        .output()
        .expect("run rayscan scan");

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    // RSC-BUG-002/003/004 regression: stdout for a machine-readable format
    // contains only the port list — no progress lines, no ANSI, no duplicate
    // ports and no defense intelligence blocks.
    assert!(
        stdout
            .trim_end()
            .chars()
            .all(|c| c.is_ascii_digit() || c == ','),
        "stdout must only contain a port list: {stdout:?}"
    );
    assert_eq!(stdout.trim(), port.to_string());

    // PROPOSAL-001 regression: progress phases auto-quiet for machine formats.
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("[tls]") && !stderr.contains("[os]"),
        "progress lines must be suppressed for machine-readable formats: {stderr:?}"
    );
    server.stop();
}

#[test]
fn exclude_ports_rejects_removing_the_entire_scan() {
    let server = banner_server();
    let port = server.port();
    let output = rayscan()
        .args([
            "scan",
            "--target",
            "127.0.0.1",
            "--ports",
            &port.to_string(),
            "--exclude-ports",
            &port.to_string(),
            "--quiet",
        ])
        .output()
        .expect("run rayscan scan");

    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("--exclude-ports removed every port"));
    server.stop();
}

#[test]
fn baseline_alerts_and_fail_on_change_drive_monitoring() {
    let server = banner_server();
    let port = server.port();
    let dir = std::env::temp_dir().join(format!("rayscan-monitor-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create test directory");
    let baseline = dir.join("baseline.json");
    let alert = dir.join("alert.txt");

    let first = rayscan()
        .args([
            "scan",
            "--target",
            "127.0.0.1",
            "--ports",
            &port.to_string(),
            "--save-baseline",
            baseline.to_str().expect("baseline path"),
            "--json",
            "--timeout",
            "1",
            "--quiet",
        ])
        .output()
        .expect("run baseline scan");
    assert!(
        first.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&first.stderr)
    );
    assert!(baseline.exists(), "baseline file must be written");

    let second = rayscan()
        .args([
            "scan",
            "--target",
            "127.0.0.1",
            "--ports",
            &port.to_string(),
            "--diff",
            baseline.to_str().expect("baseline path"),
            "--fail-on-change",
            "--alert-file",
            alert.to_str().expect("alert path"),
            "--quiet",
        ])
        .output()
        .expect("run unchanged scan");
    assert!(
        second.status.success(),
        "no changes must exit 0; stderr: {}",
        String::from_utf8_lossy(&second.stderr)
    );
    let unchanged = std::fs::read_to_string(&alert).expect("alert file");
    assert!(unchanged.contains("status: no changes"));

    let mut payload: Value =
        serde_json::from_str(&std::fs::read_to_string(&baseline).expect("read baseline"))
            .expect("baseline JSON");
    payload["open"] = serde_json::json!([]);
    if payload.get("results").is_some() {
        payload["results"] = serde_json::json!([]);
    }
    std::fs::write(
        &baseline,
        serde_json::to_string_pretty(&payload).expect("encode baseline"),
    )
    .expect("rewrite baseline");

    let third = rayscan()
        .args([
            "scan",
            "--target",
            "127.0.0.1",
            "--ports",
            &port.to_string(),
            "--diff",
            baseline.to_str().expect("baseline path"),
            "--fail-on-change",
            "--alert-file",
            alert.to_str().expect("alert path"),
            "--quiet",
        ])
        .output()
        .expect("run changed scan");
    assert_eq!(third.status.code(), Some(1));
    let changed = std::fs::read_to_string(&alert).expect("alert file");
    assert!(changed.contains("status: changes detected"));
    assert!(changed.contains(&format!("[+] NEW 127.0.0.1:{port}")));

    let _ = std::fs::remove_dir_all(&dir);
    server.stop();
}
#[test]
fn explain_shows_probe_identification_and_facts() {
    let server = banner_server();
    let port = server.port().to_string();
    let dir = std::env::temp_dir().join(format!("rayscan-probe-expl_{}", server.port()));
    std::fs::create_dir_all(&dir).expect("create probe temp dir");
    let pack = dir.join("pack.toml");
    std::fs::write(
        &pack,
        format!(
            r#"
name = "explain-test"
[[probe]]
name = "lab"
service = "rayscan-lab"
ports = [{port}]
send = "GET / HTTP/1.0\r\nHost: scan\r\n\r\n"
expect = "rayscan-lab"
product = "Rayscan Lab"
[probe.info]
server = 'Server: ([^\r\n]+)'
"#
        ),
    )
    .expect("write probe pack");

    let output = rayscan()
        .args([
            "scan",
            "--target",
            "127.0.0.1",
            "--ports",
            &port,
            "--plugins",
            pack.to_str().expect("pack path"),
            "--explain",
            &port,
            "--quiet",
        ])
        .output()
        .expect("run explained scan");
    assert!(
        output.status.success(),
        "scan failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("utf-8 output");
    assert!(stdout.contains("Identification:      plugin:explain-test/lab"));
    assert!(stdout.contains("Fact server: rayscan-lab"));

    let _ = std::fs::remove_dir_all(&dir);
    server.stop();
}

#[test]
fn probes_list_reports_built_in_packs() {
    let output = rayscan()
        .args(["probes", "list"])
        .output()
        .expect("run rayscan probes list");
    assert!(
        output.status.success(),
        "probes list failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("utf-8 output");
    assert!(stdout.contains("redis-info"));
    assert!(stdout.contains("modbus-device-id"));
    assert!(stdout.contains("vnc-handshake"));
    assert!(stdout.contains("jenkins-root"));
}

#[test]
fn probes_list_json_is_machine_readable() {
    let output = rayscan()
        .args(["probes", "list", "--json"])
        .output()
        .expect("run rayscan probes list --json");
    assert!(output.status.success());
    let probes: Value = serde_json::from_slice(&output.stdout).expect("probe JSON");
    let probes = probes.as_array().expect("probe array");
    assert!(probes.len() >= 20, "expected full built-in library");
    assert!(
        probes.iter().any(|probe| probe["tls"] == true),
        "expected TLS-aware probes in the listing"
    );
    let redis = probes
        .iter()
        .find(|probe| probe["name"] == "redis-info")
        .expect("redis probe");
    assert_eq!(redis["service"], "redis");
    assert_eq!(redis["steps"], 1);
}

#[test]
fn scripts_list_reports_manifest_metadata() {
    let dir = std::env::temp_dir().join(format!("rayscan-scripts-list-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create script temp dir");
    let manifest = dir.join("pack.toml");
    std::fs::write(
        &manifest,
        r#"
name = "test-scripts"
[[script]]
name = "lab-check"
description = "Synthetic check"
category = "vulnerability"
command = ["python3", "check.py"]
ports = [80, 443]
services = ["HTTP"]
timeout_ms = 2500
"#,
    )
    .expect("write script manifest");

    let output = rayscan()
        .args([
            "scripts",
            "list",
            manifest.to_str().expect("manifest path"),
            "--json",
        ])
        .output()
        .expect("run rayscan scripts list");
    assert!(
        output.status.success(),
        "scripts list failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let scripts: Value = serde_json::from_slice(&output.stdout).expect("script JSON");
    let scripts = scripts.as_array().expect("script array");
    assert_eq!(scripts.len(), 1);
    assert_eq!(scripts[0]["plugin"], "test-scripts/lab-check");
    assert_eq!(scripts[0]["category"], "vulnerability");
    assert_eq!(scripts[0]["danger"], "safe");
    assert_eq!(scripts[0]["timeout_ms"], 2500);
    assert_eq!(scripts[0]["services"][0], "http");

    let _ = std::fs::remove_dir_all(&dir);
}

/// A WASM module that returns `output` from `run` via the script ABI
/// (`alloc` + packed pointer/length).
fn wasm_module_emitting(output: &str) -> String {
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

#[test]
fn wasm_scripts_run_end_to_end() {
    let server = banner_server();
    let port = server.port().to_string();
    let dir = std::env::temp_dir().join(format!("rayscan-scripts-wasm-{}", server.port()));
    std::fs::create_dir_all(&dir).expect("create script temp dir");
    let output = r#"{"findings":[{"id":"wasm-lab","title":"Wasm finding","severity":"medium","confidence":0.8}],"service":{"name":"http","product":"Wasm Lab","version":"1.0"}}"#;
    std::fs::write(dir.join("check.wat"), wasm_module_emitting(output)).expect("write wasm module");
    let manifest = dir.join("pack.toml");
    std::fs::write(
        &manifest,
        r#"
name = "wasm-scripts"
[[script]]
name = "lab-check"
wasm = "check.wat"
services = ["http"]
timeout_ms = 3000
"#,
    )
    .expect("write wasm manifest");

    let listed = rayscan()
        .args([
            "scripts",
            "list",
            manifest.to_str().expect("manifest path"),
            "--json",
        ])
        .output()
        .expect("run rayscan scripts list");
    assert!(
        listed.status.success(),
        "scripts list failed: {}",
        String::from_utf8_lossy(&listed.stderr)
    );
    let scripts: Value = serde_json::from_slice(&listed.stdout).expect("script JSON");
    assert_eq!(scripts[0]["kind"], "wasm");
    assert!(
        scripts[0]["wasm_path"]
            .as_str()
            .is_some_and(|path| path.ends_with("check.wat"))
    );

    let scanned = rayscan()
        .args([
            "scan",
            "--target",
            "127.0.0.1",
            "--ports",
            &port,
            "--scripts",
            manifest.to_str().expect("manifest path"),
            "--json",
            "--quiet",
        ])
        .output()
        .expect("run scan with wasm scripts");
    assert!(
        scanned.status.success(),
        "scan failed: {}",
        String::from_utf8_lossy(&scanned.stderr)
    );
    let payload: Value = serde_json::from_slice(&scanned.stdout).expect("valid JSON output");
    let finding = &payload["open"][0]["findings"][0];
    assert_eq!(finding["title"], "Wasm finding");
    assert_eq!(finding["severity"], "medium");
    assert_eq!(finding["plugin"], "wasm-scripts/lab-check");
    assert_eq!(payload["open"][0]["service"]["product"], "Wasm Lab");

    let _ = std::fs::remove_dir_all(&dir);
    server.stop();
}

#[test]
fn script_library_install_list_scan_uninstall() {
    let server = banner_server();
    let port = server.port().to_string();
    let base = std::env::temp_dir().join(format!("rayscan-scripts-lib-{}", server.port()));
    let source = base.join("src").join("wasm-lib-pack");
    std::fs::create_dir_all(&source).expect("create source pack");
    let output = r#"{"findings":[{"title":"Library finding","severity":"low"}],"service":{"name":"http","product":"Library Lab","version":"1.1"}}"#;
    std::fs::write(source.join("check.wat"), wasm_module_emitting(output))
        .expect("write wasm module");
    std::fs::write(
        source.join("pack.toml"),
        "name = \"wasm-lib-pack\"\n[[script]]\nname = \"check\"\nwasm = \"check.wat\"\nservices = [\"http\"]\n",
    )
    .expect("write manifest");
    let library = base.join("library");

    let installed = rayscan()
        .args([
            "--scripts-dir",
            library.to_str().expect("library path"),
            "scripts",
            "install",
            source.to_str().expect("source path"),
        ])
        .output()
        .expect("install pack");
    assert!(
        installed.status.success(),
        "install failed: {}",
        String::from_utf8_lossy(&installed.stderr)
    );

    let info = rayscan()
        .args([
            "--scripts-dir",
            library.to_str().expect("library path"),
            "scripts",
            "library",
            "--json",
        ])
        .output()
        .expect("library info");
    assert!(info.status.success());
    let info: Value = serde_json::from_slice(&info.stdout).expect("library JSON");
    assert_eq!(info["exists"], true);
    assert!(
        info["path"]
            .as_str()
            .is_some_and(|path| path.ends_with("library"))
    );

    let listed = rayscan()
        .args([
            "--scripts-dir",
            library.to_str().expect("library path"),
            "scripts",
            "list",
            "--json",
        ])
        .output()
        .expect("list library");
    assert!(
        listed.status.success(),
        "list failed: {}",
        String::from_utf8_lossy(&listed.stderr)
    );
    let scripts: Value = serde_json::from_slice(&listed.stdout).expect("script JSON");
    assert_eq!(scripts[0]["plugin"], "wasm-lib-pack/check");
    assert_eq!(scripts[0]["kind"], "wasm");

    let scanned = rayscan()
        .args([
            "--scripts-dir",
            library.to_str().expect("library path"),
            "scan",
            "--target",
            "127.0.0.1",
            "--ports",
            &port,
            "--scripts-library",
            "--json",
            "--quiet",
        ])
        .output()
        .expect("scan with script library");
    assert!(
        scanned.status.success(),
        "scan failed: {}",
        String::from_utf8_lossy(&scanned.stderr)
    );
    let payload: Value = serde_json::from_slice(&scanned.stdout).expect("valid JSON output");
    assert_eq!(
        payload["open"][0]["findings"][0]["title"],
        "Library finding"
    );
    assert_eq!(payload["open"][0]["service"]["product"], "Library Lab");

    let removed = rayscan()
        .args([
            "--scripts-dir",
            library.to_str().expect("library path"),
            "scripts",
            "uninstall",
            "wasm-lib-pack",
        ])
        .output()
        .expect("uninstall pack");
    assert!(
        removed.status.success(),
        "uninstall failed: {}",
        String::from_utf8_lossy(&removed.stderr)
    );
    let empty = rayscan()
        .args([
            "--scripts-dir",
            library.to_str().expect("library path"),
            "scripts",
            "list",
        ])
        .output()
        .expect("list empty library");
    assert!(!empty.status.success(), "empty library must not list packs");

    let _ = std::fs::remove_dir_all(&base);
    server.stop();
}

#[test]
fn scripts_marketplace_rejects_incomplete_requests() {
    let base = std::env::temp_dir().join(format!("rayscan-market-cli-{}", std::process::id()));
    let library = base.join("library");
    let library = library.to_str().expect("library path");

    let search = rayscan()
        .args(["--scripts-dir", library, "scripts", "search"])
        .env_remove("RAYSCAN_SCRIPT_REGISTRY")
        .output()
        .expect("run scripts search");
    assert_eq!(search.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&search.stderr).contains("RAYSCAN_SCRIPT_REGISTRY"),
        "unexpected stderr: {}",
        String::from_utf8_lossy(&search.stderr)
    );

    let missing_digest = rayscan()
        .args([
            "--scripts-dir",
            library,
            "scripts",
            "install",
            "https://registry.example/pack.tar.gz",
        ])
        .output()
        .expect("run scripts install");
    assert_eq!(missing_digest.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&missing_digest.stderr).contains("--sha256"),
        "unexpected stderr: {}",
        String::from_utf8_lossy(&missing_digest.stderr)
    );

    let digest = "00".repeat(32);
    let conflicting = rayscan()
        .args([
            "--scripts-dir",
            library,
            "scripts",
            "install",
            "demo",
            "--registry",
            "https://registry.example/index.json",
            "--sha256",
            digest.as_str(),
        ])
        .output()
        .expect("run scripts install with registry");
    assert_eq!(conflicting.status.code(), Some(2));
    assert!(
        String::from_utf8_lossy(&conflicting.stderr).contains("--sha256"),
        "unexpected stderr: {}",
        String::from_utf8_lossy(&conflicting.stderr)
    );

    let _ = std::fs::remove_dir_all(&base);
}

#[cfg(unix)]
fn write_script_plugin(dir: &std::path::Path, danger: &str) -> std::path::PathBuf {
    std::fs::write(
        dir.join("plugin.sh"),
        "#!/bin/sh\ncat >/dev/null\nprintf '%s\\n' '{\"findings\":[{\"id\":\"lab\",\"title\":\"Lab finding\",\"severity\":\"high\",\"confidence\":0.9,\"description\":\"Synthetic finding\",\"evidence\":\"lab evidence\",\"cve\":[\"CVE-2024-1234\"],\"references\":[\"https://example.test/lab\"]}]}'\n",
    )
    .expect("write script plugin");
    let manifest = dir.join("pack.toml");
    std::fs::write(
        &manifest,
        format!(
            r#"
name = "test-scripts"
[[script]]
name = "lab-check"
description = "Synthetic check"
category = "vulnerability"
danger = "{danger}"
command = ["sh", "plugin.sh"]
services = ["http"]
timeout_ms = 3000
"#
        ),
    )
    .expect("write script manifest");
    manifest
}

#[cfg(unix)]
#[test]
fn script_findings_appear_in_json_and_explain() {
    let server = banner_server();
    let port = server.port().to_string();
    let dir = std::env::temp_dir().join(format!("rayscan-scripts-run-{}", server.port()));
    std::fs::create_dir_all(&dir).expect("create script temp dir");
    let manifest = write_script_plugin(&dir, "safe");

    let output = rayscan()
        .args([
            "scan",
            "--target",
            "127.0.0.1",
            "--ports",
            &port,
            "--scripts",
            manifest.to_str().expect("manifest path"),
            "--json",
            "--quiet",
        ])
        .output()
        .expect("run scan with scripts");
    assert!(
        output.status.success(),
        "scan failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let payload: Value = serde_json::from_slice(&output.stdout).expect("valid JSON output");
    let finding = &payload["open"][0]["findings"][0];
    assert_eq!(finding["title"], "Lab finding");
    assert_eq!(finding["severity"], "high");
    assert_eq!(finding["plugin"], "test-scripts/lab-check");
    assert_eq!(finding["cve"][0], "CVE-2024-1234");

    let explained = rayscan()
        .args([
            "scan",
            "--target",
            "127.0.0.1",
            "--ports",
            &port,
            "--scripts",
            manifest.to_str().expect("manifest path"),
            "--explain",
            &port,
            "--quiet",
        ])
        .output()
        .expect("run explained scan with scripts");
    assert!(explained.status.success());
    let stdout = String::from_utf8(explained.stdout).expect("utf-8 output");
    assert!(stdout.contains("Script Plugin Findings:"));
    assert!(stdout.contains("[HIGH] Lab finding"));
    assert!(stdout.contains("Finding [HIGH] Lab finding (plugin: test-scripts/lab-check)"));

    let _ = std::fs::remove_dir_all(&dir);
    server.stop();
}

#[cfg(unix)]
#[test]
fn intrusive_scripts_require_the_allow_flag() {
    let server = banner_server();
    let port = server.port().to_string();
    let dir = std::env::temp_dir().join(format!("rayscan-scripts-danger-{}", server.port()));
    std::fs::create_dir_all(&dir).expect("create script temp dir");
    let manifest = write_script_plugin(&dir, "intrusive");

    let blocked = rayscan()
        .args([
            "scan",
            "--target",
            "127.0.0.1",
            "--ports",
            &port,
            "--scripts",
            manifest.to_str().expect("manifest path"),
            "--json",
            "--quiet",
        ])
        .output()
        .expect("run scan with intrusive script");
    assert!(blocked.status.success());
    let payload: Value = serde_json::from_slice(&blocked.stdout).expect("valid JSON output");
    assert!(payload["open"][0].get("findings").is_none());

    let allowed = rayscan()
        .args([
            "scan",
            "--target",
            "127.0.0.1",
            "--ports",
            &port,
            "--scripts",
            manifest.to_str().expect("manifest path"),
            "--allow-intrusive",
            "--json",
            "--quiet",
        ])
        .output()
        .expect("run scan with allow-intrusive");
    assert!(allowed.status.success());
    let payload: Value = serde_json::from_slice(&allowed.stdout).expect("valid JSON output");
    assert_eq!(payload["open"][0]["findings"][0]["title"], "Lab finding");

    let _ = std::fs::remove_dir_all(&dir);
    server.stop();
}

#[cfg(unix)]
fn write_identify_plugin(dir: &std::path::Path) -> std::path::PathBuf {
    std::fs::write(
        dir.join("plugin.sh"),
        "#!/bin/sh\ncat >/dev/null\nprintf '%s\\n' '{\"findings\":[{\"title\":\"Low noise\",\"severity\":\"low\"},{\"title\":\"Serious issue\",\"severity\":\"high\"}],\"service\":{\"name\":\"LABENGINE\",\"product\":\"Lab Engine\",\"version\":\"1.2.3\",\"info\":{\"role\":\"test\"}}}'\n",
    )
    .expect("write script plugin");
    let manifest = dir.join("pack.toml");
    std::fs::write(
        &manifest,
        r#"
name = "test-scripts"
[[script]]
name = "lab-identify"
description = "Identifies the lab service and reports findings"
category = "discovery"
command = ["sh", "plugin.sh"]
timeout_ms = 3000
"#,
    )
    .expect("write script manifest");
    manifest
}

#[cfg(unix)]
#[test]
fn script_identifies_service_and_min_severity_filters() {
    let server = banner_server_with(b"LABENGINE 1.2 ready\r\n\r\n");
    let port = server.port().to_string();
    let dir = std::env::temp_dir().join(format!("rayscan-scripts-ident-{}", server.port()));
    std::fs::create_dir_all(&dir).expect("create script temp dir");
    let manifest = write_identify_plugin(&dir);

    let output = rayscan()
        .args([
            "scan",
            "--target",
            "127.0.0.1",
            "--ports",
            &port,
            "--scripts",
            manifest.to_str().expect("manifest path"),
            "--json",
            "--quiet",
        ])
        .output()
        .expect("run scan with identify script");
    assert!(
        output.status.success(),
        "scan failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let payload: Value = serde_json::from_slice(&output.stdout).expect("valid JSON output");
    assert_eq!(payload["open"][0]["service"]["name"], "labengine");
    assert_eq!(payload["open"][0]["service"]["product"], "Lab Engine");
    assert_eq!(payload["open"][0]["service"]["version"], "1.2.3");
    assert_eq!(payload["open"][0]["service"]["info"]["role"], "test");
    assert_eq!(
        payload["open"][0]["findings"]
            .as_array()
            .expect("findings")
            .len(),
        2
    );
    let stdout = String::from_utf8(output.stdout).expect("utf-8 output");
    assert!(stdout.contains("script:test-scripts/lab-identify"));

    let filtered = rayscan()
        .args([
            "scan",
            "--target",
            "127.0.0.1",
            "--ports",
            &port,
            "--scripts",
            manifest.to_str().expect("manifest path"),
            "--min-severity",
            "high",
            "--json",
            "--quiet",
        ])
        .output()
        .expect("run scan with min-severity");
    assert!(filtered.status.success());
    let payload: Value = serde_json::from_slice(&filtered.stdout).expect("valid JSON output");
    let findings = payload["open"][0]["findings"].as_array().expect("findings");
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0]["title"], "Serious issue");

    let _ = std::fs::remove_dir_all(&dir);
    server.stop();
}
