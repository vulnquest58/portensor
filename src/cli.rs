use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::time::Duration;

use clap::{ArgGroup, Args, Parser, Subcommand, ValueEnum};

use crate::config::{self, Profile, StateFilter};
use crate::error::AppError;
use crate::limits::MAX_WORKERS;
use crate::model::StateSet;
use crate::output::OutputFormat;
use crate::ports::PortPreset;
use crate::targets::AddressFamily;
use crate::theme::Theme;
use crate::tls::TlsMode;

#[derive(Debug, Parser)]
#[command(
    name = "rayscan",
    version,
    about = "An accuracy-first TCP port scanner",
    long_about = "An accuracy-first TCP/UDP scanner. Rayscan uses a bounded worker pool, \
                  adaptive per-host timeouts, a global rate limit, and a short \
                  service-verification read so a bare handshake from a tarpit or SYN \
                  proxy is not reported as an open service. Responsive services are \
                  identified from their banners, including common products and versions. \
                  On Linux, --syn performs raw SYN discovery and verifies responsive \
                  candidates over TCP. A UDP scanner is available for service \
                  detection on ports that accept UDP traffic.",
    arg_required_else_help = true,
    subcommand_required = true,
    after_help = "Examples:\n  rayscan scan --target 127.0.0.1 --ports 1-1024\n  rayscan scan -t 10.0.0.0/24 -p 22,80,443 --json\n  rayscan scan -t 10.77.0.2 -p 1-10000 --profile careful --show all\n  rayscan scan -t 10.77.0.2 --scripts ./scripts --json\n  rayscan scripts list ./scripts --json\n  rayscan scripts install ./my-pack\n  rayscan scan -t 10.77.0.2 --scripts-library\n  rayscan db intel --force\n  sudo rayscan scan -6 -t fe80::/64 --ndp -p 22,80,443"
)]
pub struct Cli {
    /// Color theme for tables, progress, and diagnostics.
    #[arg(long, global = true, value_enum, value_name = "THEME")]
    pub theme: Option<Theme>,

    /// Directory for the local NVD advisory database.
    #[arg(long, global = true, value_name = "DIR")]
    pub db_dir: Option<PathBuf>,

    /// Directory for the local script pack library.
    #[arg(long, global = true, value_name = "DIR")]
    pub scripts_dir: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
#[allow(clippy::large_enum_variant)]
pub enum Command {
    /// Scan TCP ports on one or more targets.
    Scan(ScanArgs),
    /// Compare two previous scan reports or state files to display differences.
    Diff(DiffArgs),
    /// Merge reports from distributed/sharded scans into one report.
    Merge(MergeArgs),
    /// Plan, coordinate, or execute distributed scans across multiple hosts.
    Distributed(DistributedArgs),
    /// Check permissions, terminal support, and scan capabilities.
    Doctor(DoctorArgs),
    /// Manage the local NVD CVE advisory database.
    Db(DbArgs),
    /// List built-in and custom probe packs.
    Probes(ProbesArgs),
    /// List and validate script plugin manifests (sidecar or WASM).
    Scripts(ScriptsArgs),
    /// Set up and run a scan with guided prompts.
    Interactive,
}

#[derive(Debug, Args)]
pub struct ProbesArgs {
    #[command(subcommand)]
    pub action: ProbesAction,
}

#[derive(Debug, Subcommand)]
pub enum ProbesAction {
    /// List probe packs and their probes.
    List(ProbesListArgs),
}

#[derive(Debug, Args)]
pub struct ProbesListArgs {
    /// Include probes from an additional pack file or directory.
    #[arg(long, value_name = "PATH")]
    pub plugins: Option<PathBuf>,

    /// Emit machine-readable JSON.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct ScriptsArgs {
    #[command(subcommand)]
    pub action: ScriptsAction,
}

#[derive(Debug, Subcommand)]
pub enum ScriptsAction {
    /// List and validate script plugin manifests.
    List(ScriptsListArgs),
    /// Search a remote script pack registry index.
    Search(ScriptsSearchArgs),
    /// Install a pack directory, archive URL, or registry pack into the local library.
    Install(ScriptsInstallArgs),
    /// Remove an installed pack from the local script library.
    Uninstall(ScriptsUninstallArgs),
    /// Print the local script library location.
    Library(ScriptsLibraryArgs),
}

#[derive(Debug, Args)]
pub struct ScriptsListArgs {
    /// Script manifest file or directory of *.toml manifests.
    /// Defaults to the local script library.
    #[arg(value_name = "PATH")]
    pub path: Option<PathBuf>,

    /// Emit machine-readable JSON.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct ScriptsSearchArgs {
    /// Case-insensitive filter matched against pack name, description, and tags.
    #[arg(value_name = "QUERY")]
    pub query: Option<String>,

    /// JSON registry index URL (or set RAYSCAN_SCRIPT_REGISTRY).
    #[arg(long, value_name = "URL")]
    pub registry: Option<String>,

    /// Emit machine-readable JSON.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct ScriptsInstallArgs {
    /// Pack directory, http(s) archive URL, or pack name with --registry.
    #[arg(value_name = "SOURCE")]
    pub source: String,

    /// Resolve SOURCE as a pack name from this registry index
    /// (or set RAYSCAN_SCRIPT_REGISTRY).
    #[arg(long, value_name = "URL")]
    pub registry: Option<String>,

    /// Expected SHA-256 digest of a direct archive URL (required for URLs).
    #[arg(long, value_name = "HEX")]
    pub sha256: Option<String>,

    /// Replace an existing installed pack of the same name.
    #[arg(long)]
    pub force: bool,
}

#[derive(Debug, Args)]
pub struct ScriptsUninstallArgs {
    /// Installed pack name (library subdirectory).
    #[arg(value_name = "NAME")]
    pub name: String,
}

#[derive(Debug, Args)]
pub struct ScriptsLibraryArgs {
    /// Emit machine-readable JSON.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct DbArgs {
    #[command(subcommand)]
    pub action: DbAction,
}

#[derive(Debug, Subcommand)]
pub enum DbAction {
    /// Download, verify, and index the latest NVD CVE feeds.
    Update(DbUpdateArgs),
    /// Show local advisory database status and coverage.
    Status(DbStatusArgs),
    /// Download and index the full CISA KEV catalog and current EPSS scores.
    Intel(DbIntelArgs),
}

#[derive(Debug, Args)]
pub struct DbUpdateArgs {
    /// Re-download feeds even when their published digest matches.
    #[arg(long)]
    pub force: bool,

    /// Year selection: all (default), 2002-2026, or 2024,2025,2026.
    #[arg(long, value_name = "SPEC")]
    pub years: Option<String>,

    /// Suppress progress output.
    #[arg(long)]
    pub quiet: bool,
}

#[derive(Debug, Args)]
pub struct DbStatusArgs {
    /// Emit machine-readable JSON.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct DbIntelArgs {
    /// Re-download feeds even when the cached copy is fresh.
    #[arg(long)]
    pub force: bool,

    /// Emit the refresh summary as JSON.
    #[arg(long)]
    pub json: bool,

    /// Suppress progress output.
    #[arg(long)]
    pub quiet: bool,
}

#[derive(Debug, Args)]
pub struct DiffArgs {
    /// Baseline JSON report or state file.
    #[arg(value_name = "BASELINE_FILE")]
    pub baseline: PathBuf,

    /// Current/comparison JSON report or state file.
    #[arg(value_name = "CURRENT_FILE")]
    pub current: PathBuf,

    /// Output differences in JSON format.
    #[arg(long)]
    pub json: bool,

    /// Exit with status 1 when any change is detected.
    #[arg(long)]
    pub fail_on_change: bool,

    /// Write a concise change alert to FILE (written on every run).
    #[arg(long, value_name = "FILE")]
    pub alert_file: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct MergeArgs {
    /// Input scan reports in JSON or JSONL format. Repeatable.
    #[arg(value_name = "FILE", required = true)]
    pub inputs: Vec<PathBuf>,

    /// Write the merged report to a file instead of stdout.
    #[arg(short, long, value_name = "FILE")]
    pub output: Option<PathBuf>,

    /// Emit one JSON result per line instead of a single report object.
    #[arg(long)]
    pub jsonl: bool,
}

#[derive(Debug, Args)]
pub struct DistributedArgs {
    #[command(subcommand)]
    pub action: DistributedAction,
}

#[derive(Debug, Subcommand)]
pub enum DistributedAction {
    /// Print a shell script that runs every shard locally and merges the reports.
    Plan(DistributedPlanArgs),
    /// Serve a coordinator that assigns shard jobs to polling workers or push agents.
    Serve(DistributedServeArgs),
    /// Poll a coordinator, execute assigned shard scans, and submit the reports.
    Worker(DistributedWorkerArgs),
    /// Listen for jobs pushed by a coordinator (inbound mode).
    Agent(DistributedAgentArgs),
}

#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum DistributedShell {
    Bash,
    Powershell,
}

#[derive(Debug, Args)]
pub struct DistributedPlanArgs {
    /// Number of deterministic target shards.
    #[arg(long, default_value_t = 8, value_name = "N")]
    pub shards: usize,

    /// Shell syntax for the generated script.
    #[arg(long, value_enum, default_value_t = DistributedShell::Bash)]
    pub shell: DistributedShell,

    /// Write the script to FILE instead of stdout.
    #[arg(short, long, value_name = "FILE")]
    pub output: Option<PathBuf>,

    /// Scan command and arguments, prefixed with `scan`.
    #[arg(
        last = true,
        required = true,
        num_args = 1..,
        allow_hyphen_values = true,
        value_name = "SCAN_ARGS"
    )]
    pub scan_args: Vec<String>,
}

#[derive(Debug, Args)]
pub struct DistributedServeArgs {
    /// Coordinator listen address. Set --tls-cert and --tls-key to serve HTTPS.
    #[arg(long, default_value = "127.0.0.1:9090", value_name = "ADDR")]
    pub listen: String,

    /// Bearer token (or RAYSCAN_DISTRIBUTED_TOKEN), at least 16 characters.
    #[arg(long, value_name = "TOKEN")]
    pub token: Option<String>,

    /// PEM certificate chain for the coordinator's HTTPS listener.
    #[arg(long, value_name = "FILE", requires = "tls_key")]
    pub tls_cert: Option<PathBuf>,

    /// PEM private key for the coordinator's HTTPS listener.
    #[arg(long, value_name = "FILE", requires = "tls_cert")]
    pub tls_key: Option<PathBuf>,

    /// PEM CA bundle used to verify push-agent HTTPS certificates.
    #[arg(long, value_name = "FILE", conflicts_with = "insecure_tls")]
    pub ca_cert: Option<PathBuf>,

    /// Accept any push-agent HTTPS certificate. Use only for testing.
    #[arg(long, conflicts_with = "ca_cert")]
    pub insecure_tls: bool,

    /// Number of deterministic target shards/jobs.
    #[arg(long, default_value_t = 8, value_name = "N")]
    pub shards: usize,

    /// Write the merged report to FILE.
    #[arg(long, default_value = "rayscan-distributed.json", value_name = "FILE")]
    pub out: PathBuf,

    /// Seconds a worker may hold a job without a heartbeat before it is requeued.
    #[arg(long, default_value_t = 300, value_name = "SECS")]
    pub lease_secs: u64,

    /// Attempts per shard before it is marked failed.
    #[arg(long, default_value_t = 3, value_name = "N")]
    pub max_attempts: u32,

    /// Per-job execution timeout in seconds.
    #[arg(long, default_value_t = 3600, value_name = "SECS")]
    pub job_timeout_secs: u64,

    /// Agent base URLs for push mode. Omit for polling-worker mode.
    #[arg(long, value_delimiter = ',', value_name = "URL,URL")]
    pub agents: Vec<String>,

    /// Scan command and arguments, prefixed with `scan`.
    #[arg(
        last = true,
        required = true,
        num_args = 1..,
        allow_hyphen_values = true,
        value_name = "SCAN_ARGS"
    )]
    pub scan_args: Vec<String>,
}

#[derive(Debug, Args)]
pub struct DistributedWorkerArgs {
    /// Coordinator base URL, for example http://10.0.0.5:9090 or
    /// https://10.0.0.5:9090.
    #[arg(long, value_name = "URL")]
    pub coordinator: String,

    /// Bearer token (or RAYSCAN_DISTRIBUTED_TOKEN), at least 16 characters.
    #[arg(long, value_name = "TOKEN")]
    pub token: Option<String>,

    /// Worker display name (defaults to the hostname).
    #[arg(long, value_name = "NAME")]
    pub name: Option<String>,

    /// PEM CA bundle used to verify the coordinator's HTTPS certificate.
    #[arg(long, value_name = "FILE", conflicts_with = "insecure_tls")]
    pub ca_cert: Option<PathBuf>,

    /// Accept any coordinator HTTPS certificate. Use only for testing.
    #[arg(long, conflicts_with = "ca_cert")]
    pub insecure_tls: bool,

    /// Claim and run a single job, then exit.
    #[arg(long)]
    pub once: bool,

    /// Stop after N jobs (0 means unlimited).
    #[arg(long, default_value_t = 0, value_name = "N")]
    pub max_jobs: u64,
}

#[derive(Debug, Args)]
pub struct DistributedAgentArgs {
    /// Agent listen address. Set --tls-cert and --tls-key to serve HTTPS.
    #[arg(long, default_value = "127.0.0.1:9091", value_name = "ADDR")]
    pub listen: String,

    /// Bearer token (or RAYSCAN_DISTRIBUTED_TOKEN), at least 16 characters.
    #[arg(long, value_name = "TOKEN")]
    pub token: Option<String>,

    /// PEM certificate chain for the agent's HTTPS listener.
    #[arg(long, value_name = "FILE", requires = "tls_key")]
    pub tls_cert: Option<PathBuf>,

    /// PEM private key for the agent's HTTPS listener.
    #[arg(long, value_name = "FILE", requires = "tls_cert")]
    pub tls_key: Option<PathBuf>,

    /// Maximum scans executed concurrently on this agent.
    #[arg(long, default_value_t = 1, value_name = "N")]
    pub concurrency: usize,
}

#[derive(Debug, Args)]
pub struct DoctorArgs {
    /// Emit machine-readable JSON.
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
#[command(group(
    ArgGroup::new("target_source")
        .required(true)
        .multiple(true)
        .args(["target", "target_file"])
))]
pub struct ScanArgs {
    /// Target host, IP, CIDR, range, or file path. Repeatable.
    #[arg(short = 't', long = "target", value_name = "TARGET")]
    pub target: Vec<String>,

    /// Read targets from a file, one target or CIDR per line. Repeatable.
    #[arg(long = "target-file", value_name = "FILE")]
    pub target_file: Vec<PathBuf>,

    /// Exclude a target, CIDR, range, or @file. Repeatable.
    #[arg(long, value_name = "TARGET")]
    pub exclude: Vec<String>,

    /// Ports to scan, for example 80,443,8000-8100. Defaults to 1-1024 if omitted.
    #[arg(short = 'p', long, value_name = "PORTS")]
    pub ports: Option<String>,

    /// Scan the top N most common ports (e.g. 10, 100, 1000).
    #[arg(long, value_name = "N", conflicts_with = "ports")]
    pub top_ports: Option<usize>,

    /// Port preset bundle (e.g. dc, win, web, linux, ot, full, q).
    #[arg(long, value_enum, conflicts_with_all = ["ports", "top_ports"], value_name = "PRESET")]
    pub preset: Option<PortPreset>,

    /// Exclude ports from the scan, for example 22,135,445 or 8000-8100.
    #[arg(long, value_name = "PORTS")]
    pub exclude_ports: Option<String>,

    /// Emit the benchmark-compatible JSON report.
    #[arg(long, conflicts_with = "format")]
    pub json: bool,

    /// Output format.
    #[arg(long, value_enum)]
    pub format: Option<OutputFormat>,

    /// Write results to a file instead of stdout.
    #[arg(short = 'o', long, value_name = "FILE")]
    pub output: Option<PathBuf>,

    /// Configuration profile.
    #[arg(long, value_enum)]
    pub profile: Option<Profile>,

    /// Enable stealth mode (slow rate 20 pps, randomized order, high retries).
    #[arg(long)]
    pub stealth: bool,

    /// Read settings from a TOML file. Defaults to rayscan.toml if present.
    #[arg(long, value_name = "FILE")]
    pub config: Option<PathBuf>,

    /// Per-connect timeout ceiling in seconds.
    #[arg(long, value_name = "SECONDS")]
    pub timeout: Option<f64>,

    /// How long to wait for a banner before calling a handshake silent, in ms.
    #[arg(long, value_name = "MS")]
    pub probe_timeout_ms: Option<u64>,

    /// Per-connect timeout ceiling in milliseconds. Overrides --timeout.
    #[arg(long, value_name = "MS")]
    pub connect_timeout_ms: Option<u64>,

    /// Global probes per second. 0 means unlimited.
    #[arg(long, visible_alias = "max-rate", value_name = "N")]
    pub rate: Option<u64>,

    /// Worker count. 0 means automatic: cores × 32 capped at 512, bounded by RLIMIT_NOFILE.
    #[arg(long, value_name = "N")]
    pub workers: Option<usize>,

    /// Retries for local resource failures such as EMFILE.
    #[arg(long, value_name = "N")]
    pub retries: Option<u32>,

    /// Shuffle target and port order.
    #[arg(long, conflicts_with = "sequential")]
    pub randomize: bool,

    /// Keep target and port order. Overrides config randomize.
    #[arg(long)]
    pub sequential: bool,

    /// Maximum random delay before each probe, in milliseconds (0-5000).
    #[arg(long, value_name = "MS")]
    pub jitter_ms: Option<u64>,

    /// Spoofed source addresses for decoy probes, comma-separated (max 8).
    /// Requires --syn.
    #[arg(long, requires = "syn", value_name = "IP,IP")]
    pub decoys: Option<String>,

    /// Fragment raw SYN probes into IP fragments of this payload size
    /// (multiple of 8, 8-1480). Requires --syn.
    #[arg(long, requires = "syn", value_name = "BYTES")]
    pub fragment_size: Option<usize>,

    /// IP TTL / IPv6 hop limit for raw SYN, ACK, and OS fingerprint probes (1-255).
    /// Requires --syn, --ack, or --os.
    #[arg(long, value_name = "N")]
    pub ttl: Option<u8>,

    /// Source port range for raw SYN/ACK probes, as MIN-MAX (1-65535).
    /// Requires --syn or --ack.
    #[arg(long, value_name = "MIN-MAX")]
    pub source_port_range: Option<String>,

    /// Scan most common ports first to minimize time-to-first-result.
    #[arg(long, conflicts_with = "randomize")]
    pub top_ports_first: bool,

    /// Disable top ports prioritization (keep sequential or natural order).
    #[arg(long, conflicts_with = "top_ports_first")]
    pub no_top_ports_first: bool,

    /// Fast discovery mode: report open ports immediately without service/banner inspection.
    #[arg(long, conflicts_with = "verify")]
    pub discover_only: bool,

    /// Disable real-time live results table streaming during scan.
    #[arg(long)]
    pub no_live: bool,

    /// Report handshake success as open without banner or connect verification.
    #[arg(long, conflicts_with = "verify")]
    pub connect_only: bool,

    /// Verify that a handshake yields a banner or immediate close.
    #[arg(long)]
    pub verify: bool,

    /// Disable banner-based service and version detection.
    #[arg(long)]
    pub no_service_detection: bool,

    /// Enable UDP service detection (passive banner read + optional active probe).
    #[arg(long)]
    pub udp: bool,

    /// Disable UDP active probe; only perform the initial passive banner read.
    #[arg(long)]
    pub no_udp_probe: bool,

    /// Inspect TLS on every open TCP port (certificate, version, cipher).
    #[arg(long, conflicts_with = "no_tls")]
    pub tls: bool,

    /// Disable automatic TLS inspection of known TLS/STARTTLS ports.
    #[arg(long)]
    pub no_tls: bool,

    /// Enable OS fingerprinting via TCP/IP stack analysis (requires root/CAP_NET_RAW).
    /// Probes up to --os-probes open ports per host and classifies the SYN-ACK replies.
    #[arg(long)]
    pub os: bool,

    /// Open-port samples per host for the OS fingerprint consensus (1-8, default: 3).
    #[arg(long, value_name = "N", requires = "os")]
    pub os_probes: Option<usize>,

    /// Show every port state.
    #[arg(long)]
    pub all_states: bool,

    /// States to display. Repeat or comma-separate.
    #[arg(long, value_enum, value_delimiter = ',', value_name = "STATE")]
    pub show: Vec<StateFilter>,

    /// Resolve and scan only IPv4 targets.
    #[arg(short = '4', long, conflicts_with = "ipv6")]
    pub ipv4: bool,

    /// Resolve and scan only IPv6 targets.
    #[arg(short = '6', long)]
    pub ipv6: bool,

    /// Suppress progress and status messages.
    #[arg(short = 'q', long)]
    pub quiet: bool,

    /// Use raw SYN discovery, then verify responsive ports (root/CAP_NET_RAW, Linux only).
    #[arg(long)]
    pub syn: bool,

    /// TCP ACK scan to map firewall filtering (root/CAP_NET_RAW, Linux only).
    /// Unfiltered ports answer with RST; filtered ports stay silent.
    #[arg(
        long,
        conflicts_with_all = [
            "syn",
            "os",
            "udp",
            "tls",
            "verify",
            "connect_only",
            "discover_only",
            "decoys",
            "plugins",
            "scripts",
            "scripts_library",
        ]
    )]
    pub ack: bool,

    /// Disable AIMD adaptive rate control during raw SYN scanning.
    #[arg(long)]
    pub no_aimd: bool,

    /// Enable adaptive rate control for connect scans (detect rate limiting and back off).
    #[arg(long)]
    pub rate_auto: bool,

    /// Maximum concurrent connect attempts per target host (0 = unlimited).
    #[arg(long, value_name = "N")]
    pub host_concurrency: Option<usize>,

    /// AIMD minimum rate floor in packets per second (default: 100).
    #[arg(long, value_name = "N")]
    pub aimd_min_rate: Option<u64>,

    /// Rate used for SYN retransmission passes in packets per second.
    /// 0 means auto (rate / 4, minimum 100). Default: 0.
    #[arg(long, value_name = "N")]
    pub retry_rate: Option<u64>,

    /// Per-host SYN-open count above which the host is treated as anomalous
    /// (tarpit/SYN-proxy farm) and verification is sampled.  0 disables.
    /// Default: 1000.
    #[arg(long, value_name = "N")]
    pub anomaly_threshold: Option<u32>,

    /// Resume a previous interrupted scan from a saved state file.
    /// Ports already probed in the state file are skipped; results are merged.
    #[arg(long, value_name = "FILE")]
    pub resume: Option<PathBuf>,

    /// Save scan state to a file on completion or interruption (Ctrl-C).
    /// Use with --resume to continue an interrupted scan.
    #[arg(long, value_name = "FILE")]
    pub save_state: Option<PathBuf>,

    /// Filter results to only show ports with confidence score >= N percent (0-100).
    #[arg(long, value_name = "PERCENT")]
    pub min_confidence: Option<u8>,

    /// Print comprehensive evidence and accuracy breakdown for all ports or a specific port.
    #[arg(long, num_args = 0..=1, default_missing_value = "0", value_name = "PORT")]
    pub explain: Option<u16>,

    /// Always display detailed defense and middlebox intelligence assessment.
    #[arg(long)]
    pub defense: bool,

    /// Correlate detected service versions against the local and bundled CVE advisory databases.
    #[arg(long)]
    pub advisories: bool,

    /// Skip the automatic NVD advisory database refresh check before scanning.
    #[arg(long)]
    pub no_db_update: bool,

    /// Compare scan results against a previous scan JSON report or state file to detect changes.
    #[arg(
        long,
        visible_alias = "compare",
        alias = "compare-to",
        value_name = "FILE"
    )]
    pub diff: Option<PathBuf>,

    /// Save the final report as a JSON baseline for future --diff comparisons.
    #[arg(long, value_name = "FILE")]
    pub save_baseline: Option<PathBuf>,

    /// Write a concise change alert to FILE (requires --diff; written on every run).
    #[arg(long, value_name = "FILE", requires = "diff")]
    pub alert_file: Option<PathBuf>,

    /// Exit with status 1 when --diff detects any new, gone, or modified port.
    #[arg(long, requires = "diff")]
    pub fail_on_change: bool,

    /// Discover responsive hosts with ICMP echo/TCP ping before scanning.
    #[arg(long)]
    pub ping_sweep: bool,

    /// Ping probes per host (1-10). Requires --ping-sweep.
    #[arg(long, value_name = "N", requires = "ping_sweep")]
    pub ping_count: Option<u8>,

    /// Per-ping timeout in milliseconds (50-10000). Requires --ping-sweep.
    #[arg(long, value_name = "MS", requires = "ping_sweep")]
    pub ping_timeout_ms: Option<u64>,

    /// Discover local IPv6 neighbors with an NDP all-nodes multicast probe.
    /// Expands broad IPv6 CIDRs such as /64 instead of enumerating every address.
    #[arg(long, requires = "ipv6")]
    pub ndp: bool,

    /// NDP discovery timeout in milliseconds (50-5000). Requires --ndp.
    #[arg(long, value_name = "MS", requires = "ndp")]
    pub ndp_timeout_ms: Option<u64>,

    /// Directory or TOML file with declarative probe packs.
    #[arg(long, value_name = "PATH")]
    pub plugins: Option<PathBuf>,

    /// TOML manifest or directory of script plugin manifests (sidecar or WASM).
    /// Repeatable; every path contributes packs to the same registry.
    #[arg(long, value_name = "PATH")]
    pub scripts: Vec<PathBuf>,

    /// Load script packs installed in the local library (see `rayscan scripts`).
    #[arg(long)]
    pub scripts_library: bool,

    /// Allow script plugins whose manifest sets danger = "intrusive".
    #[arg(long)]
    pub allow_intrusive: bool,

    /// Drop script findings below this severity (info < low < medium < high < critical).
    #[arg(long, value_enum, value_name = "SEVERITY")]
    pub min_severity: Option<crate::script::FindingSeverity>,

    /// Scope definition file (TOML or plaintext) specifying authorized target boundaries.
    #[arg(long = "scope", visible_alias = "scope-file", value_name = "FILE")]
    pub scope: Option<PathBuf>,

    /// Force scan execution even if targets violate the Scope Guard definition.
    #[arg(long = "force-out-of-scope")]
    pub force_out_of_scope: bool,

    /// Filter advisory findings to only display services with CISA Known Exploited Vulnerabilities.
    #[arg(long = "kev-only")]
    pub kev_only: bool,

    /// Filter advisory findings to those with EPSS exploitation probability >= SCORE (0.0-1.0).
    #[arg(long = "min-epss", value_name = "SCORE")]
    pub min_epss: Option<f32>,

    /// Stream JSONL port findings immediately to stdout as each candidate is verified.
    #[arg(long = "stream")]
    pub stream: bool,

    /// Scan only this shard of the target list (0-based). Requires --shard-count.
    #[arg(long, value_name = "N")]
    pub shard_index: Option<usize>,

    /// Split targets into N deterministic shards for distributed scans. Requires --shard-index.
    #[arg(long, value_name = "N")]
    pub shard_count: Option<usize>,
}

#[derive(Clone, Debug)]
pub struct ResolvedConfig {
    pub timeout: Duration,
    pub probe_timeout: Duration,
    pub rate: u64,
    pub workers: usize,
    pub retries: u32,
    pub randomize: bool,
    pub connect_only: bool,
    pub service_detection: bool,
    pub udp_detection: bool,
    /// Enable OS fingerprinting stage (Phase 5).
    pub os_detection: bool,
    /// Open-port samples per host for the OS fingerprint consensus.
    pub os_probes: usize,
    pub format: OutputFormat,
    pub show: StateSet,
    pub family: AddressFamily,
    pub syn_mode: bool,
    /// Raw TCP ACK scan for firewall filtered/unfiltered mapping.
    pub ack_mode: bool,
    /// Enable AIMD adaptive rate control during SYN scan.
    pub aimd: bool,
    /// AIMD minimum rate floor in packets per second.
    pub aimd_min_pps: u64,
    /// Enable adaptive rate control for connect scans.
    pub rate_auto: bool,
    /// Maximum concurrent connect attempts per target host (0 = unlimited).
    pub host_concurrency: usize,
    /// Per-host SYN-open count above which the host is treated as an anomaly.
    /// `0` disables anomaly detection.
    pub anomaly_threshold: u32,
    /// Scan most common ports first.
    pub top_ports_first: bool,
    /// Stream live results table during scan.
    pub live_table: bool,
    /// Path to a saved state file to resume from.
    pub resume_file: Option<PathBuf>,
    /// Path to write the scan state on completion or interruption.
    pub save_state_file: Option<PathBuf>,
    /// Selected color theme.
    pub theme: Theme,
    /// Minimum confidence percentage filter.
    pub min_confidence: Option<u8>,
    /// Port to explain (0 means all open ports).
    pub explain: Option<u16>,
    /// Display defense and middlebox intelligence assessment.
    pub defense: bool,
    /// Correlate detected service versions against the local and bundled advisory databases.
    pub advisories: bool,
    /// Skip the automatic database refresh check before scanning.
    pub no_db_update: bool,
    /// Path to baseline report file to compute diff against.
    pub diff_file: Option<PathBuf>,
    /// Optional probe pack file or directory.
    pub plugins: Option<PathBuf>,
    /// Optional script plugin manifest files or directories.
    pub scripts: Vec<PathBuf>,
    /// Load packs from the local script library.
    pub scripts_library: bool,
    /// Run script plugins marked danger = "intrusive".
    pub allow_intrusive: bool,
    /// Minimum script finding severity kept in output.
    pub min_severity: crate::script::FindingSeverity,
    /// Discover responsive hosts before scanning.
    pub ping_sweep: bool,
    /// ICMP/TCP ping probes per host.
    pub ping_count: u8,
    /// Per-ping timeout.
    pub ping_timeout: Duration,
    /// Discover local IPv6 neighbors through NDP multicast before scanning.
    pub ndp: bool,
    /// NDP discovery timeout.
    pub ndp_timeout: Duration,
    /// Maximum random delay before each probe.
    pub jitter: Duration,
    /// Spoofed decoy source addresses for raw SYN scans.
    pub decoys: Vec<Ipv4Addr>,
    /// IPv4 payload size per fragment for raw SYN scans.
    pub fragment_size: Option<usize>,
    /// IP TTL / IPv6 hop limit for raw probes.
    pub ttl: Option<u8>,
    /// Source port range for raw SYN probes.
    pub source_port_range: Option<(u16, u16)>,
    /// TLS inspection policy.
    pub tls_mode: TlsMode,
    /// Optional `(index, count)` target shard selection.
    pub shard: Option<(usize, usize)>,
    /// Authorized target boundary definition.
    pub scope: Option<PathBuf>,
    /// Bypass Scope Guard enforcement with warnings.
    pub force_out_of_scope: bool,
    /// Filter to CISA KEV findings only.
    pub kev_only: bool,
    /// Minimum EPSS probability threshold.
    pub min_epss: Option<f32>,
    /// Real-time JSONL streaming output.
    pub stream: bool,
    /// Ports excluded from the scan.
    pub exclude_ports: Vec<u16>,
    /// Path to write the JSON baseline after the scan.
    pub save_baseline: Option<PathBuf>,
    /// Path to write the change alert when a diff is computed.
    pub alert_file: Option<PathBuf>,
    /// Exit with status 1 when the diff detects changes.
    pub fail_on_change: bool,
}

impl ScanArgs {
    pub fn resolve(&self) -> Result<ResolvedConfig, AppError> {
        let shard = crate::shard::validate(self.shard_index, self.shard_count)?;
        let file = config::load(self.config.as_deref())?;
        let profile = if self.stealth {
            self.profile.unwrap_or(Profile::Stealth)
        } else {
            self.profile.or(file.profile).unwrap_or_default()
        };
        let defaults = profile.defaults();

        let timeout_seconds = self
            .timeout
            .or(file.timeout)
            .unwrap_or(defaults.timeout_seconds);
        if !timeout_seconds.is_finite() || timeout_seconds <= 0.0 || timeout_seconds > 300.0 {
            return Err(AppError::usage(
                "--timeout must be greater than 0 and at most 300 seconds",
            ));
        }

        let timeout = if let Some(ms) = self.connect_timeout_ms {
            if !(1..=300_000).contains(&ms) {
                return Err(AppError::usage(
                    "--connect-timeout-ms must be between 1 and 300000",
                ));
            }
            Duration::from_millis(ms)
        } else {
            Duration::from_secs_f64(timeout_seconds)
        };

        let probe_timeout_ms = self
            .probe_timeout_ms
            .or(file.probe_timeout_ms)
            .unwrap_or(defaults.probe_timeout_ms);
        if !(10..=60_000).contains(&probe_timeout_ms) {
            return Err(AppError::usage(
                "--probe-timeout-ms must be between 10 and 60000",
            ));
        }

        if self.ack {
            let conflicts = [
                (self.syn, "--syn"),
                (self.os, "--os"),
                (self.udp, "--udp"),
                (self.verify, "--verify"),
                (self.connect_only, "--connect-only"),
                (self.discover_only, "--discover-only"),
                (self.tls, "--tls"),
                (self.decoys.is_some(), "--decoys"),
                (self.plugins.is_some(), "--plugins"),
                (!self.scripts.is_empty(), "--scripts"),
                (self.scripts_library, "--scripts-library"),
            ];
            if let Some((_, flag)) = conflicts.iter().find(|(enabled, _)| *enabled) {
                return Err(AppError::usage(format!(
                    "--ack cannot be combined with {flag}"
                )));
            }
        }

        let rate = self.rate.or(file.rate).unwrap_or(defaults.rate);
        if rate > 1_000_000 {
            return Err(AppError::usage("--rate must be at most 1000000"));
        }
        let host_concurrency = self.host_concurrency.or(file.host_concurrency).unwrap_or(0);
        if host_concurrency > MAX_WORKERS {
            return Err(AppError::usage(format!(
                "--host-concurrency must be at most {MAX_WORKERS}"
            )));
        }

        let os_probes = self
            .os_probes
            .or(file.os_probes)
            .unwrap_or(crate::fingerprint::DEFAULT_OS_PROBES);
        if !(1..=crate::fingerprint::MAX_OS_PROBES).contains(&os_probes) {
            return Err(AppError::usage(format!(
                "--os-probes must be between 1 and {}",
                crate::fingerprint::MAX_OS_PROBES
            )));
        }

        let ttl = self.ttl.or(file.ttl);
        if ttl == Some(0) {
            return Err(AppError::usage("--ttl must be between 1 and 255"));
        }
        if self.ttl.is_some() && !self.syn && !self.ack && !self.os {
            return Err(AppError::usage("--ttl requires --syn, --ack, or --os"));
        }

        let source_port_range = parse_source_port_range(
            self.source_port_range
                .as_deref()
                .or(file.source_port_range.as_deref()),
        )?;
        if self.source_port_range.is_some() && !self.syn && !self.ack {
            return Err(AppError::usage(
                "--source-port-range requires --syn or --ack",
            ));
        }

        let workers = self.workers.or(file.workers).unwrap_or(defaults.workers);
        if workers > MAX_WORKERS {
            return Err(AppError::usage(format!(
                "--workers must be at most {MAX_WORKERS}"
            )));
        }

        let retries = self.retries.or(file.retries).unwrap_or(defaults.retries);
        if retries > 10 {
            return Err(AppError::usage("--retries must be at most 10"));
        }

        let randomize = if self.randomize || (self.stealth && !self.sequential) {
            true
        } else if self.sequential {
            false
        } else {
            file.randomize.unwrap_or(false)
        };

        let connect_only = !self.ack
            && if self.discover_only || self.connect_only {
                true
            } else if self.verify {
                false
            } else {
                file.connect_only.unwrap_or(false)
            };

        let service_detection = if self.discover_only || self.no_service_detection {
            false
        } else {
            file.service_detection.unwrap_or(true)
        } && !connect_only
            && !self.ack;

        let udp_detection = if self.no_udp_probe {
            false
        } else {
            file.udp_probe.unwrap_or(true)
        } && self.udp
            && !self.ack;

        let format = if self.json {
            OutputFormat::Json
        } else {
            self.format.or(file.format).unwrap_or(OutputFormat::Table)
        };
        if self.ack && matches!(format, OutputFormat::PortList | OutputFormat::HostPort) {
            return Err(AppError::usage(
                "--ack cannot be used with --format port-list or host-port",
            ));
        }

        let show = if self.all_states {
            StateSet::all()
        } else if !self.show.is_empty() {
            config::state_set(&self.show)
        } else if let Some(filters) = file.show.as_deref() {
            config::state_set(filters)
        } else if self.ack {
            StateSet::unfiltered()
        } else if format == OutputFormat::PortList {
            // Discovery stage: silent means the TCP handshake completed but
            // the listener held mute, so the port still belongs in the list.
            let mut discovery = StateSet::open();
            discovery.insert(crate::model::PortState::Silent);
            discovery
        } else {
            StateSet::open()
        };

        let family = if self.ipv4 {
            AddressFamily::V4
        } else if self.ipv6 {
            AddressFamily::V6
        } else {
            AddressFamily::Any
        };

        let top_ports_first = if self.no_top_ports_first || self.sequential || randomize {
            false
        } else if self.top_ports_first {
            true
        } else {
            // Enabled by default in Fast and Balanced profiles
            matches!(profile, Profile::Fast | Profile::Balanced)
        };

        if let Some(min_conf) = self.min_confidence
            && min_conf > 100
        {
            return Err(AppError::usage(
                "--min-confidence must be between 0 and 100 percent",
            ));
        }

        let ping_count = self.ping_count.unwrap_or(2);
        if !(1..=10).contains(&ping_count) {
            return Err(AppError::usage("--ping-count must be between 1 and 10"));
        }
        let ping_timeout_ms = self.ping_timeout_ms.unwrap_or(500);
        if !(50..=10_000).contains(&ping_timeout_ms) {
            return Err(AppError::usage(
                "--ping-timeout-ms must be between 50 and 10000",
            ));
        }
        let ndp_timeout_ms = self.ndp_timeout_ms.unwrap_or(750);
        if !(50..=5_000).contains(&ndp_timeout_ms) {
            return Err(AppError::usage(
                "--ndp-timeout-ms must be between 50 and 5000",
            ));
        }

        let jitter_ms = self
            .jitter_ms
            .or(file.jitter_ms)
            .unwrap_or_else(|| if profile == Profile::Stealth { 50 } else { 0 });
        if jitter_ms > 5_000 {
            return Err(AppError::usage("--jitter-ms must be at most 5000"));
        }
        let tls_mode = if self.ack || self.no_tls {
            TlsMode::Disabled
        } else if self.tls {
            TlsMode::Force
        } else {
            TlsMode::Auto
        };
        let decoys = parse_decoy_addresses(self.decoys.as_deref())?;
        if let Some(size) = self.fragment_size
            && (!(8..=1480).contains(&size) || !size.is_multiple_of(8))
        {
            return Err(AppError::usage(
                "--fragment-size must be a multiple of 8 between 8 and 1480",
            ));
        }

        if let Some(epss) = self.min_epss
            && !(0.0..=1.0).contains(&epss)
        {
            return Err(AppError::usage("--min-epss must be between 0.0 and 1.0"));
        }

        let exclude_ports = match self.exclude_ports.as_deref() {
            Some(spec) => crate::ports::parse_ports(spec)?,
            None => Vec::new(),
        };

        Ok(ResolvedConfig {
            timeout,
            probe_timeout: Duration::from_millis(probe_timeout_ms),
            rate,
            workers,
            retries,
            randomize,
            connect_only,
            service_detection,
            udp_detection,
            os_detection: self.os && !self.ack,
            os_probes,
            format,
            show,
            family,
            syn_mode: self.syn,
            ack_mode: self.ack,
            aimd: !self.no_aimd && !self.ack,
            aimd_min_pps: self.aimd_min_rate.unwrap_or(100),
            rate_auto: self.rate_auto,
            host_concurrency,
            anomaly_threshold: self.anomaly_threshold.unwrap_or(1000),
            top_ports_first,
            live_table: !self.no_live,
            resume_file: self.resume.clone(),
            save_state_file: self.save_state.clone(),
            theme: file.theme.unwrap_or_default(),
            min_confidence: self.min_confidence,
            explain: self.explain,
            defense: self.defense,
            advisories: (self.advisories || self.kev_only || self.min_epss.is_some()) && !self.ack,
            no_db_update: self.no_db_update,
            diff_file: self.diff.clone(),
            plugins: if self.ack {
                None
            } else {
                self.plugins.clone().or_else(|| file.plugins.clone())
            },
            scripts: if self.ack {
                Vec::new()
            } else if self.scripts.is_empty() {
                file.scripts.clone().into_iter().collect()
            } else {
                self.scripts.clone()
            },
            scripts_library: self.scripts_library && !self.ack,
            allow_intrusive: self.allow_intrusive || file.allow_intrusive.unwrap_or(false),
            min_severity: self
                .min_severity
                .unwrap_or(crate::script::FindingSeverity::Info),
            ping_sweep: self.ping_sweep,
            ping_count,
            ping_timeout: Duration::from_millis(ping_timeout_ms),
            ndp: self.ndp,
            ndp_timeout: Duration::from_millis(ndp_timeout_ms),
            jitter: Duration::from_millis(jitter_ms),
            decoys,
            fragment_size: if self.ack { None } else { self.fragment_size },
            ttl,
            source_port_range,
            tls_mode,
            shard,
            scope: self.scope.clone(),
            force_out_of_scope: self.force_out_of_scope,
            kev_only: self.kev_only,
            min_epss: self.min_epss,
            stream: self.stream,
            exclude_ports,
            save_baseline: self.save_baseline.clone(),
            alert_file: self.alert_file.clone(),
            fail_on_change: self.fail_on_change,
        })
    }

    pub fn target_label(&self) -> String {
        let mut parts = self.target.clone();
        parts.extend(
            self.target_file
                .iter()
                .map(|path| path.display().to_string()),
        );
        if parts.is_empty() {
            "targets".to_string()
        } else {
            parts.join(",")
        }
    }

    /// Resolve the ports to scan and return `(ports_vec, spec_string)`.
    ///
    /// If `--ports` is given, parses that list/range.
    /// If `--top-ports N` is given, returns the top N most common ports.
    /// Otherwise, defaults to `"1-1024"`.
    pub fn resolve_ports(&self) -> Result<(Vec<u16>, String), AppError> {
        if let Some(ref p) = self.ports {
            let ports = crate::ports::parse_ports(p)?;
            Ok((ports, p.clone()))
        } else if let Some(n) = self.top_ports {
            let ports = crate::ports::top_ports(n)?;
            Ok((ports, format!("top-{n}")))
        } else {
            let default_spec = "1-1024";
            let ports = crate::ports::parse_ports(default_spec)?;
            Ok((ports, default_spec.to_string()))
        }
    }

    /// Resolve the port set for a scan, taking the output format into account.
    ///
    /// `--format port-list` is the discovery stage of a two-step workflow
    /// (discover, then deep-scan the returned list), so without an explicit
    /// `--ports`/`--top-ports` selection it sweeps the full TCP range
    /// (1-65535) instead of the well-known 1-1024 default.
    pub fn resolve_ports_for(&self, format: OutputFormat) -> Result<(Vec<u16>, String), AppError> {
        if let Some(preset) = self.preset {
            let ports = preset.ports();
            let spec = if ports.len() == 65_535 {
                "1-65535".to_string()
            } else {
                preset.spec()
            };
            if spec.starts_with("preset:") {
                let list = ports
                    .iter()
                    .map(|p| p.to_string())
                    .collect::<Vec<_>>()
                    .join(",");
                return Ok((ports, list));
            }
            return Ok((ports, spec));
        }
        if self.ports.is_none() && self.top_ports.is_none() && format == OutputFormat::PortList {
            let discovery_spec = "1-65535";
            let ports = crate::ports::parse_ports(discovery_spec)?;
            return Ok((ports, discovery_spec.to_string()));
        }
        self.resolve_ports()
    }
}

fn parse_decoy_addresses(spec: Option<&str>) -> Result<Vec<Ipv4Addr>, AppError> {
    let Some(spec) = spec else {
        return Ok(Vec::new());
    };
    let mut addresses = Vec::new();
    for part in spec.split([',', ' ', '\t']).filter(|part| !part.is_empty()) {
        let address: Ipv4Addr = part.parse().map_err(|_| {
            AppError::usage(format!(
                "--decoys accepts IPv4 addresses only; '{part}' is invalid"
            ))
        })?;
        if !addresses.contains(&address) {
            addresses.push(address);
        }
    }
    if addresses.len() > 8 {
        return Err(AppError::usage("--decoys accepts at most 8 addresses"));
    }
    Ok(addresses)
}

fn parse_source_port_range(spec: Option<&str>) -> Result<Option<(u16, u16)>, AppError> {
    let Some(spec) = spec else {
        return Ok(None);
    };
    let (low, high) = spec
        .split_once('-')
        .ok_or_else(|| AppError::usage("--source-port-range must use the form MIN-MAX"))?;
    let low: u16 = low
        .trim()
        .parse()
        .map_err(|_| AppError::usage("--source-port-range MIN must be between 1 and 65535"))?;
    let high: u16 = high
        .trim()
        .parse()
        .map_err(|_| AppError::usage("--source-port-range MAX must be between 1 and 65535"))?;
    if low == 0 || low > high {
        return Err(AppError::usage(
            "--source-port-range requires 1 <= MIN <= MAX <= 65535",
        ));
    }
    Ok(Some((low, high)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args() -> ScanArgs {
        ScanArgs {
            target: vec!["192.0.2.1".to_string()],
            target_file: Vec::new(),
            exclude: Vec::new(),
            ports: Some("80".to_string()),
            top_ports: None,
            preset: None,
            json: false,
            format: None,
            output: None,
            profile: None,
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
            plugins: None,
            scripts: Vec::new(),
            scripts_library: false,
            allow_intrusive: false,
            min_severity: None,
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
            tls: false,
            no_tls: false,
            shard_index: None,
            shard_count: None,
            scope: None,
            force_out_of_scope: false,
            kev_only: false,
            min_epss: None,
            stream: false,
            exclude_ports: None,
            save_baseline: None,
            alert_file: None,
            fail_on_change: false,
        }
    }

    #[test]
    fn defaults_are_balanced_and_verified() {
        let resolved = args().resolve().unwrap();
        assert!(!resolved.connect_only);
        assert!(!resolved.randomize);
        assert!(resolved.top_ports_first);
        assert!(resolved.service_detection);
        assert_eq!(resolved.format, OutputFormat::Table);
        assert!(resolved.show.contains(crate::model::PortState::Open));
        assert!(!resolved.show.contains(crate::model::PortState::Closed));
    }

    #[test]
    fn stealth_mode_activates_stealth_defaults_and_randomize() {
        let mut stealth_args = args();
        stealth_args.stealth = true;
        let resolved = stealth_args.resolve().unwrap();
        assert!(resolved.randomize);
        assert_eq!(resolved.rate, 20);
        assert_eq!(resolved.workers, 8);
        assert_eq!(resolved.retries, 3);
        assert_eq!(resolved.probe_timeout, Duration::from_millis(1000));

        // When sequential is explicitly requested, randomize stays false
        let mut seq_stealth = args();
        seq_stealth.stealth = true;
        seq_stealth.sequential = true;
        let resolved_seq = seq_stealth.resolve().unwrap();
        assert!(!resolved_seq.randomize);
        assert_eq!(resolved_seq.rate, 20);
    }

    #[test]
    fn service_detection_can_be_disabled_or_implied_off() {
        let mut disabled = args();
        disabled.no_service_detection = true;
        assert!(!disabled.resolve().unwrap().service_detection);

        let mut connect_only = args();
        connect_only.connect_only = true;
        assert!(!connect_only.resolve().unwrap().service_detection);

        let mut no_udp = args();
        no_udp.udp = true;
        no_udp.no_udp_probe = true;
        assert!(!no_udp.resolve().unwrap().udp_detection);
    }

    #[test]
    fn validation_rejects_bad_bounds() {
        let mut invalid = args();
        invalid.timeout = Some(0.0);
        assert_eq!(invalid.resolve().unwrap_err().exit_code(), 2);

        let mut invalid = args();
        invalid.workers = Some(MAX_WORKERS + 1);
        assert_eq!(invalid.resolve().unwrap_err().exit_code(), 2);

        let mut invalid_conf = args();
        invalid_conf.min_confidence = Some(101);
        assert_eq!(invalid_conf.resolve().unwrap_err().exit_code(), 2);

        let mut valid_conf = args();
        valid_conf.min_confidence = Some(80);
        assert_eq!(valid_conf.resolve().unwrap().min_confidence, Some(80));
    }

    #[test]
    fn resolve_ports_defaults_to_well_known_when_omitted() {
        let mut no_ports = args();
        no_ports.ports = None;
        no_ports.top_ports = None;
        let (ports, spec) = no_ports.resolve_ports().unwrap();
        assert_eq!(spec, "1-1024");
        assert_eq!(ports.len(), 1024);
        assert_eq!(ports[0], 1);
        assert_eq!(ports[1023], 1024);
    }

    #[test]
    fn resolve_ports_top_ports_works() {
        let mut top = args();
        top.ports = None;
        top.top_ports = Some(20);
        let (ports, spec) = top.resolve_ports().unwrap();
        assert_eq!(spec, "top-20");
        assert_eq!(ports.len(), 20);
        assert_eq!(ports[0], 80);
    }

    #[test]
    fn resolve_ports_preset_overrides_format_default() {
        let mut preset = args();
        preset.ports = None;
        preset.top_ports = None;
        preset.preset = Some(PortPreset::DcAd);
        let (ports, spec) = preset.resolve_ports_for(OutputFormat::PortList).unwrap();
        assert!(ports.contains(&88));
        assert!(ports.contains(&389));
        assert!(ports.contains(&445));
        assert!(ports.len() < 65_535);
        assert!(!spec.is_empty());
    }

    #[test]
    fn connect_timeout_ms_overrides_timeout_seconds() {
        let mut args = args();
        args.connect_timeout_ms = Some(2_500);
        let resolved = args.resolve().unwrap();
        assert_eq!(resolved.timeout, Duration::from_millis(2_500));
    }

    #[test]
    fn connect_timeout_ms_rejects_out_of_range() {
        let mut args = args();
        args.connect_timeout_ms = Some(0);
        assert_eq!(args.resolve().unwrap_err().exit_code(), 2);
        args.connect_timeout_ms = Some(300_001);
        assert_eq!(args.resolve().unwrap_err().exit_code(), 2);
    }

    #[test]
    fn host_concurrency_is_optional_and_bounded() {
        let mut args = args();
        args.host_concurrency = Some(0);
        assert_eq!(args.resolve().unwrap().host_concurrency, 0);
        args.host_concurrency = Some(64);
        assert_eq!(args.resolve().unwrap().host_concurrency, 64);
        args.host_concurrency = Some(crate::limits::MAX_WORKERS + 1);
        assert_eq!(args.resolve().unwrap_err().exit_code(), 2);
    }

    #[test]
    fn os_probes_are_optional_and_bounded() {
        let mut args = args();
        args.os = true;
        assert_eq!(
            args.resolve().unwrap().os_probes,
            crate::fingerprint::DEFAULT_OS_PROBES
        );
        args.os_probes = Some(crate::fingerprint::MAX_OS_PROBES);
        assert_eq!(
            args.resolve().unwrap().os_probes,
            crate::fingerprint::MAX_OS_PROBES
        );
        args.os_probes = Some(0);
        assert_eq!(args.resolve().unwrap_err().exit_code(), 2);
        args.os_probes = Some(crate::fingerprint::MAX_OS_PROBES + 1);
        assert_eq!(args.resolve().unwrap_err().exit_code(), 2);
    }

    #[test]
    fn ttl_and_source_port_range_are_validated() {
        let mut shaped = args();
        shaped.syn = true;
        shaped.ttl = Some(37);
        shaped.source_port_range = Some("40000-40100".to_string());
        let resolved = shaped.resolve().unwrap();
        assert_eq!(resolved.ttl, Some(37));
        assert_eq!(resolved.source_port_range, Some((40000, 40100)));

        let mut bad_ttl = args();
        bad_ttl.syn = true;
        bad_ttl.ttl = Some(0);
        assert_eq!(bad_ttl.resolve().unwrap_err().exit_code(), 2);

        let mut no_raw = args();
        no_raw.ttl = Some(64);
        assert_eq!(no_raw.resolve().unwrap_err().exit_code(), 2);

        let mut os_only = args();
        os_only.os = true;
        os_only.ttl = Some(64);
        assert_eq!(os_only.resolve().unwrap().ttl, Some(64));

        for spec in ["", "1", "0-100", "100-50", "1-65536", "a-b"] {
            let mut invalid = args();
            invalid.syn = true;
            invalid.source_port_range = Some(spec.to_string());
            assert_eq!(invalid.resolve().unwrap_err().exit_code(), 2, "{spec}");
        }

        let mut synless = args();
        synless.source_port_range = Some("40000-40100".to_string());
        assert_eq!(synless.resolve().unwrap_err().exit_code(), 2);
    }

    #[test]
    fn ack_mode_uses_unfiltered_defaults_and_shaping_flags() {
        let mut ack = args();
        ack.ack = true;
        ack.ttl = Some(37);
        ack.source_port_range = Some("40000-40100".to_string());
        ack.fragment_size = Some(8);
        let resolved = ack.resolve().unwrap();
        assert!(resolved.ack_mode);
        assert!(!resolved.syn_mode);
        assert!(!resolved.connect_only);
        assert!(!resolved.service_detection);
        assert!(!resolved.udp_detection);
        assert!(!resolved.os_detection);
        assert!(!resolved.advisories);
        assert!(!resolved.aimd);
        assert_eq!(resolved.fragment_size, None);
        assert_eq!(resolved.tls_mode, TlsMode::Disabled);
        assert_eq!(resolved.ttl, Some(37));
        assert_eq!(resolved.source_port_range, Some((40000, 40100)));
        assert!(resolved.show.contains(crate::model::PortState::Unfiltered));
        assert!(!resolved.show.contains(crate::model::PortState::Open));
    }

    #[test]
    fn ack_mode_rejects_incompatible_flags_and_formats() {
        let mut with_syn = args();
        with_syn.ack = true;
        with_syn.syn = true;
        assert_eq!(with_syn.resolve().unwrap_err().exit_code(), 2);

        let mut with_os = args();
        with_os.ack = true;
        with_os.os = true;
        assert_eq!(with_os.resolve().unwrap_err().exit_code(), 2);

        let mut with_udp = args();
        with_udp.ack = true;
        with_udp.udp = true;
        assert_eq!(with_udp.resolve().unwrap_err().exit_code(), 2);

        let mut with_scripts = args();
        with_scripts.ack = true;
        with_scripts.scripts_library = true;
        assert_eq!(with_scripts.resolve().unwrap_err().exit_code(), 2);

        let mut port_list = args();
        port_list.ack = true;
        port_list.format = Some(OutputFormat::PortList);
        assert_eq!(port_list.resolve().unwrap_err().exit_code(), 2);
    }

    #[test]
    fn port_list_discovery_defaults_to_full_tcp_range() {
        let mut discovery = args();
        discovery.ports = None;
        discovery.top_ports = None;

        let (ports, spec) = discovery.resolve_ports_for(OutputFormat::PortList).unwrap();
        assert_eq!(spec, "1-65535");
        assert_eq!(ports.len(), 65_535);
        assert_eq!(ports[0], 1);
        assert_eq!(ports[65_534], 65_535);

        // An explicit selection still takes precedence.
        discovery.ports = Some("80,445".to_string());
        let (ports, spec) = discovery.resolve_ports_for(OutputFormat::PortList).unwrap();
        assert_eq!(spec, "80,445");
        assert_eq!(ports, vec![80, 445]);

        // Every other format keeps the well-known-port default.
        discovery.ports = None;
        let (ports, spec) = discovery.resolve_ports_for(OutputFormat::Table).unwrap();
        assert_eq!(spec, "1-1024");
        assert_eq!(ports.len(), 1_024);
    }

    #[test]
    fn port_list_discovery_includes_silent_by_default() {
        let mut discovery = args();
        discovery.format = Some(OutputFormat::PortList);
        let resolved = discovery.resolve().unwrap();
        assert!(resolved.show.contains(crate::model::PortState::Open));
        assert!(resolved.show.contains(crate::model::PortState::Silent));
        assert!(!resolved.show.contains(crate::model::PortState::Closed));
        assert!(!resolved.show.contains(crate::model::PortState::Filtered));

        // An explicit --show still wins over the discovery default.
        discovery.show = vec![StateFilter::Open];
        let resolved = discovery.resolve().unwrap();
        assert!(resolved.show.contains(crate::model::PortState::Open));
        assert!(!resolved.show.contains(crate::model::PortState::Silent));

        // Other formats keep showing verified-open ports only.
        let mut table = args();
        table.format = Some(OutputFormat::Table);
        let resolved = table.resolve().unwrap();
        assert!(resolved.show.contains(crate::model::PortState::Open));
        assert!(!resolved.show.contains(crate::model::PortState::Silent));
    }

    #[test]
    fn discover_only_and_speed_flags_work() {
        let mut disc = args();
        disc.discover_only = true;
        let resolved = disc.resolve().unwrap();
        assert!(resolved.connect_only);
        assert!(!resolved.service_detection);

        let mut prioritized = args();
        prioritized.top_ports_first = true;
        assert!(prioritized.resolve().unwrap().top_ports_first);

        let mut disabled_prio = args();
        disabled_prio.no_top_ports_first = true;
        assert!(!disabled_prio.resolve().unwrap().top_ports_first);

        let mut seq = args();
        seq.sequential = true;
        assert!(!seq.resolve().unwrap().top_ports_first);

        let mut no_live = args();
        no_live.no_live = true;
        assert!(!no_live.resolve().unwrap().live_table);
    }

    #[test]
    fn db_subcommands_parse() {
        let cli = Cli::try_parse_from(["rayscan", "db", "status", "--json"]).unwrap();
        match cli.command {
            Command::Db(DbArgs {
                action: DbAction::Status(options),
            }) => assert!(options.json),
            other => panic!("unexpected command: {other:?}"),
        }

        let cli = Cli::try_parse_from(["rayscan", "db", "intel", "--force", "--json"]).unwrap();
        match cli.command {
            Command::Db(DbArgs {
                action: DbAction::Intel(options),
            }) => {
                assert!(options.force);
                assert!(options.json);
            }
            other => panic!("unexpected command: {other:?}"),
        }

        let cli = Cli::try_parse_from([
            "rayscan",
            "--db-dir",
            "/tmp/rayscan-db",
            "db",
            "update",
            "--years",
            "2024-2026",
            "--force",
        ])
        .unwrap();
        assert_eq!(
            cli.db_dir.as_deref(),
            Some(std::path::Path::new("/tmp/rayscan-db"))
        );
        match cli.command {
            Command::Db(DbArgs {
                action: DbAction::Update(options),
            }) => {
                assert!(options.force);
                assert_eq!(options.years.as_deref(), Some("2024-2026"));
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn scan_accepts_advisory_flags() {
        let mut parsed = args();
        parsed.advisories = true;
        parsed.no_db_update = true;
        let resolved = parsed.resolve().unwrap();
        assert!(resolved.advisories);
        assert!(resolved.no_db_update);
    }

    #[test]
    fn ndp_timeout_is_bounded_and_resolved() {
        let mut enabled = args();
        enabled.ipv6 = true;
        enabled.ndp = true;
        enabled.ndp_timeout_ms = Some(250);
        let resolved = enabled.resolve().unwrap();
        assert!(resolved.ndp);
        assert_eq!(resolved.ndp_timeout, Duration::from_millis(250));

        let mut invalid = args();
        invalid.ndp = true;
        invalid.ndp_timeout_ms = Some(10);
        assert_eq!(invalid.resolve().unwrap_err().exit_code(), 2);
    }

    #[test]
    fn ndp_requires_ipv6_and_parses_timeout() {
        let cli = Cli::try_parse_from([
            "rayscan",
            "scan",
            "-t",
            "fe80::/64",
            "-6",
            "--ndp",
            "--ndp-timeout-ms",
            "250",
        ])
        .unwrap();
        match cli.command {
            Command::Scan(scan) => {
                assert!(scan.ndp);
                assert_eq!(scan.ndp_timeout_ms, Some(250));
            }
            other => panic!("unexpected command: {other:?}"),
        }

        let error = Cli::try_parse_from(["rayscan", "scan", "-t", "fe80::/64", "--ndp"])
            .expect_err("--ndp without --ipv6 must fail");
        assert!(error.to_string().contains("--ipv6"));
    }

    #[test]
    fn shard_selection_requires_a_valid_pair() {
        let mut parsed = args();
        parsed.shard_index = Some(0);
        parsed.shard_count = Some(4);
        assert_eq!(parsed.resolve().unwrap().shard, Some((0, 4)));

        let mut incomplete = args();
        incomplete.shard_index = Some(1);
        assert_eq!(incomplete.resolve().unwrap_err().exit_code(), 2);

        let mut invalid = args();
        invalid.shard_index = Some(4);
        invalid.shard_count = Some(4);
        assert_eq!(invalid.resolve().unwrap_err().exit_code(), 2);
    }

    #[test]
    fn exclude_ports_and_change_monitoring_flags_resolve() {
        let mut excluded = args();
        excluded.exclude_ports = Some("80,443".to_string());
        assert_eq!(excluded.resolve().unwrap().exclude_ports, vec![80, 443]);

        let mut invalid = args();
        invalid.exclude_ports = Some("70000".to_string());
        assert_eq!(invalid.resolve().unwrap_err().exit_code(), 2);

        let cli = Cli::try_parse_from([
            "rayscan",
            "scan",
            "-t",
            "192.0.2.1",
            "--diff",
            "baseline.json",
            "--fail-on-change",
            "--alert-file",
            "alert.txt",
            "--save-baseline",
            "next.json",
        ])
        .unwrap();
        match cli.command {
            Command::Scan(scan) => {
                assert!(scan.fail_on_change);
                assert_eq!(
                    scan.alert_file.as_deref(),
                    Some(std::path::Path::new("alert.txt"))
                );
                assert_eq!(
                    scan.save_baseline.as_deref(),
                    Some(std::path::Path::new("next.json"))
                );
            }
            other => panic!("unexpected command: {other:?}"),
        }

        let error = Cli::try_parse_from(["rayscan", "scan", "-t", "192.0.2.1", "--fail-on-change"])
            .expect_err("--fail-on-change requires --diff");
        assert!(error.to_string().contains("--diff"));

        let cli = Cli::try_parse_from([
            "rayscan",
            "diff",
            "a.json",
            "b.json",
            "--fail-on-change",
            "--alert-file",
            "alert.txt",
        ])
        .unwrap();
        match cli.command {
            Command::Diff(options) => {
                assert!(options.fail_on_change);
                assert_eq!(
                    options.alert_file.as_deref(),
                    Some(std::path::Path::new("alert.txt"))
                );
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }

    #[test]
    fn distributed_tls_flags_are_paired_and_parse() {
        let cli = Cli::try_parse_from([
            "rayscan",
            "distributed",
            "serve",
            "--tls-cert",
            "coordinator.pem",
            "--tls-key",
            "coordinator.key",
            "--ca-cert",
            "ca.pem",
            "--",
            "scan",
            "-t",
            "127.0.0.1",
        ])
        .unwrap();
        match cli.command {
            Command::Distributed(DistributedArgs {
                action: DistributedAction::Serve(options),
            }) => {
                assert_eq!(
                    options.tls_cert.as_deref(),
                    Some(std::path::Path::new("coordinator.pem"))
                );
                assert_eq!(
                    options.ca_cert.as_deref(),
                    Some(std::path::Path::new("ca.pem"))
                );
                assert!(!options.insecure_tls);
            }
            other => panic!("unexpected command: {other:?}"),
        }

        let error =
            Cli::try_parse_from(["rayscan", "distributed", "agent", "--tls-cert", "agent.pem"])
                .expect_err("--tls-cert without --tls-key must fail");
        assert!(error.to_string().contains("tls-key"));

        let error = Cli::try_parse_from([
            "rayscan",
            "distributed",
            "worker",
            "--coordinator",
            "https://127.0.0.1:9090",
            "--ca-cert",
            "ca.pem",
            "--insecure-tls",
        ])
        .expect_err("--ca-cert and --insecure-tls must conflict");
        assert!(error.to_string().contains("insecure-tls"));
    }

    #[test]
    fn merge_subcommand_parses() {
        let cli = Cli::try_parse_from([
            "rayscan",
            "merge",
            "shard-a.json",
            "shard-b.jsonl",
            "--output",
            "merged.json",
            "--jsonl",
        ])
        .unwrap();
        match cli.command {
            Command::Merge(options) => {
                assert_eq!(options.inputs.len(), 2);
                assert!(options.jsonl);
                assert_eq!(
                    options.output.as_deref(),
                    Some(std::path::Path::new("merged.json"))
                );
            }
            other => panic!("unexpected command: {other:?}"),
        }
    }
}
