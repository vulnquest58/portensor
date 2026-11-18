//! Windows raw SYN/ACK engine backed by a dynamically loaded Npcap/WinPcap.
//!
//! Npcap is optional at build time: the release executable loads `wpcap.dll`
//! only when `--syn` or `--ack` is requested. IPv4 is supported; IPv6 raw
//! scanning remains Linux-only.

use std::collections::HashMap;
use std::ffi::{CStr, CString, c_char, c_int, c_uint, c_void};
use std::net::{IpAddr, Ipv4Addr};
use std::ptr;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use super::aimd::{AimdConfig, AimdController};
use super::cookie::CookieKey;
use super::pacer::Pacer;
use super::packet;
use super::permute::BlackRock;
use super::source_port::next_source_port;
use super::{ProbeMode, SynScanOptions};
use crate::error::AppError;
use crate::model::{HostProgress, PortResult, PortState, ScanReport, StateCounts};
use crate::scanner::{ProgressCallback, ProgressEvent};

const DLT_EN10MB: c_int = 1;
const PCAP_ERRBUF_SIZE: usize = 256;
const PCAP_NETMASK_UNKNOWN: c_uint = 0xffff_ffff;
const ERROR_BUFFER_OVERFLOW: u32 = 111;
const MAX_ADAPTER_NAME_LENGTH: usize = 256;
const MAX_ADAPTER_DESCRIPTION_LENGTH: usize = 128;
const MAX_ADAPTER_ADDRESS_LENGTH: usize = 8;

#[repr(C)]
struct PcapPkthdr {
    ts_sec: i32,
    ts_usec: i32,
    caplen: u32,
    len: u32,
}

#[repr(C)]
struct BpfProgram {
    bf_len: c_uint,
    bf_insns: *mut c_void,
}

type PcapHandleRaw = *mut c_void;
type PcapOpenLive =
    unsafe extern "C" fn(*const c_char, c_int, c_int, c_int, *mut c_char) -> PcapHandleRaw;
type PcapDatalink = unsafe extern "C" fn(PcapHandleRaw) -> c_int;
type PcapCompile =
    unsafe extern "C" fn(PcapHandleRaw, *mut BpfProgram, *const c_char, c_int, c_uint) -> c_int;
type PcapSetFilter = unsafe extern "C" fn(PcapHandleRaw, *mut BpfProgram) -> c_int;
type PcapFreeCode = unsafe extern "C" fn(*mut BpfProgram);
type PcapSendPacket = unsafe extern "C" fn(PcapHandleRaw, *const u8, c_int) -> c_int;
type PcapNextEx =
    unsafe extern "C" fn(PcapHandleRaw, *mut *mut PcapPkthdr, *mut *const u8) -> c_int;
type PcapGetErr = unsafe extern "C" fn(PcapHandleRaw) -> *mut c_char;
type PcapClose = unsafe extern "C" fn(PcapHandleRaw);

struct PcapApi {
    open_live: PcapOpenLive,
    datalink: PcapDatalink,
    compile: PcapCompile,
    setfilter: PcapSetFilter,
    freecode: PcapFreeCode,
    sendpacket: PcapSendPacket,
    next_ex: PcapNextEx,
    geterr: PcapGetErr,
    close: PcapClose,
}

// The function pointers are immutable and Npcap's pcap_t handles are only used
// from the thread that opened them.
unsafe impl Send for PcapApi {}
unsafe impl Sync for PcapApi {}

static PCAP_API: OnceLock<Result<PcapApi, String>> = OnceLock::new();

#[link(name = "kernel32")]
unsafe extern "system" {
    fn LoadLibraryW(name: *const u16) -> *mut c_void;
    fn GetProcAddress(module: *mut c_void, name: *const c_char) -> *mut c_void;
}

#[link(name = "iphlpapi")]
unsafe extern "system" {
    fn GetBestRoute(dest: u32, source: u32, route: *mut MibIpforwardRow) -> u32;
    fn SendARP(dest: u32, source: u32, mac: *mut u8, len: *mut u32) -> u32;
    fn GetAdaptersInfo(info: *mut IpAdapterInfo, len: *mut u32) -> u32;
}

#[repr(C)]
#[derive(Clone, Copy)]
struct MibIpforwardRow {
    dest: u32,
    mask: u32,
    policy: u32,
    next_hop: u32,
    if_index: u32,
    route_type: u32,
    proto: u32,
    age: u32,
    next_hop_as: u32,
    metric1: u32,
    metric2: u32,
    metric3: u32,
    metric4: u32,
    metric5: u32,
}

#[repr(C)]
struct IpAddrString {
    next: *mut IpAddrString,
    ip_address: [u8; 16],
    ip_mask: [u8; 16],
    context: u32,
}

#[repr(C)]
struct IpAdapterInfo {
    next: *mut IpAdapterInfo,
    combo_index: u32,
    adapter_name: [u8; MAX_ADAPTER_NAME_LENGTH + 4],
    description: [u8; MAX_ADAPTER_DESCRIPTION_LENGTH + 4],
    address_length: u32,
    address: [u8; MAX_ADAPTER_ADDRESS_LENGTH],
    index: u32,
    adapter_type: u32,
    dhcp_enabled: u32,
    current_ip_address: *mut IpAddrString,
    ip_address_list: IpAddrString,
    gateway_list: IpAddrString,
    dhcp_server: IpAddrString,
    have_wins: u32,
    primary_wins_server: IpAddrString,
    secondary_wins_server: IpAddrString,
}

#[derive(Clone, Debug)]
struct Adapter {
    name: String,
    index: u32,
    mac: [u8; 6],
    ips: Vec<(Ipv4Addr, Ipv4Addr)>,
}

#[derive(Clone, Debug)]
struct WinRoute {
    device: String,
    iface: String,
    if_index: u32,
    src_ip: Ipv4Addr,
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
}

struct PcapHandle {
    raw: PcapHandleRaw,
    api: &'static PcapApi,
}

impl Drop for PcapHandle {
    fn drop(&mut self) {
        // SAFETY: raw was opened by this type and is closed exactly once.
        unsafe { (self.api.close)(self.raw) };
    }
}

impl PcapApi {
    fn load() -> Result<&'static PcapApi, String> {
        PCAP_API
            .get_or_init(load_pcap)
            .as_ref()
            .map_err(String::clone)
    }
}

fn load_pcap() -> Result<PcapApi, String> {
    let module = load_wpcap_module()?;
    // SAFETY: GetProcAddress receives a live module handle and NUL-terminated
    // symbol names; each symbol is transmuted to its matching C signature.
    unsafe {
        let open_live = symbol::<PcapOpenLive>(module, "pcap_open_live")?;
        let datalink = symbol::<PcapDatalink>(module, "pcap_datalink")?;
        let compile = symbol::<PcapCompile>(module, "pcap_compile")?;
        let setfilter = symbol::<PcapSetFilter>(module, "pcap_setfilter")?;
        let freecode = symbol::<PcapFreeCode>(module, "pcap_freecode")?;
        let sendpacket = symbol::<PcapSendPacket>(module, "pcap_sendpacket")?;
        let next_ex = symbol::<PcapNextEx>(module, "pcap_next_ex")?;
        let geterr = symbol::<PcapGetErr>(module, "pcap_geterr")?;
        let close = symbol::<PcapClose>(module, "pcap_close")?;
        Ok(PcapApi {
            open_live,
            datalink,
            compile,
            setfilter,
            freecode,
            sendpacket,
            next_ex,
            geterr,
            close,
        })
    }
}

fn load_wpcap_module() -> Result<*mut c_void, String> {
    let mut candidates: Vec<std::path::PathBuf> = Vec::new();
    if let Some(root) = std::env::var_os("SystemRoot") {
        candidates.push(
            std::path::PathBuf::from(root.clone())
                .join("System32")
                .join("Npcap")
                .join("wpcap.dll"),
        );
        candidates.push(
            std::path::PathBuf::from(root)
                .join("System32")
                .join("wpcap.dll"),
        );
    }
    candidates.push(std::path::PathBuf::from("wpcap.dll"));

    let mut last_error = String::from("wpcap.dll was not found");
    for candidate in candidates {
        use std::os::windows::ffi::OsStrExt as _;
        let wide: Vec<u16> = candidate
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        // SAFETY: wide is a NUL-terminated UTF-16 path.
        let module = unsafe { LoadLibraryW(wide.as_ptr()) };
        if !module.is_null() {
            return Ok(module);
        }
        last_error = std::io::Error::last_os_error().to_string();
    }

    Err(format!(
        "cannot load Npcap/WinPcap (wpcap.dll): {last_error}. Install Npcap with the \
         WinPcap API-compatible mode"
    ))
}

unsafe fn symbol<T: Copy>(module: *mut c_void, name: &str) -> Result<T, String> {
    let name = CString::new(name).map_err(|_| "invalid Npcap symbol name".to_string())?;
    // SAFETY: the caller passes a live module and a valid C string.
    let address = unsafe { GetProcAddress(module, name.as_ptr()) };
    if address.is_null() {
        return Err(format!(
            "Npcap is missing the required symbol {}",
            name.to_string_lossy()
        ));
    }
    if std::mem::size_of::<T>() != std::mem::size_of::<*mut c_void>() {
        return Err("unexpected function pointer size".to_string());
    }
    // SAFETY: Npcap functions use the platform C ABI and the size check above
    // guarantees the pointer representation fits T.
    Ok(unsafe { std::mem::transmute_copy(&address) })
}

pub fn check_raw_privilege() -> Result<(), AppError> {
    PcapApi::load()
        .map(|_| ())
        .map_err(|error| AppError::runtime(format!("Windows raw SYN unavailable: {error}")))
}

pub fn route_summary() -> Result<String, String> {
    let target = Ipv4Addr::new(0, 0, 0, 0);
    let (if_index, next_hop) = best_route(target)?;
    let adapters = get_adapters()?;
    let adapter = find_adapter(&adapters, if_index)?;
    let src_ip = choose_source_ip(&adapter.ips, target, next_hop)
        .ok_or_else(|| format!("adapter {} has no usable IPv4 address", adapter.name))?;
    Ok(format!("{} via {} ({})", adapter.name, next_hop, src_ip))
}

pub fn syn_scan(
    opts: SynScanOptions,
    progress: Option<ProgressCallback>,
) -> Result<ScanReport, AppError> {
    if opts.targets.is_empty() || opts.ports.is_empty() {
        return Err(AppError::usage(
            "scan needs at least one target and one port",
        ));
    }

    let mut v4_targets = Vec::new();
    for target in &opts.targets {
        match target {
            IpAddr::V4(ip) => v4_targets.push(*ip),
            IpAddr::V6(_) => {
                return Err(AppError::usage(
                    "Windows Npcap raw scanning supports IPv4 only; use --connect for IPv6",
                ));
            }
        }
    }
    v4_targets.sort_unstable();
    v4_targets.dedup();

    let api = PcapApi::load()
        .map_err(|error| AppError::runtime(format!("Windows raw SYN unavailable: {error}")))?;

    let adapters = get_adapters()
        .map_err(|error| AppError::runtime(format!("cannot enumerate adapters: {error}")))?;
    let mut routes = HashMap::new();
    let mut groups: HashMap<u32, Vec<Ipv4Addr>> = HashMap::new();
    for target in &v4_targets {
        let route = resolve_target_route(*target, &adapters)
            .map_err(|error| AppError::runtime(format!("{target}: {error}")))?;
        groups.entry(route.if_index).or_default().push(*target);
        routes.insert(*target, route);
    }

    let started = Instant::now();
    let mut combined = ScanReport {
        targets: v4_targets.len(),
        ports: opts.ports.len(),
        jobs: 0,
        workers: groups.len().max(1),
        elapsed: Duration::ZERO,
        counts: StateCounts::default(),
        results: Vec::new(),
        os_fingerprints: HashMap::new(),
        probed_ports: opts.ports.clone(),
        host_progress: HashMap::new(),
        partial: false,
        defense_observations: Vec::new(),
    };

    for mut targets in groups.into_values() {
        targets.sort_unstable();
        let report = scan_group(&targets, &routes, &opts, api, progress.as_ref())
            .map_err(|error| AppError::runtime(error.to_string()))?;
        combined.jobs = combined.jobs.saturating_add(report.jobs);
        combined.counts.add_other(report.counts);
        combined.results.extend(report.results);
        combined.host_progress.extend(report.host_progress);
        combined.partial |= report.partial;
    }
    combined.elapsed = started.elapsed();
    Ok(combined)
}

fn scan_group(
    targets: &[Ipv4Addr],
    routes: &HashMap<Ipv4Addr, WinRoute>,
    opts: &SynScanOptions,
    api: &'static PcapApi,
    progress: Option<&ProgressCallback>,
) -> Result<ScanReport, String> {
    let first = targets
        .first()
        .and_then(|target| routes.get(target))
        .ok_or_else(|| "no route for target group".to_string())?;
    let handle = open_capture(api, &first.device)?;
    let link = unsafe { (api.datalink)(handle.raw) };
    if link != DLT_EN10MB {
        return Err(format!(
            "Npcap interface {} uses datalink {link}, expected Ethernet; loopback raw \
             scanning is not supported on Windows (use --connect)",
            first.iface
        ));
    }

    let ports_len = opts.ports.len() as u64;
    let total_probes = (targets.len() as u64)
        .checked_mul(ports_len)
        .ok_or_else(|| "target/port combination count overflowed".to_string())?;
    let blackrock = BlackRock::new(total_probes);
    let cookie_key = CookieKey::random();
    let mut pacer = Pacer::new(opts.rate_pps);
    let mut aimd = AimdController::new(AimdConfig {
        initial_pps: opts.rate_pps,
        min_pps: opts.aimd_min_pps.max(1),
        max_pps: opts.rate_pps.max(opts.aimd_min_pps.max(1)),
        step_pps: (opts.rate_pps / 4).max(10),
        ..AimdConfig::default()
    });
    let mut aimd_last = Instant::now();
    let mut aimd_sent = 0u64;
    let mut aimd_received = 0u64;
    let mut last_response_count = 0u64;

    let sport_lo = opts.sport_range.0.max(1);
    let sport_hi = opts.sport_range.1.max(sport_lo);
    let range_len = u64::from(sport_hi - sport_lo) + 1;
    let timeout = Duration::from_millis(opts.timeout_ms.clamp(1, 60_000));
    let drain_every = opts.batch_size.clamp(1, 512);
    let mut tx_times: HashMap<(Ipv4Addr, u16), Instant> = HashMap::new();
    let mut last_src: HashMap<(Ipv4Addr, u16), u16> = HashMap::new();
    let mut responses: HashMap<(Ipv4Addr, u16), (PortState, Duration)> = HashMap::new();
    let mut answered: HashMap<Ipv4Addr, u32> = HashMap::new();
    let started = Instant::now();

    let mut sent_since_drain = 0usize;
    for cursor in 0..total_probes {
        let perm = blackrock.encrypt(cursor);
        let target = targets[(perm / ports_len) as usize];
        let port = opts.ports[(perm % ports_len) as usize];
        let src_port = sport_lo + (perm % range_len) as u16;
        let route = routes
            .get(&target)
            .ok_or_else(|| format!("no route for {target}"))?;

        pacer.wait_for_batch(1 + opts.decoys.len());
        jitter(opts.jitter_ms);
        let sent_at = Instant::now();
        send_probe(
            api,
            handle.raw,
            opts,
            route,
            &cookie_key,
            target,
            port,
            src_port,
        )?;
        tx_times.insert((target, port), sent_at);
        last_src.insert((target, port), src_port);
        sent_since_drain += 1;
        aimd_sent = aimd_sent.saturating_add(1);

        if sent_since_drain >= drain_every {
            sent_since_drain = 0;
            drain_available(
                api,
                handle.raw,
                &cookie_key,
                opts.mode,
                &mut responses,
                &mut answered,
                &tx_times,
                started,
            )?;
            if let Some(callback) = progress {
                callback(ProgressEvent::default());
            }
        }

        if opts.aimd
            && opts.rate_pps > 0
            && aimd_sent >= 64
            && aimd_last.elapsed() >= Duration::from_secs(1)
        {
            let new_responses = responses.len() as u64 - last_response_count;
            aimd_received = aimd_received.saturating_add(new_responses);
            last_response_count = responses.len() as u64;
            let rate = aimd.update(aimd_sent, aimd_received);
            pacer = Pacer::new(rate);
            aimd_last = Instant::now();
            aimd_sent = 0;
            aimd_received = 0;
        }
    }

    drain_until(
        api,
        handle.raw,
        Instant::now() + timeout,
        &cookie_key,
        opts.mode,
        &mut responses,
        &mut answered,
        &tx_times,
        started,
        progress,
    )?;

    for _attempt in 0..opts.retries {
        if (responses.len() as u64).saturating_mul(100) < total_probes {
            break;
        }
        let mut retried = 0u64;
        for target in targets {
            if answered.get(target).copied().unwrap_or(0) == 0 {
                continue;
            }
            let route = routes
                .get(target)
                .ok_or_else(|| format!("no route for {target}"))?;
            for &port in &opts.ports {
                let key = (*target, port);
                if responses.contains_key(&key) {
                    continue;
                }
                let previous = last_src.get(&key).copied().unwrap_or(sport_lo);
                let src_port = next_source_port(previous, sport_lo, total_probes, range_len);
                pacer.wait_for_batch(1 + opts.decoys.len());
                jitter(opts.jitter_ms);
                let sent_at = Instant::now();
                send_probe(
                    api,
                    handle.raw,
                    opts,
                    route,
                    &cookie_key,
                    *target,
                    port,
                    src_port,
                )?;
                tx_times.insert(key, sent_at);
                last_src.insert(key, src_port);
                retried += 1;
            }
        }
        if retried == 0 {
            break;
        }
        drain_until(
            api,
            handle.raw,
            Instant::now() + timeout,
            &cookie_key,
            opts.mode,
            &mut responses,
            &mut answered,
            &tx_times,
            started,
            progress,
        )?;
        if let Some(callback) = progress {
            callback(ProgressEvent::default());
        }
    }

    let mut counts = StateCounts::default();
    let mut results = Vec::new();
    let mut host_progress: HashMap<IpAddr, HostProgress> = HashMap::new();
    for &target in targets {
        for &port in &opts.ports {
            let (state, latency) = responses
                .get(&(target, port))
                .copied()
                .unwrap_or((PortState::Filtered, timeout));
            counts.add(state);
            let progress = host_progress.entry(IpAddr::V4(target)).or_default();
            progress.ports_scanned.push(port);
            progress.counts.add(state);
            if opts.retain.contains(state) {
                results.push(PortResult::new(IpAddr::V4(target), port, state, latency));
            }
        }
    }

    Ok(ScanReport {
        targets: targets.len(),
        ports: opts.ports.len(),
        jobs: total_probes,
        workers: 1,
        elapsed: started.elapsed(),
        counts,
        results,
        os_fingerprints: HashMap::new(),
        probed_ports: opts.ports.clone(),
        host_progress,
        partial: false,
        defense_observations: Vec::new(),
    })
}

fn open_capture(api: &'static PcapApi, device: &str) -> Result<PcapHandle, String> {
    let device = CString::new(device).map_err(|_| "Npcap device name contains NUL".to_string())?;
    let mut errbuf = [0i8; PCAP_ERRBUF_SIZE];
    // SAFETY: device and errbuf are valid for the duration of the call.
    let raw = unsafe {
        (api.open_live)(
            device.as_ptr(),
            65_535,
            1,
            10,
            errbuf.as_mut_ptr() as *mut c_char,
        )
    };
    if raw.is_null() {
        return Err(format!(
            "cannot open Npcap interface: {}",
            c_buffer(&errbuf)
        ));
    }
    let handle = PcapHandle { raw, api };

    let filter = CString::new("tcp or icmp").expect("static BPF filter");
    let mut program = BpfProgram {
        bf_len: 0,
        bf_insns: ptr::null_mut(),
    };
    // SAFETY: handle.raw is a live pcap handle and program is writable.
    let compiled = unsafe {
        (api.compile)(
            handle.raw,
            &mut program,
            filter.as_ptr(),
            1,
            PCAP_NETMASK_UNKNOWN,
        )
    };
    if compiled == 0 {
        // SAFETY: program was initialized by pcap_compile.
        unsafe {
            (api.setfilter)(handle.raw, &mut program);
            (api.freecode)(&mut program);
        }
    }
    Ok(handle)
}

#[expect(clippy::too_many_arguments)]
fn send_probe(
    api: &PcapApi,
    handle: PcapHandleRaw,
    opts: &SynScanOptions,
    route: &WinRoute,
    cookie_key: &CookieKey,
    target: Ipv4Addr,
    port: u16,
    src_port: u16,
) -> Result<(), String> {
    let seq = cookie_key.encode(u32::from(target), port, src_port);
    let mut frame = [0u8; 54];
    match opts.mode {
        ProbeMode::Syn => packet::write_syn_frame(
            &mut frame,
            &route.src_mac,
            &route.dst_mac,
            u32::from(route.src_ip),
            u32::from(target),
            src_port,
            port,
            seq,
            opts.ttl,
        ),
        ProbeMode::Ack => packet::write_ack_frame(
            &mut frame,
            &route.src_mac,
            &route.dst_mac,
            u32::from(route.src_ip),
            u32::from(target),
            src_port,
            port,
            seq,
            seq,
            opts.ttl,
        ),
    }

    let frames = match opts.fragment_size {
        Some(size) => packet::fragment_syn_frame(&frame, size),
        None => vec![frame.to_vec()],
    };
    for frame in frames {
        send_frame(api, handle, &frame)?;
    }

    if opts.mode == ProbeMode::Syn {
        for (index, decoy) in opts.decoys.iter().enumerate() {
            let decoy_port = decoy_source_port(index, opts.sport_range.0, opts.sport_range.1);
            let decoy_frame = packet::build_syn_frame(
                &route.src_mac,
                &route.dst_mac,
                u32::from(*decoy),
                u32::from(target),
                decoy_port,
                port,
                seq.wrapping_add(index as u32 + 1),
                opts.ttl,
            );
            send_frame(api, handle, &decoy_frame)?;
        }
    }
    Ok(())
}

fn send_frame(api: &PcapApi, handle: PcapHandleRaw, frame: &[u8]) -> Result<(), String> {
    // SAFETY: frame is a valid slice and handle is a live pcap handle.
    let result = unsafe { (api.sendpacket)(handle, frame.as_ptr(), frame.len() as c_int) };
    if result == 0 {
        Ok(())
    } else {
        Err(format!("Npcap send failed: {}", pcap_error(api, handle)))
    }
}

#[expect(clippy::too_many_arguments)]
fn drain_available(
    api: &PcapApi,
    handle: PcapHandleRaw,
    cookie_key: &CookieKey,
    mode: ProbeMode,
    responses: &mut HashMap<(Ipv4Addr, u16), (PortState, Duration)>,
    answered: &mut HashMap<Ipv4Addr, u32>,
    tx_times: &HashMap<(Ipv4Addr, u16), Instant>,
    started: Instant,
) -> Result<(), String> {
    for _ in 0..2048 {
        let mut header: *mut PcapPkthdr = ptr::null_mut();
        let mut data: *const u8 = ptr::null();
        // SAFETY: header/data are output pointers owned by Npcap for this call.
        let result = unsafe { (api.next_ex)(handle, &mut header, &mut data) };
        if result == -1 {
            return Err(format!("Npcap receive failed: {}", pcap_error(api, handle)));
        }
        if result != 1 {
            break;
        }
        // SAFETY: result == 1 guarantees header and data are valid.
        let record = unsafe { (*header).caplen as usize };
        if record == 0 || data.is_null() {
            continue;
        }
        // SAFETY: Npcap guarantees caplen readable bytes at data.
        let frame = unsafe { std::slice::from_raw_parts(data, record) };
        handle_frame(
            frame, cookie_key, mode, responses, answered, tx_times, started,
        );
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn drain_until(
    api: &PcapApi,
    handle: PcapHandleRaw,
    deadline: Instant,
    cookie_key: &CookieKey,
    mode: ProbeMode,
    responses: &mut HashMap<(Ipv4Addr, u16), (PortState, Duration)>,
    answered: &mut HashMap<Ipv4Addr, u32>,
    tx_times: &HashMap<(Ipv4Addr, u16), Instant>,
    started: Instant,
    progress: Option<&ProgressCallback>,
) -> Result<(), String> {
    let mut drained = 0usize;
    while Instant::now() < deadline {
        let mut header: *mut PcapPkthdr = ptr::null_mut();
        let mut data: *const u8 = ptr::null();
        // SAFETY: header/data are output pointers owned by Npcap for this call.
        let result = unsafe { (api.next_ex)(handle, &mut header, &mut data) };
        if result == -1 {
            return Err(format!("Npcap receive failed: {}", pcap_error(api, handle)));
        }
        if result == 1 {
            // SAFETY: result == 1 guarantees header and data are valid.
            let record = unsafe { (*header).caplen as usize };
            if record > 0 && !data.is_null() {
                // SAFETY: Npcap guarantees caplen readable bytes at data.
                let frame = unsafe { std::slice::from_raw_parts(data, record) };
                handle_frame(
                    frame, cookie_key, mode, responses, answered, tx_times, started,
                );
                drained += 1;
                if drained.is_multiple_of(256)
                    && let Some(callback) = progress
                {
                    callback(ProgressEvent::default());
                }
            }
        }
    }
    Ok(())
}

fn handle_frame(
    frame: &[u8],
    cookie_key: &CookieKey,
    mode: ProbeMode,
    responses: &mut HashMap<(Ipv4Addr, u16), (PortState, Duration)>,
    answered: &mut HashMap<Ipv4Addr, u32>,
    tx_times: &HashMap<(Ipv4Addr, u16), Instant>,
    started: Instant,
) {
    let now = Instant::now();
    match packet::parse_frame(frame) {
        packet::ParsedFrame::SynAck {
            src_ip,
            src_port,
            dst_port,
            ack,
            ..
        } => {
            if mode == ProbeMode::Syn && cookie_key.validate(src_ip, src_port, dst_port, ack) {
                record(
                    Ipv4Addr::from(src_ip),
                    src_port,
                    PortState::Open,
                    now,
                    responses,
                    answered,
                    tx_times,
                    started,
                );
            }
        }
        packet::ParsedFrame::Rst {
            src_ip,
            src_port,
            dst_port,
            seq,
        } => {
            let state = match mode {
                ProbeMode::Syn => Some(PortState::Closed),
                ProbeMode::Ack => {
                    let cookie = cookie_key.encode(src_ip, src_port, dst_port);
                    (seq == cookie).then_some(PortState::Unfiltered)
                }
            };
            if let Some(state) = state {
                record(
                    Ipv4Addr::from(src_ip),
                    src_port,
                    state,
                    now,
                    responses,
                    answered,
                    tx_times,
                    started,
                );
            }
        }
        packet::ParsedFrame::IcmpUnreachable { dst_ip, dst_port } => {
            record(
                Ipv4Addr::from(dst_ip),
                dst_port,
                PortState::Filtered,
                now,
                responses,
                answered,
                tx_times,
                started,
            );
        }
        packet::ParsedFrame::Other => {}
    }
}

#[allow(clippy::too_many_arguments)]
fn record(
    host: Ipv4Addr,
    port: u16,
    state: PortState,
    now: Instant,
    responses: &mut HashMap<(Ipv4Addr, u16), (PortState, Duration)>,
    answered: &mut HashMap<Ipv4Addr, u32>,
    tx_times: &HashMap<(Ipv4Addr, u16), Instant>,
    started: Instant,
) {
    let key = (host, port);
    let sent_at = tx_times.get(&key).copied().unwrap_or(started);
    let latency = now.saturating_duration_since(sent_at);
    *answered.entry(host).or_default() += 1;
    if let Some(&(PortState::Open | PortState::Unfiltered, _)) = responses.get(&key) {
        return;
    }
    responses.insert(key, (state, latency));
}

fn jitter(max_ms: u64) {
    if max_ms == 0 {
        return;
    }
    use rand::Rng as _;
    let delay = rand::thread_rng().gen_range(0..=max_ms);
    if delay > 0 {
        std::thread::sleep(Duration::from_millis(delay));
    }
}

fn decoy_source_port(index: usize, low: u16, high: u16) -> u16 {
    let low = low.max(1);
    let high = high.max(low);
    let mut candidate = 1024_u16.wrapping_add(index as u16);
    for _ in 0..128 {
        if candidate != 0 && !(low..=high).contains(&candidate) {
            return candidate;
        }
        candidate = candidate.wrapping_add(1001);
    }
    if low > 1024 { 1023 } else { 65535 }
}

fn pcap_error(api: &PcapApi, handle: PcapHandleRaw) -> String {
    // SAFETY: handle is live and pcap_geterr returns a NUL-terminated string
    // owned by the handle until the next call.
    let pointer = unsafe { (api.geterr)(handle) };
    if pointer.is_null() {
        "unknown Npcap error".to_string()
    } else {
        // SAFETY: pcap_geterr returns a valid NUL-terminated C string.
        unsafe { CStr::from_ptr(pointer) }
            .to_string_lossy()
            .into_owned()
    }
}

fn c_buffer(buffer: &[c_char]) -> String {
    // SAFETY: buffer is a fixed NUL-terminated C buffer.
    unsafe { CStr::from_ptr(buffer.as_ptr()) }
        .to_string_lossy()
        .into_owned()
}

fn resolve_target_route(target: Ipv4Addr, adapters: &[Adapter]) -> Result<WinRoute, String> {
    if target.is_loopback() {
        return Err(
            "raw scanning on the Windows loopback interface is not supported; use --connect"
                .to_string(),
        );
    }
    let (if_index, next_hop) = best_route(target)?;
    let adapter = find_adapter(adapters, if_index)?;
    let src_ip = choose_source_ip(&adapter.ips, target, next_hop)
        .ok_or_else(|| format!("adapter {} has no usable IPv4 address", adapter.name))?;
    if adapter.mac == [0u8; 6] {
        return Err(format!("adapter {} has no MAC address", adapter.name));
    }
    let dst_mac = arp_resolve(next_hop, src_ip)
        .map_err(|error| format!("cannot resolve {next_hop} MAC: {error}"))?;
    Ok(WinRoute {
        device: format!("\\Device\\NPF_{}", adapter.name),
        iface: adapter.name.clone(),
        if_index,
        src_ip,
        src_mac: adapter.mac,
        dst_mac,
    })
}

fn find_adapter(adapters: &[Adapter], if_index: u32) -> Result<&Adapter, String> {
    adapters
        .iter()
        .find(|adapter| adapter.index == if_index)
        .ok_or_else(|| format!("adapter index {if_index} not found"))
}

fn best_route(target: Ipv4Addr) -> Result<(u32, Ipv4Addr), String> {
    let mut row = MibIpforwardRow {
        dest: 0,
        mask: 0,
        policy: 0,
        next_hop: 0,
        if_index: 0,
        route_type: 0,
        proto: 0,
        age: 0,
        next_hop_as: 0,
        metric1: 0,
        metric2: 0,
        metric3: 0,
        metric4: 0,
        metric5: 0,
    };
    // SAFETY: row is writable and target is in network byte order.
    let result = unsafe { GetBestRoute(u32::from_ne_bytes(target.octets()), 0, &mut row) };
    if result != 0 {
        return Err(format!("GetBestRoute failed with code {result}"));
    }
    let next_hop = Ipv4Addr::from(row.next_hop.to_ne_bytes());
    let next_hop = if next_hop.is_unspecified() {
        target
    } else {
        next_hop
    };
    Ok((row.if_index, next_hop))
}

fn choose_source_ip(
    ips: &[(Ipv4Addr, Ipv4Addr)],
    target: Ipv4Addr,
    next_hop: Ipv4Addr,
) -> Option<Ipv4Addr> {
    let prefer = [next_hop, target];
    for peer in prefer {
        for &(ip, mask) in ips {
            if !ip.is_unspecified() && same_subnet(peer, ip, mask) {
                return Some(ip);
            }
        }
    }
    ips.iter()
        .map(|(ip, _)| *ip)
        .find(|ip| !ip.is_unspecified())
}

fn same_subnet(peer: Ipv4Addr, ip: Ipv4Addr, mask: Ipv4Addr) -> bool {
    let mask = u32::from(mask);
    if mask == 0 {
        return false;
    }
    (u32::from(peer) & mask) == (u32::from(ip) & mask)
}

fn get_adapters() -> Result<Vec<Adapter>, String> {
    let mut size = 16 * 1024u32;
    for _ in 0..4 {
        let words = (size as usize).div_ceil(std::mem::size_of::<u64>()) + 1;
        let mut buffer = vec![0u64; words];
        let mut length = size;
        // SAFETY: buffer is aligned and length covers the allocation.
        let result =
            unsafe { GetAdaptersInfo(buffer.as_mut_ptr() as *mut IpAdapterInfo, &mut length) };
        if result == ERROR_BUFFER_OVERFLOW {
            size = length.max(size.saturating_mul(2));
            continue;
        }
        if result != 0 {
            return Err(format!("GetAdaptersInfo failed with code {result}"));
        }

        let mut adapters = Vec::new();
        let mut current = buffer.as_ptr() as *const IpAdapterInfo;
        while !current.is_null() {
            // SAFETY: GetAdaptersInfo returned a linked list inside buffer and
            // current points at one live node.
            let node = unsafe { &*current };
            adapters.push(Adapter {
                name: c_array_string(&node.adapter_name),
                index: node.index,
                mac: adapter_mac(node),
                ips: adapter_ips(&node.ip_address_list),
            });
            // SAFETY: node.next is either null or another API-owned node.
            current = node.next;
        }
        return Ok(adapters);
    }
    Err("GetAdaptersInfo buffer overflowed repeatedly".to_string())
}

fn adapter_mac(adapter: &IpAdapterInfo) -> [u8; 6] {
    let mut mac = [0u8; 6];
    let length = (adapter.address_length as usize).min(6);
    mac[..length].copy_from_slice(&adapter.address[..length]);
    mac
}

fn adapter_ips(head: &IpAddrString) -> Vec<(Ipv4Addr, Ipv4Addr)> {
    let mut ips = Vec::new();
    let mut current: *const IpAddrString = head;
    while !current.is_null() {
        // SAFETY: current points into the API-owned adapter linked list.
        let node = unsafe { &*current };
        if let (Some(ip), Some(mask)) = (
            parse_c_array_ipv4(&node.ip_address),
            parse_c_array_ipv4(&node.ip_mask),
        ) {
            ips.push((ip, mask));
        }
        current = node.next;
    }
    ips
}

fn c_array_string(bytes: &[u8]) -> String {
    let length = bytes
        .iter()
        .position(|&byte| byte == 0)
        .unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..length]).into_owned()
}

fn parse_c_array_ipv4(bytes: &[u8; 16]) -> Option<Ipv4Addr> {
    let length = bytes
        .iter()
        .position(|&byte| byte == 0)
        .unwrap_or(bytes.len());
    std::str::from_utf8(&bytes[..length]).ok()?.parse().ok()
}

fn arp_resolve(target: Ipv4Addr, source: Ipv4Addr) -> Result<[u8; 6], String> {
    let mut mac = [0u8; 8];
    let mut length = 6u32;
    // SAFETY: mac is an 8-byte buffer and length is the requested size.
    let result = unsafe {
        SendARP(
            u32::from_ne_bytes(target.octets()),
            u32::from_ne_bytes(source.octets()),
            mac.as_mut_ptr(),
            &mut length,
        )
    };
    if result != 0 {
        return Err(format!("SendARP failed with code {result}"));
    }
    if length < 6 {
        return Err(format!("SendARP returned {length} bytes"));
    }
    let mut resolved = [0u8; 6];
    resolved.copy_from_slice(&mac[..6]);
    Ok(resolved)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_ip_prefers_route_subnet() {
        let ips = vec![
            (Ipv4Addr::new(10, 0, 1, 10), Ipv4Addr::new(255, 255, 255, 0)),
            (
                Ipv4Addr::new(192, 168, 1, 10),
                Ipv4Addr::new(255, 255, 255, 0),
            ),
        ];
        assert_eq!(
            choose_source_ip(
                &ips,
                Ipv4Addr::new(192, 168, 1, 1),
                Ipv4Addr::new(192, 168, 1, 1)
            ),
            Some(Ipv4Addr::new(192, 168, 1, 10))
        );
    }

    #[test]
    #[cfg(target_pointer_width = "64")]
    fn ip_adapter_info_matches_the_64_bit_windows_layout() {
        assert_eq!(std::mem::size_of::<IpAddrString>(), 48);
        assert_eq!(std::mem::offset_of!(IpAdapterInfo, ip_address_list), 440);
        assert_eq!(std::mem::offset_of!(IpAdapterInfo, have_wins), 584);
        assert_eq!(std::mem::size_of::<IpAdapterInfo>(), 688);
    }

    #[test]
    fn c_array_string_stops_at_nul() {
        let mut name = [0u8; 16];
        name[..4].copy_from_slice(b"test");
        assert_eq!(c_array_string(&name), "test");
    }

    #[test]
    fn decoy_ports_stay_outside_the_probe_range() {
        for index in 0..32 {
            let port = decoy_source_port(index, 61000, 61999);
            assert!(!(61000..=61999).contains(&port));
        }
    }
}
