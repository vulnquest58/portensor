//! High-performance raw SYN scanner engine.
//!
//! Features:
//! - Hand-crafted Ethernet/IPv4/TCP frames sent over Linux `AF_PACKET` raw sockets
//! - Kernel-level BPF filtering for inbound SYN-ACK, RST, and ICMP Destination Unreachable frames
//! - SipHash-1-3 stateless SYN cookies encoded into TCP ISN
//! - BlackRock format-preserving Feistel permutation for $O(1)$-memory randomized probe traversal
//! - Asynchronous split-architecture with dedicated TX and RX threads pinned via core affinity
//! - Automatic fallback detection for unprivileged execution without `CAP_NET_RAW`

use std::collections::HashMap;
use std::fs;
use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use super::aimd::{AimdConfig, AimdController, AimdFeedback};
use super::cookie::CookieKey;
use super::filter;
use super::pacer::Pacer;
use super::packet;
use super::permute::BlackRock;
use super::retry::{Retry, RetryQueue, retry_window};
use super::route;
use super::source_port::next_source_port;
use super::{ProbeMode, SynScanOptions};
use crate::error::AppError;
use crate::model::{HostProgress, PortResult, PortState, ScanReport, StateCounts};
use crate::rtt::RttEstimator;
use crate::scanner::{ProgressCallback, ProgressEvent};

/// Internal RAII wrapper ensuring file descriptors are always closed on drop.
struct RawSocket(i32);

impl Drop for RawSocket {
    fn drop(&mut self) {
        if self.0 >= 0 {
            // SAFETY: self.0 is an open socket descriptor managed exclusively by this wrapper.
            unsafe { libc::close(self.0) };
        }
    }
}

/// Resolved routing and MAC addressing for a specific target IPv4 address.
#[derive(Clone, Debug)]
struct TargetRoute {
    if_idx: i32,
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: u32,
}

/// One outbound frame with an optional probe key used for latency tracking.
struct TxFrame {
    frame: Vec<u8>,
    sll: libc::sockaddr_ll,
    key: Option<(Ipv4Addr, u16)>,
}

/// Preallocated, reusable transmit batch.
///
/// Frame buffers are allocated once when the batch is created and reused slot
/// by slot across every probe/retransmission pass, so the steady-state transmit
/// loop never hits the heap allocator.
struct Batch {
    slots: Vec<TxFrame>,
    len: usize,
}

impl Batch {
    fn new(batch_size: usize) -> Self {
        let slots = (0..batch_size.max(1))
            .map(|_| TxFrame {
                frame: Vec::with_capacity(64),
                sll: unsafe { std::mem::zeroed() },
                key: None,
            })
            .collect();
        Self { slots, len: 0 }
    }

    fn len(&self) -> usize {
        self.len
    }

    fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Append a frame built on the stack (no heap allocation in steady state).
    fn push_frame(
        &mut self,
        frame: &[u8],
        if_idx: i32,
        dst_mac: &[u8; 6],
        key: Option<(Ipv4Addr, u16)>,
    ) {
        // Fragmented probes emit several frames for one slot iteration, so the
        // pool occasionally needs to grow past `batch_size`; existing slots are
        // never reallocated.
        if self.len >= self.slots.len() {
            self.slots.push(TxFrame {
                frame: Vec::with_capacity(64),
                sll: unsafe { std::mem::zeroed() },
                key: None,
            });
        }
        let slot = &mut self.slots[self.len];
        slot.frame.clear();
        slot.frame.extend_from_slice(frame);
        slot.sll = make_sll(if_idx, dst_mac);
        slot.key = key;
        self.len += 1;
    }
}

/// Incoming probe response message sent from the RX thread to the coordinator.
#[derive(Debug)]
struct RxResponse {
    host: Ipv4Addr,
    port: u16,
    state: PortState,
    timestamp: Instant,
    icmp_error: bool,
}

/// Checks if the current process has the necessary permissions (`root` or `CAP_NET_RAW`)
/// to open raw packet sockets.
pub fn check_raw_privilege() -> Result<(), AppError> {
    // SAFETY: Creating an AF_PACKET raw socket to probe kernel capability.
    let fd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW, 0) };
    if fd < 0 {
        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::EPERM) || err.raw_os_error() == Some(libc::EACCES) {
            return Err(AppError::runtime(
                "raw SYN scanning requires root privileges or CAP_NET_RAW capability",
            ));
        }
        return Err(AppError::runtime(format!(
            "failed to create raw socket: {err}",
        )));
    }
    // SAFETY: fd is a valid open socket descriptor.
    unsafe { libc::close(fd) };
    Ok(())
}

/// Enables loopback raw frame reception in the Linux kernel if running as root.
fn enable_loopback_raw() {
    let _ = fs::write("/proc/sys/net/ipv4/conf/all/accept_local", "1");
    let _ = fs::write("/proc/sys/net/ipv4/conf/lo/accept_local", "1");
    let _ = fs::write("/proc/sys/net/ipv4/conf/lo/route_localnet", "1");
}

/// Resolves the outgoing interface, source IP, and target/gateway MAC address for a target.
fn resolve_target_route(
    target: Ipv4Addr,
    cache: &mut HashMap<Ipv4Addr, TargetRoute>,
) -> Result<TargetRoute, AppError> {
    if let Some(cached) = cache.get(&target) {
        return Ok(cached.clone());
    }

    if target.is_loopback() {
        enable_loopback_raw();
        let lo_idx = route::iface_index("lo").map_err(|e| AppError::runtime(e.to_string()))?;
        let route_info = TargetRoute {
            if_idx: lo_idx,
            src_mac: [0u8; 6],
            dst_mac: [0u8; 6],
            src_ip: u32::from(Ipv4Addr::new(127, 0, 0, 1)),
        };
        cache.insert(target, route_info.clone());
        return Ok(route_info);
    }

    let rt = route::route_for(target).map_err(|e| AppError::runtime(e.to_string()))?;
    let src_mac = route::iface_mac(&rt.iface).map_err(|e| AppError::runtime(e.to_string()))?;
    let if_idx = route::iface_index(&rt.iface).map_err(|e| AppError::runtime(e.to_string()))?;
    // For directly connected routes, ARP the target itself; for gateway routes, ARP the gateway.
    let dst_mac = route::arp_resolve(&rt.iface, &src_mac, rt.src_ip, rt.gateway_ip)
        .map_err(|e| AppError::runtime(e.to_string()))?;

    let route_info = TargetRoute {
        if_idx,
        src_mac,
        dst_mac,
        src_ip: u32::from(rt.src_ip),
    };
    cache.insert(target, route_info.clone());
    Ok(route_info)
}

/// Sends a batch of raw Ethernet frames using `sendmmsg(2)`.
fn send_frames_batch(fd: i32, batch: &[TxFrame]) -> Result<(), io::Error> {
    if batch.is_empty() {
        return Ok(());
    }

    // Build the iovec/msghdr/mmsghdr arrays so the syscall sees contiguous
    // memory without per-flush heap allocation. Capacities are exact, so no
    // push reallocates and captured pointers stay valid.
    let mut iovs: Vec<libc::iovec> = Vec::with_capacity(batch.len());
    let mut msghdrs: Vec<libc::msghdr> = vec![unsafe { std::mem::zeroed() }; batch.len()];
    let mut msgs: Vec<libc::mmsghdr> = Vec::with_capacity(batch.len());

    for (index, TxFrame { frame, sll, .. }) in batch.iter().enumerate() {
        iovs.push(libc::iovec {
            iov_base: frame.as_ptr() as *mut libc::c_void,
            iov_len: frame.len(),
        });
        msghdrs[index].msg_name = sll as *const _ as *mut libc::c_void;
        msghdrs[index].msg_namelen = std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t;
        msghdrs[index].msg_iovlen = 1;
    }
    // SAFETY: `iovs` is fully populated and will not reallocate, so the
    // pointers below stay valid for the `sendmmsg` call.
    for index in 0..batch.len() {
        msghdrs[index].msg_iov = &mut iovs[index];
        msgs.push(libc::mmsghdr {
            msg_hdr: msghdrs[index],
            msg_len: 0,
        });
    }

    let mut sent = 0;
    while sent < msgs.len() {
        // SAFETY: `fd` is a valid open socket descriptor. `msgs` points to an array of valid
        // `libc::mmsghdr` structs with corresponding valid iovecs and sockaddr_ll addresses.
        let ret = unsafe {
            libc::sendmmsg(
                fd,
                msgs[sent..].as_mut_ptr(),
                (msgs.len() - sent) as libc::c_uint,
                0,
            )
        };
        if ret < 0 {
            let err = io::Error::last_os_error();
            if err.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
        sent += ret as usize;
    }
    Ok(())
}

fn flush_batch(
    fd: i32,
    pacer: &mut Pacer,
    batch: &mut Batch,
    tx_times: &mut HashMap<(Ipv4Addr, u16), Instant>,
    jitter_ms: u64,
) -> Result<(), io::Error> {
    if batch.is_empty() {
        return Ok(());
    }

    pacer.wait_for_batch(batch.len());
    if jitter_ms > 0 {
        use rand::Rng;
        let delay = rand::thread_rng().gen_range(0..=jitter_ms);
        if delay > 0 {
            std::thread::sleep(Duration::from_millis(delay));
        }
    }
    let now = Instant::now();
    for entry in batch.slots[..batch.len].iter() {
        if let Some(key) = entry.key {
            tx_times.insert(key, now);
        }
    }
    send_frames_batch(fd, &batch.slots[..batch.len])?;
    batch.len = 0;
    Ok(())
}

fn decoy_source_port(index: usize, sport_lo: u16, sport_hi: u16) -> u16 {
    let mut candidate = 1024_u16.wrapping_add(index as u16);
    for _ in 0..128 {
        if candidate != 0 && !(sport_lo..=sport_hi).contains(&candidate) {
            return candidate;
        }
        candidate = candidate.wrapping_add(1001);
    }
    if sport_lo > 1024 { 1023 } else { 65535 }
}

fn make_sll(if_idx: i32, dst_mac: &[u8; 6]) -> libc::sockaddr_ll {
    let mut sll: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    sll.sll_family = libc::AF_PACKET as u16;
    sll.sll_protocol = (libc::ETH_P_IP as u16).to_be();
    sll.sll_ifindex = if_idx;
    sll.sll_halen = 6;
    sll.sll_addr[..6].copy_from_slice(dst_mac);
    sll
}

/// Routes a decoded response to the TX worker that owns the destination
/// address and port.
fn dispatch_response(
    senders: &[crossbeam_channel::Sender<RxResponse>],
    plan: &ShardPlan,
    host: Ipv4Addr,
    port: u16,
    state: PortState,
    timestamp: Instant,
    icmp_error: bool,
) {
    if let Some(index) = plan.worker_index(host, port)
        && let Some(sender) = senders.get(index)
    {
        let _ = sender.send(RxResponse {
            host,
            port,
            state,
            timestamp,
            icmp_error,
        });
    }
}

/// Number of frames drained from the RX socket per `recvmmsg(2)` syscall.
const RX_BATCH: usize = 64;
/// Per-datagram receive buffer size (Ethernet frames are well under 2 KiB).
const RX_SLOT_SIZE: usize = 2048;

struct RxBatch {
    data: Vec<[u8; RX_SLOT_SIZE]>,
    addrs: Vec<libc::sockaddr_ll>,
    iovs: Vec<libc::iovec>,
    msgs: Vec<libc::mmsghdr>,
}

impl RxBatch {
    fn new(count: usize) -> Self {
        let data = vec![[0u8; RX_SLOT_SIZE]; count];
        let mut batch = Self {
            addrs: vec![unsafe { std::mem::zeroed() }; count],
            iovs: Vec::with_capacity(count.next_power_of_two()),
            msgs: Vec::with_capacity(count),
            data,
        };
        // SAFETY: every pointer group stays allocated and stable for the
        // lifetime of `batch`; the iovec/msg arrays are never reallocated
        // after construction.
        for slot in 0..count {
            let payload = batch.data[slot].as_mut_ptr();
            let name = batch.addrs.as_mut_ptr().wrapping_add(slot);
            // SAFETY: base pointers are initialized before the recv loop runs.
            let iov = libc::iovec {
                iov_base: payload.cast(),
                iov_len: RX_SLOT_SIZE,
            };
            let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
            msg.msg_name = name.cast();
            msg.msg_namelen = std::mem::size_of::<libc::sockaddr_ll>() as u32;
            msg.msg_iov = batch.iovs.as_mut_ptr().wrapping_add(slot);
            msg.msg_iovlen = 1;
            batch.iovs.push(iov);
            batch.msgs.push(libc::mmsghdr {
                msg_hdr: msg,
                msg_len: 0,
            });
        }
        batch
    }
}

/// Receives a batch of frames into `batch`; returns the number of frames read.
fn receive_batch(rx_fd: i32, batch: &mut RxBatch) -> io::Result<usize> {
    for msg in batch.msgs.iter_mut() {
        msg.msg_len = 0;
    }
    // SAFETY: `rx_fd` is a valid open socket; `batch.msgs` points to prebuilt
    // `libc::mmsghdr` entries whose iovecs and names reference allocations
    // owned by `batch` and outlive the syscall.
    let n = unsafe {
        libc::recvmmsg(
            rx_fd,
            batch.msgs.as_mut_ptr(),
            batch.msgs.len() as libc::c_uint,
            0,
            std::ptr::null_mut(),
        )
    };
    if n < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(n as usize)
    }
}

/// Response-classification rules shared by the RX worker.
#[derive(Clone, Copy)]
struct ProbePolicy {
    cookie_key: CookieKey,
    mode: ProbeMode,
}

impl ProbePolicy {
    /// Classifies a TCP RST for the active probe mode.
    ///
    /// ACK probes only accept a RST whose sequence number echoes the cookie we
    /// placed in the probe's acknowledgment field; anything else belongs to an
    /// unrelated flow or a spoofed packet.
    fn classify_rst(
        self,
        src_ip: u32,
        src_port: u16,
        dst_port: u16,
        seq: u32,
    ) -> Option<PortState> {
        match self.mode {
            ProbeMode::Syn => Some(PortState::Closed),
            ProbeMode::Ack => {
                let cookie = self.cookie_key.encode(src_ip, src_port, dst_port);
                (seq == cookie).then_some(PortState::Unfiltered)
            }
        }
    }
}

/// The continuous receive loop executed on the dedicated RX worker thread.
fn rx_loop(
    rx_fd: i32,
    running: Arc<AtomicBool>,
    policy: ProbePolicy,
    senders: Vec<crossbeam_channel::Sender<RxResponse>>,
    owners: HashMap<Ipv4Addr, usize>,
    port_groups: HashMap<u16, usize>,
    groups: usize,
) {
    let plan = ShardPlan {
        owners,
        port_groups,
        groups,
        shards: Vec::new(),
    };
    let mut batch = RxBatch::new(RX_BATCH);
    while running.load(Ordering::Acquire) {
        let count = match receive_batch(rx_fd, &mut batch) {
            Ok(count) => count,
            Err(err)
                if matches!(
                    err.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::Interrupted
                ) =>
            {
                continue;
            }
            Err(_) => break,
        };

        for index in 0..count {
            let len = batch.msgs[index].msg_len as usize;
            if len == 0 || batch.addrs[index].sll_pkttype == libc::PACKET_OUTGOING {
                // Ignore our own locally transmitted packets
                continue;
            }
            let frame = &batch.data[index][..len];
            let parsed = packet::parse_frame(frame);
            let now = Instant::now();

            match parsed {
                packet::ParsedFrame::SynAck {
                    src_ip,
                    src_port,
                    dst_port,
                    ack,
                    ..
                } => {
                    if policy.mode == ProbeMode::Syn
                        && policy.cookie_key.validate(src_ip, src_port, dst_port, ack)
                    {
                        dispatch_response(
                            &senders,
                            &plan,
                            Ipv4Addr::from(src_ip),
                            src_port,
                            PortState::Open,
                            now,
                            false,
                        );
                    }
                }
                packet::ParsedFrame::Rst {
                    src_ip,
                    src_port,
                    dst_port,
                    seq,
                } => {
                    let Some(state) = policy.classify_rst(src_ip, src_port, dst_port, seq) else {
                        continue;
                    };
                    dispatch_response(
                        &senders,
                        &plan,
                        Ipv4Addr::from(src_ip),
                        src_port,
                        state,
                        now,
                        false,
                    );
                }
                packet::ParsedFrame::IcmpUnreachable { dst_ip, dst_port } => {
                    dispatch_response(
                        &senders,
                        &plan,
                        Ipv4Addr::from(dst_ip),
                        dst_port,
                        PortState::Filtered,
                        now,
                        true,
                    );
                }
                packet::ParsedFrame::Other => {}
            }
        }
    }
}

fn record_response(
    response: RxResponse,
    tx_times: &HashMap<(Ipv4Addr, u16), Instant>,
    responses: &mut HashMap<(Ipv4Addr, u16), (PortState, Duration)>,
    fallback: Instant,
    rtt: &mut HashMap<Ipv4Addr, RttEstimator>,
    answered: &mut HashMap<Ipv4Addr, u32>,
    icmp_errors: &mut u64,
) {
    let key = (response.host, response.port);
    let tx_time = tx_times.get(&key).copied().unwrap_or(fallback);
    let latency = response.timestamp.saturating_duration_since(tx_time);
    rtt.entry(response.host).or_default().observe(latency);
    *answered.entry(response.host).or_default() += 1;
    if response.icmp_error {
        *icmp_errors = icmp_errors.saturating_add(1);
    }

    if let Some(&(PortState::Open | PortState::Unfiltered, _)) = responses.get(&key) {
        return;
    }
    responses.insert(key, (response.state, latency));
}

fn drain_responses(
    result_rx: &crossbeam_channel::Receiver<RxResponse>,
    tx_times: &HashMap<(Ipv4Addr, u16), Instant>,
    responses: &mut HashMap<(Ipv4Addr, u16), (PortState, Duration)>,
    fallback: Instant,
    rtt: &mut HashMap<Ipv4Addr, RttEstimator>,
    answered: &mut HashMap<Ipv4Addr, u32>,
    icmp_errors: &mut u64,
) {
    while let Ok(response) = result_rx.try_recv() {
        record_response(
            response,
            tx_times,
            responses,
            fallback,
            rtt,
            answered,
            icmp_errors,
        );
    }
}

/// Executes a raw SYN port scan against IPv4 and IPv6 targets.
pub fn syn_scan(
    opts: SynScanOptions,
    progress: Option<ProgressCallback>,
) -> Result<ScanReport, AppError> {
    if opts.targets.is_empty() || opts.ports.is_empty() {
        return Err(AppError::usage(
            "scan needs at least one target and one port",
        ));
    }
    let v4_targets: Vec<Ipv4Addr> = opts
        .targets
        .iter()
        .filter_map(|target| match target {
            IpAddr::V4(v4) => Some(*v4),
            IpAddr::V6(_) => None,
        })
        .collect();
    let v6_targets: Vec<std::net::Ipv6Addr> = opts
        .targets
        .iter()
        .filter_map(|target| match target {
            IpAddr::V6(v6) => Some(*v6),
            IpAddr::V4(_) => None,
        })
        .collect();

    if v6_targets.is_empty() {
        return syn_scan_v4(opts, progress);
    }
    if v4_targets.is_empty() {
        return super::v6::scan_v6(&v6_targets, &opts, progress.as_ref());
    }

    let started = Instant::now();
    let mut v4_opts = opts.clone();
    v4_opts.targets = v4_targets.iter().copied().map(IpAddr::V4).collect();
    let v4_report = syn_scan_v4(v4_opts, progress.clone())?;
    let mut report = super::v6::scan_v6(&v6_targets, &opts, progress.as_ref())?;

    report.targets += v4_report.targets;
    report.jobs += v4_report.jobs;
    report.elapsed = started.elapsed();
    report.counts.add_other(v4_report.counts);
    report.results.extend(v4_report.results);
    report.os_fingerprints.extend(v4_report.os_fingerprints);
    report.partial |= v4_report.partial;
    Ok(report)
}

/// Splits targets into contiguous destination shards for parallel TX workers.
fn shard_targets(targets: &[Ipv4Addr], max_workers: usize) -> Vec<Vec<Ipv4Addr>> {
    let max_workers = max_workers.max(1);
    let shard_len = targets.len().div_ceil(max_workers).max(1);
    targets
        .chunks(shard_len)
        .map(<[Ipv4Addr]>::to_vec)
        .collect()
}

/// Builds a lookup table mapping every target address to its owning shard.
fn shard_owners(shards: &[Vec<Ipv4Addr>]) -> HashMap<Ipv4Addr, usize> {
    let mut owners = HashMap::new();
    for (index, shard) in shards.iter().enumerate() {
        for &target in shard {
            owners.insert(target, index);
        }
    }
    owners
}

/// How the (target, port) probe space is split across parallel TX workers.
struct ShardPlan {
    /// One entry per TX worker: its target slice and port slice.
    shards: Vec<(Vec<Ipv4Addr>, Vec<u16>)>,
    /// Destination address to target-shard index.
    owners: HashMap<Ipv4Addr, usize>,
    /// Destination port to port-group index (single group when `groups == 1`).
    port_groups: HashMap<u16, usize>,
    /// Number of port groups per target shard.
    groups: usize,
}

impl ShardPlan {
    /// Resolves the RX fan-out worker index for a response destination.
    fn worker_index(&self, host: Ipv4Addr, port: u16) -> Option<usize> {
        let target_shard = self.owners.get(&host).copied()?;
        if self.groups == 1 {
            return Some(target_shard);
        }
        let group = self.port_groups.get(&port).copied().unwrap_or(0);
        Some(target_shard * self.groups + group)
    }
}

/// Splits the probe space into per-worker shards.
///
/// Targets are split contiguously first. When there are fewer targets than
/// workers (the common single-host scan), the port list is additionally split
/// into contiguous groups so one host can still saturate every TX core.
fn shard_plan(targets: &[Ipv4Addr], ports: &[u16], max_workers: usize) -> ShardPlan {
    let max_workers = max_workers.max(1);
    let target_shard_count = targets.len().min(max_workers).max(1);
    let target_shards = shard_targets(targets, target_shard_count);
    let mut groups = if targets.len() >= max_workers {
        1
    } else {
        (max_workers / target_shard_count).max(1)
    };
    // Every port group must contain at least one port.
    groups = groups.min(ports.len().max(1));

    let chunk_len = ports.len().div_ceil(groups);
    let mut port_groups = HashMap::with_capacity(ports.len());
    let mut shards = Vec::new();
    for (group, ports_chunk) in ports.chunks(chunk_len).enumerate() {
        for port in ports_chunk {
            port_groups.insert(*port, group);
        }
    }
    // Target-major layout so the RX fan-out index is `target * groups + group`.
    for target_shard in &target_shards {
        for ports_chunk in ports.chunks(chunk_len) {
            shards.push((target_shard.clone(), ports_chunk.to_vec()));
        }
    }
    let owners = shard_owners(&target_shards);
    ShardPlan {
        shards,
        owners,
        port_groups,
        groups,
    }
}

/// Per-TX-worker shard handed to its dedicated thread.
struct ShardJob {
    worker_id: usize,
    /// Number of CPU cores observed; used for core-affinity pinning.
    core_count: usize,
    targets: Vec<Ipv4Addr>,
    /// Pre-divided per-worker transmit rate (0 means unlimited).
    rate_pps: u64,
    /// Pre-divided per-worker retransmission rate (0 means unlimited).
    retry_rate_pps: u64,
    opts: SynScanOptions,
    routes: std::sync::Arc<HashMap<Ipv4Addr, TargetRoute>>,
    cookie_key: CookieKey,
    result_rx: crossbeam_channel::Receiver<RxResponse>,
    progress: Option<ProgressCallback>,
}

fn run_shard(job: ShardJob) -> Result<ScanReport, AppError> {
    // SAFETY: Creating raw AF_PACKET socket for probe frame transmission.
    let tx_fd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW, 0) };
    if tx_fd < 0 {
        return Err(AppError::runtime(format!(
            "failed to create TX raw socket: {}",
            io::Error::last_os_error()
        )));
    }
    let _tx_sock = RawSocket(tx_fd);

    let sndbuf: libc::c_int = 4 * 1024 * 1024;
    // SAFETY: tx_fd is a valid open socket.
    unsafe {
        libc::setsockopt(
            tx_fd,
            libc::SOL_SOCKET,
            libc::SO_SNDBUF,
            &sndbuf as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
    }

    // Pin each TX worker to a core after the RX-reserved first core.
    if job.core_count > 1
        && let Some(core) = core_affinity::get_core_ids()
            .and_then(|ids| ids.get((job.worker_id % (ids.len() - 1)) + 1).copied())
    {
        core_affinity::set_for_current(core);
    }

    scan_shard(&job, tx_fd)
}

/// Builds one logical SYN probe (fragments and decoys included) into `batch`.
fn push_probe(
    batch: &mut Batch,
    opts: &SynScanOptions,
    routes: &HashMap<Ipv4Addr, TargetRoute>,
    cookie_key: CookieKey,
    target_ip: Ipv4Addr,
    target_port: u16,
    src_port: u16,
) {
    let seq = cookie_key.encode(u32::from(target_ip), target_port, src_port);
    let rt = routes
        .get(&target_ip)
        .expect("target route resolved by the coordinator");
    let mut stack_frame = [0u8; 54];
    match opts.mode {
        ProbeMode::Syn => packet::write_syn_frame(
            &mut stack_frame,
            &rt.src_mac,
            &rt.dst_mac,
            rt.src_ip,
            u32::from(target_ip),
            src_port,
            target_port,
            seq,
            opts.ttl,
        ),
        ProbeMode::Ack => packet::write_ack_frame(
            &mut stack_frame,
            &rt.src_mac,
            &rt.dst_mac,
            rt.src_ip,
            u32::from(target_ip),
            src_port,
            target_port,
            seq,
            seq,
            opts.ttl,
        ),
    }

    let real_frames = match opts.fragment_size {
        Some(size) => packet::fragment_syn_frame(&stack_frame, size),
        None => vec![stack_frame.to_vec()],
    };
    for frame in real_frames {
        batch.push_frame(
            &frame,
            rt.if_idx,
            &rt.dst_mac,
            Some((target_ip, target_port)),
        );
    }

    for (decoy_index, decoy) in opts
        .decoys
        .iter()
        .enumerate()
        .filter(|_| opts.mode == ProbeMode::Syn)
    {
        let decoy_port = decoy_source_port(decoy_index, opts.sport_range.0, opts.sport_range.1);
        let decoy_frame = packet::build_syn_frame(
            &rt.src_mac,
            &rt.dst_mac,
            u32::from(*decoy),
            u32::from(target_ip),
            decoy_port,
            target_port,
            seq.wrapping_add(decoy_index as u32 + 1),
            opts.ttl,
        );
        let decoy_frames = match opts.fragment_size {
            Some(size) => packet::fragment_syn_frame(&decoy_frame, size),
            None => vec![decoy_frame.to_vec()],
        };
        for frame in decoy_frames {
            batch.push_frame(&frame, rt.if_idx, &rt.dst_mac, None);
        }
    }
}

fn scan_shard(job: &ShardJob, tx_fd: i32) -> Result<ScanReport, AppError> {
    let targets = job.targets.as_slice();
    let opts = &job.opts;
    let ports_len = opts.ports.len() as u64;
    if targets.is_empty() || ports_len == 0 {
        return Err(AppError::usage(
            "scan needs at least one target and one port",
        ));
    }
    let total_probes = (targets.len() as u64)
        .checked_mul(ports_len)
        .ok_or_else(|| AppError::usage("target/port combination count overflowed"))?;

    let blackrock = BlackRock::new(total_probes);
    let mut initial_pacer = Pacer::new(job.rate_pps);
    let mut retry_pacer = Pacer::new(job.retry_rate_pps);
    let mut tx_times: HashMap<(Ipv4Addr, u16), Instant> = HashMap::new();
    let mut responses: HashMap<(Ipv4Addr, u16), (PortState, Duration)> = HashMap::new();
    let mut rtt: HashMap<Ipv4Addr, RttEstimator> = HashMap::new();
    let mut answered: HashMap<Ipv4Addr, u32> = HashMap::new();
    let batch_size = opts.batch_size.max(1);
    let mut initial_batch = Batch::new(batch_size);
    let mut retry_batch = Batch::new(batch_size);
    let mut pending_initial: Vec<((Ipv4Addr, u16), u16, u32)> = Vec::new();
    let mut pending_retry: Vec<((Ipv4Addr, u16), u16, u32)> = Vec::new();
    let mut retries: RetryQueue<(Ipv4Addr, u16)> = RetryQueue::new();

    let sport_lo = opts.sport_range.0;
    let sport_hi = opts.sport_range.1;
    let range_len = (sport_hi - sport_lo + 1) as u64;
    let start_time = Instant::now();

    let timeout_duration = Duration::from_millis(opts.timeout_ms);
    let mut initial_cursor = 0u64;
    let mut initial_done = false;
    let mut retries_allowed = true;
    let mut last_initial_send: Option<Instant> = None;

    // AIMD controller for the initial pass
    let mut aimd = AimdController::new(AimdConfig {
        initial_pps: job.rate_pps,
        min_pps: opts.aimd_min_pps.max(1),
        max_pps: job.rate_pps,
        step_pps: (job.rate_pps / 4).max(10),
        ..AimdConfig::default()
    });
    let mut aimd_last_tick = Instant::now();
    let mut aimd_sent = 0u64;
    let mut aimd_received = 0u64;
    let mut aimd_icmp_errors = 0u64;
    let mut responses_seen = 0u64;

    loop {
        let now = Instant::now();
        let mut retry_probes = 0u64;

        // Retries run before new probes so a probe whose RTT window expired
        // is resent while the initial sweep is still in flight.
        while retry_batch.len() < batch_size {
            let Some(entry) = retries.pop_due(now) else {
                break;
            };
            if responses.contains_key(&entry.key)
                || !retries_allowed
                || entry.attempt >= opts.retries
            {
                continue;
            }
            // A host that has never answered is probably filtered or paging;
            // do not add retransmission load until it shows a live response.
            if !initial_done && answered.get(&entry.key.0).copied().unwrap_or(0) == 0 {
                continue;
            }
            let attempt = entry.attempt + 1;
            let src_port = next_source_port(entry.src_port, sport_lo, total_probes, range_len);
            push_probe(
                &mut retry_batch,
                opts,
                &job.routes,
                job.cookie_key,
                entry.key.0,
                entry.key.1,
                src_port,
            );
            pending_retry.push((entry.key, src_port, attempt));
            retry_probes += 1;
        }

        let mut initial_probes = 0u64;
        while initial_batch.len() < batch_size && initial_cursor < total_probes {
            let perm_idx = blackrock.encrypt(initial_cursor);
            let target_idx = (perm_idx / ports_len) as usize;
            let port_idx = (perm_idx % ports_len) as usize;
            let target_ip = targets[target_idx];
            let target_port = opts.ports[port_idx];
            let src_port = sport_lo + (perm_idx % range_len) as u16;
            push_probe(
                &mut initial_batch,
                opts,
                &job.routes,
                job.cookie_key,
                target_ip,
                target_port,
                src_port,
            );
            pending_initial.push(((target_ip, target_port), src_port, 0));
            initial_cursor += 1;
            initial_probes += 1;
        }

        if !retry_batch.is_empty() {
            flush_batch(
                tx_fd,
                &mut retry_pacer,
                &mut retry_batch,
                &mut tx_times,
                opts.jitter_ms,
            )
            .map_err(|e| AppError::runtime(format!("TX send failed: {e}")))?;
            let sent_at = Instant::now();
            drain_responses(
                &job.result_rx,
                &tx_times,
                &mut responses,
                start_time,
                &mut rtt,
                &mut answered,
                &mut aimd_icmp_errors,
            );
            let new_responses = responses.len() as u64 - responses_seen;
            if !initial_done {
                aimd_received = aimd_received.saturating_add(new_responses);
            }
            responses_seen = responses.len() as u64;
            for (key, src_port, attempt) in pending_retry.drain(..) {
                let deadline = sent_at + retry_window(rtt.get(&key.0), timeout_duration);
                retries.schedule(Retry {
                    deadline,
                    key,
                    src_port,
                    attempt,
                });
            }
        }

        if !initial_batch.is_empty() {
            flush_batch(
                tx_fd,
                &mut initial_pacer,
                &mut initial_batch,
                &mut tx_times,
                opts.jitter_ms,
            )
            .map_err(|e| AppError::runtime(format!("TX send failed: {e}")))?;
            let sent_at = Instant::now();
            last_initial_send = Some(sent_at);
            drain_responses(
                &job.result_rx,
                &tx_times,
                &mut responses,
                start_time,
                &mut rtt,
                &mut answered,
                &mut aimd_icmp_errors,
            );
            let new_responses = responses.len() as u64 - responses_seen;
            aimd_received = aimd_received.saturating_add(new_responses);
            responses_seen = responses.len() as u64;
            for (key, src_port, attempt) in pending_initial.drain(..) {
                let deadline = sent_at + retry_window(rtt.get(&key.0), timeout_duration);
                retries.schedule(Retry {
                    deadline,
                    key,
                    src_port,
                    attempt,
                });
            }
            if initial_cursor >= total_probes {
                initial_done = true;
            }
            aimd_sent = aimd_sent.saturating_add(initial_probes);
            if !initial_done
                && opts.aimd
                && job.rate_pps > 0
                && aimd_sent >= 64
                && aimd_last_tick.elapsed() >= Duration::from_secs(1)
            {
                let tarpit_pressure =
                    super::has_high_density_open(&responses, opts.anomaly_threshold);
                let new_rate = aimd.update_with_feedback(
                    aimd_sent,
                    aimd_received,
                    AimdFeedback {
                        icmp_errors: aimd_icmp_errors,
                        tarpit_pressure,
                    },
                );
                initial_pacer = Pacer::new(new_rate);
                aimd_last_tick = Instant::now();
                aimd_sent = 0;
                aimd_received = 0;
                aimd_icmp_errors = 0;
            }
            if let Some(cb) = &job.progress {
                cb(ProgressEvent::default());
            }
        }

        // A path that answered under 1 % of its probes is silent: retransmits
        // cannot recover responses that never arrive, so stop paying their
        // wall clock. Evaluate after the initial probes' full wait window.
        if initial_done
            && retries_allowed
            && last_initial_send.is_some_and(|sent| sent.elapsed() >= timeout_duration)
            && (responses.len() as u64).saturating_mul(100) < total_probes
        {
            retries_allowed = false;
            retries.clear();
        }

        if initial_cursor >= total_probes
            && initial_batch.is_empty()
            && retry_batch.is_empty()
            && retries.is_empty()
        {
            break;
        }

        if retry_probes == 0 && initial_probes == 0 {
            // Drop answered entries at the head so a fast response can end
            // the scan immediately instead of waiting for its deadline.
            while retries
                .peek()
                .is_some_and(|entry| responses.contains_key(&entry.key))
            {
                retries.pop();
            }
            if let Some(deadline) = retries.next_deadline() {
                let wait = deadline
                    .saturating_duration_since(Instant::now())
                    .min(Duration::from_millis(50));
                if !wait.is_zero() {
                    match job.result_rx.recv_timeout(wait) {
                        Ok(response) => record_response(
                            response,
                            &tx_times,
                            &mut responses,
                            start_time,
                            &mut rtt,
                            &mut answered,
                            &mut aimd_icmp_errors,
                        ),
                        Err(crossbeam_channel::RecvTimeoutError::Timeout) => {}
                        Err(crossbeam_channel::RecvTimeoutError::Disconnected) => break,
                    }
                }
            }
        }
    }

    drain_responses(
        &job.result_rx,
        &tx_times,
        &mut responses,
        start_time,
        &mut rtt,
        &mut answered,
        &mut aimd_icmp_errors,
    );

    // Aggregate the shard scan report
    let mut counts = StateCounts::default();
    let mut results = Vec::new();
    let mut host_progress: HashMap<IpAddr, HostProgress> = HashMap::new();

    for &target in targets {
        for &port in &opts.ports {
            let (state, latency) = match responses.get(&(target, port)) {
                Some(&(st, lat)) => (st, lat),
                None => (PortState::Filtered, timeout_duration),
            };
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
        elapsed: start_time.elapsed(),
        counts,
        results,
        os_fingerprints: std::collections::HashMap::new(),
        probed_ports: opts.ports.clone(),
        host_progress,
        partial: false,
        defense_observations: Vec::new(),
    })
}

fn syn_scan_v4(
    opts: SynScanOptions,
    progress: Option<ProgressCallback>,
) -> Result<ScanReport, AppError> {
    if opts.targets.is_empty() || opts.ports.is_empty() {
        return Err(AppError::usage(
            "scan needs at least one target and one port",
        ));
    }

    // 1. Verify raw socket privilege (CAP_NET_RAW or root)
    check_raw_privilege()?;

    // 2. Extract IPv4 targets (IPv6 is handled by the AF_INET6 engine).
    let v4_targets: Vec<Ipv4Addr> = opts
        .targets
        .iter()
        .filter_map(|target| match target {
            IpAddr::V4(v4) => Some(*v4),
            IpAddr::V6(_) => None,
        })
        .collect();

    // 3. Point-to-point interfaces (OpenVPN tun, WireGuard) have no ARP.
    //    Use the kernel-routed raw IPv4 engine instead of AF_PACKET.
    for &target in &v4_targets {
        let rt = route::route_for(target).map_err(|e| AppError::runtime(e.to_string()))?;
        if !route::iface_is_arp_capable(&rt.iface) {
            if !opts.decoys.is_empty() || opts.fragment_size.is_some() {
                return Err(AppError::usage(
                    "decoys and fragmentation require an Ethernet interface; \
                     point-to-point interfaces use the raw IPv4 engine",
                ));
            }
            return super::v4raw::scan_v4_raw(&v4_targets, &opts, progress.as_ref());
        }
    }

    // 4. Resolve routes and ARP for all targets
    let mut route_cache = HashMap::new();
    for &target in &v4_targets {
        resolve_target_route(target, &mut route_cache)?;
    }

    // 4. Open RX raw packet socket and attach BPF filter
    // SAFETY: Creating raw AF_PACKET socket to capture IPv4 frames.
    let rx_fd = unsafe {
        libc::socket(
            libc::AF_PACKET,
            libc::SOCK_RAW,
            (libc::ETH_P_IP as u16).to_be() as i32,
        )
    };
    if rx_fd < 0 {
        return Err(AppError::runtime(format!(
            "failed to create RX raw socket: {}",
            io::Error::last_os_error()
        )));
    }
    let _rx_sock = RawSocket(rx_fd);

    let filter = filter::build_filter(opts.sport_range.0, opts.sport_range.1);
    filter::attach_filter(rx_fd, &filter).map_err(|e| AppError::runtime(e.to_string()))?;

    // Set receive timeout of 100ms on RX socket
    let tv = libc::timeval {
        tv_sec: 0,
        tv_usec: 100_000,
    };
    // SAFETY: rx_fd is a valid open socket.
    unsafe {
        libc::setsockopt(
            rx_fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &tv as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        );
    }

    // Set receive buffer size to 4MB
    let rcvbuf: libc::c_int = 4 * 1024 * 1024;
    // SAFETY: rx_fd is a valid open socket.
    unsafe {
        libc::setsockopt(
            rx_fd,
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            &rcvbuf as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
    }

    // 5. Thread layout: one RX thread plus one TX thread per probe shard.
    //    Shards split targets first, then the port space so single-host
    //    scans still spread across all TX cores.
    let core_ids: Vec<core_affinity::CoreId> = core_affinity::get_core_ids().unwrap_or_default();
    let core_count = core_ids.len().max(1);
    let max_tx_workers = (core_count / 2).clamp(1, 8);
    let plan = shard_plan(&v4_targets, &opts.ports, max_tx_workers);
    let worker_count = plan.shards.len();

    let mut senders: Vec<crossbeam_channel::Sender<RxResponse>> = Vec::with_capacity(worker_count);
    let mut channels: Vec<crossbeam_channel::Receiver<RxResponse>> =
        Vec::with_capacity(worker_count);
    for _ in 0..worker_count {
        let (sender, receiver) = crossbeam_channel::unbounded::<RxResponse>();
        senders.push(sender);
        channels.push(receiver);
    }

    let running = Arc::new(AtomicBool::new(true));
    let cookie_key = CookieKey::random();

    // 6. Spawn RX worker thread with per-shard fan-out
    let rx_running = Arc::clone(&running);
    let rx_policy = ProbePolicy {
        cookie_key,
        mode: opts.mode,
    };
    let rx_owners = plan.owners.clone();
    let rx_port_groups = plan.port_groups.clone();
    let rx_groups = plan.groups;
    let rx_handle = std::thread::Builder::new()
        .name("portensor-rx".to_string())
        .spawn(move || {
            if let Some(first_core) =
                core_affinity::get_core_ids().and_then(|ids| ids.into_iter().next())
            {
                core_affinity::set_for_current(first_core);
            }
            rx_loop(
                rx_fd,
                rx_running,
                rx_policy,
                senders,
                rx_owners,
                rx_port_groups,
                rx_groups,
            );
        })
        .map_err(|e| AppError::runtime(format!("failed to spawn RX thread: {e}")))?;

    // 7. Divide rates evenly across TX workers
    let per_worker_rate = if opts.rate_pps > 0 {
        (opts.rate_pps / worker_count as u64).max(1)
    } else {
        0
    };
    let per_worker_retry_rate = if opts.retry_rate_pps > 0 {
        (opts.retry_rate_pps / worker_count as u64).max(1)
    } else if opts.rate_pps > 0 {
        (per_worker_rate / 4).max(100)
    } else {
        0
    };

    // 8. Spawn one TX worker per shard, each with its own AF_PACKET socket
    let routes = std::sync::Arc::new(route_cache);
    let overall_start = Instant::now();
    let mut handles = Vec::with_capacity(worker_count);
    for (worker_id, (targets, ports)) in plan.shards.into_iter().enumerate() {
        let shard_routes = std::sync::Arc::clone(&routes);
        let mut shard_opts = opts.clone();
        shard_opts.ports = ports;
        let shard_receiver = channels.remove(0);
        let shard_progress = progress.clone();
        let shard_cookie = cookie_key;
        let handle = std::thread::Builder::new()
            .name(format!("portensor-tx{worker_id}"))
            .spawn(move || {
                run_shard(ShardJob {
                    worker_id,
                    core_count,
                    targets,
                    rate_pps: per_worker_rate,
                    retry_rate_pps: per_worker_retry_rate,
                    opts: shard_opts,
                    routes: shard_routes,
                    cookie_key: shard_cookie,
                    result_rx: shard_receiver,
                    progress: shard_progress,
                })
            })
            .map_err(|e| AppError::runtime(format!("failed to spawn TX worker: {e}")))?;
        handles.push(handle);
    }

    // 9. Collect shard reports
    let mut merged = ScanReport {
        targets: v4_targets.len(),
        ports: opts.ports.len(),
        jobs: 0,
        workers: worker_count + 1,
        elapsed: overall_start.elapsed(),
        counts: StateCounts::default(),
        results: Vec::new(),
        os_fingerprints: std::collections::HashMap::new(),
        probed_ports: opts.ports.clone(),
        host_progress: HashMap::new(),
        partial: false,
        defense_observations: Vec::new(),
    };
    let mut worker_error: Option<AppError> = None;
    for handle in handles {
        let shard_report = match handle.join() {
            Ok(Ok(report)) => report,
            Ok(Err(error)) => {
                worker_error = Some(error);
                break;
            }
            Err(panic) => {
                worker_error = Some(AppError::runtime(format!("TX worker panicked: {panic:?}")));
                break;
            }
        };
        merged.jobs = merged.jobs.saturating_add(shard_report.jobs);
        merged.counts.add_other(shard_report.counts);
        merged.results.extend(shard_report.results);
        merged.os_fingerprints.extend(shard_report.os_fingerprints);
        merged.host_progress.extend(shard_report.host_progress);
        merged.partial |= shard_report.partial;
    }
    merged.elapsed = overall_start.elapsed();

    // 10. Stop RX thread
    running.store(false, Ordering::Release);
    let _ = rx_handle.join();

    if let Some(error) = worker_error {
        return Err(error);
    }

    Ok(merged)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shard_targets_partitions_without_overlap_or_loss() {
        let targets: Vec<Ipv4Addr> = (1..=10)
            .map(|octet| Ipv4Addr::new(10, 0, 0, octet))
            .collect();

        for workers in 1..=12 {
            let shards = shard_targets(&targets, workers);
            assert!(shards.len() <= workers.max(1));
            assert_eq!(shards.iter().map(Vec::len).sum::<usize>(), targets.len());
            let mut seen: Vec<(usize, Ipv4Addr)> = Vec::new();
            for (index, shard) in shards.iter().enumerate() {
                for &target in shard {
                    seen.push((index, target));
                }
            }
            let mut unique: Vec<(usize, Ipv4Addr)> = seen.clone();
            unique.dedup();
            assert_eq!(unique.len(), seen.len(), "duplicate target across shards");

            // Contiguous chunks preserve original order.
            let mut flattened: Vec<Ipv4Addr> = Vec::new();
            for shard in &shards {
                flattened.extend_from_slice(shard);
            }
            assert_eq!(flattened, targets);
        }
    }

    #[test]
    fn single_target_is_never_sharded() {
        let targets = vec![Ipv4Addr::new(10, 0, 0, 1)];
        let shards = shard_targets(&targets, 8);
        assert_eq!(shards.len(), 1);
        assert_eq!(shards[0], targets);
    }

    #[test]
    fn shard_plan_partitions_probes_exactly_once() {
        let targets: Vec<Ipv4Addr> = (1..=3)
            .map(|octet| Ipv4Addr::new(10, 0, 0, octet))
            .collect();
        let ports: Vec<u16> = (1..=100).collect();

        for workers in [1_usize, 2, 4, 8, 16] {
            let plan = shard_plan(&targets, &ports, workers);
            assert!(
                plan.shards.len() <= workers.max(1),
                "worker {} produced {} shards",
                workers,
                plan.shards.len()
            );

            // Every (target, port) pair appears in exactly one shard.
            let mut seen: Vec<(Ipv4Addr, u16)> = Vec::new();
            for (shard_targets, shard_ports) in &plan.shards {
                assert!(!shard_ports.is_empty(), "empty port shard");
                for &target in shard_targets {
                    for &port in shard_ports {
                        seen.push((target, port));
                    }
                }
            }
            seen.sort_unstable();
            seen.dedup();
            assert_eq!(seen.len(), targets.len() * ports.len(), "probe coverage");

            // Responses dispatch to the shard that owns the destination.
            for (index, (shard_targets, shard_ports)) in plan.shards.iter().enumerate() {
                let target = shard_targets[0];
                for &port in shard_ports {
                    assert_eq!(
                        plan.worker_index(target, port),
                        Some(index),
                        "port {port} dispatched to the wrong shard"
                    );
                }
            }
        }
    }

    #[test]
    fn shard_plan_splits_single_target_port_space() {
        let targets = vec![Ipv4Addr::new(10, 0, 0, 1)];
        let ports: Vec<u16> = (1..=64).collect();
        let plan = shard_plan(&targets, &ports, 4);
        assert_eq!(plan.shards.len(), 4);
        assert_eq!(plan.groups, 4);
        for (shard_targets, shard_ports) in &plan.shards {
            assert_eq!(shard_targets.as_slice(), targets.as_slice());
            assert_eq!(shard_ports.len(), 16);
        }
    }

    #[test]
    fn shard_plan_groups_ports_once_targets_fill_workers() {
        let targets: Vec<Ipv4Addr> = (1..=8)
            .map(|octet| Ipv4Addr::new(10, 0, 0, octet))
            .collect();
        let ports: Vec<u16> = (1..=32).collect();
        let plan = shard_plan(&targets, &ports, 4);
        assert_eq!(plan.shards.len(), 4);
        assert_eq!(plan.groups, 1);
        for (shard_targets, shard_ports) in &plan.shards {
            assert_eq!(shard_ports.len(), 32);
            assert_eq!(shard_targets.len(), 2);
        }
    }

    #[test]
    fn shard_plan_clamps_groups_to_the_port_count() {
        let targets = vec![Ipv4Addr::new(10, 0, 0, 1)];
        let ports = vec![80_u16, 443, 22];
        let plan = shard_plan(&targets, &ports, 8);
        assert_eq!(plan.shards.len(), 3);
        for (_shard_targets, shard_ports) in &plan.shards {
            assert_eq!(shard_ports.len(), 1);
        }
    }

    #[test]
    fn owner_lookup_routes_every_target_to_its_shard() {
        let targets: Vec<Ipv4Addr> = (1..=6)
            .map(|octet| Ipv4Addr::new(192, 168, 100, octet))
            .collect();
        let shards = shard_targets(&targets, 3);
        let owners = shard_owners(&shards);
        assert_eq!(owners.len(), targets.len());
        for (index, shard) in shards.iter().enumerate() {
            for &target in shard {
                assert_eq!(owners.get(&target), Some(&index));
            }
        }
    }

    #[test]
    fn ack_rst_is_accepted_only_with_the_probe_cookie() {
        let key = CookieKey::random();
        let policy = ProbePolicy {
            cookie_key: key,
            mode: ProbeMode::Ack,
        };
        let target = u32::from(Ipv4Addr::new(10, 0, 0, 9));
        let cookie = key.encode(target, 443, 61000);

        assert_eq!(
            policy.classify_rst(target, 443, 61000, cookie),
            Some(PortState::Unfiltered)
        );
        assert_eq!(policy.classify_rst(target, 443, 61000, cookie ^ 1), None);
        assert_eq!(policy.classify_rst(target, 443, 61001, cookie), None);
    }

    #[test]
    fn syn_rst_still_classifies_as_closed() {
        let policy = ProbePolicy {
            cookie_key: CookieKey::random(),
            mode: ProbeMode::Syn,
        };
        let target = u32::from(Ipv4Addr::new(10, 0, 0, 9));
        assert_eq!(
            policy.classify_rst(target, 443, 61000, 0),
            Some(PortState::Closed)
        );
    }

    #[test]
    fn unfiltered_response_is_not_downgraded_by_a_later_filtered_response() {
        let host = Ipv4Addr::new(10, 0, 0, 9);
        let mut tx_times = HashMap::new();
        tx_times.insert((host, 443), Instant::now());
        let mut responses = HashMap::new();
        let mut rtt = HashMap::new();
        let mut answered = HashMap::new();
        let mut icmp_errors = 0;
        let now = Instant::now();

        record_response(
            RxResponse {
                host,
                port: 443,
                state: PortState::Unfiltered,
                timestamp: now,
                icmp_error: false,
            },
            &tx_times,
            &mut responses,
            now,
            &mut rtt,
            &mut answered,
            &mut icmp_errors,
        );
        record_response(
            RxResponse {
                host,
                port: 443,
                state: PortState::Filtered,
                timestamp: now,
                icmp_error: true,
            },
            &tx_times,
            &mut responses,
            now,
            &mut rtt,
            &mut answered,
            &mut icmp_errors,
        );

        assert_eq!(
            responses.get(&(host, 443)).map(|entry| entry.0),
            Some(PortState::Unfiltered)
        );
        assert_eq!(icmp_errors, 1);
    }
}
