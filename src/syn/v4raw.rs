//! Raw IPv4 SYN scanning over Linux `AF_INET` raw sockets.
//!
//! IPv4 routing is delegated to the kernel, so this path works on point-to-point
//! interfaces (OpenVPN `tun`, WireGuard) where ARP is unavailable. SYN cookies
//! bind the target address to the target/source port pair.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddrV4, UdpSocket};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use super::pacer::Pacer;
use super::packet;
use super::permute::BlackRock;
use super::retry::{Retry, RetryQueue, retry_window};
use super::source_port::next_source_port;
use super::{ProbeMode, SynScanOptions};
use crate::error::AppError;
use crate::model::{HostProgress, PortResult, PortState, ScanReport, StateCounts};
use crate::rtt::RttEstimator;
use crate::scanner::{ProgressCallback, ProgressEvent};

struct RawSocket(i32);

impl Drop for RawSocket {
    fn drop(&mut self) {
        if self.0 >= 0 {
            // SAFETY: the descriptor is owned exclusively by this wrapper.
            unsafe { libc::close(self.0) };
        }
    }
}

#[derive(Debug)]
struct RxResponse {
    host: Ipv4Addr,
    port: u16,
    state: PortState,
    timestamp: Instant,
}

fn sockaddr_v4(target: Ipv4Addr, port: u16) -> libc::sockaddr_in {
    let mut addr: libc::sockaddr_in = unsafe { std::mem::zeroed() };
    addr.sin_family = libc::AF_INET as u16;
    addr.sin_port = port.to_be();
    addr.sin_addr.s_addr = u32::from(target).to_be();
    addr
}

/// `IPPROTO_RAW` destinations ignore `sin_port`; keep it zero.
fn sockaddr_v4_raw(target: Ipv4Addr) -> libc::sockaddr_in {
    sockaddr_v4(target, 0)
}

struct BatchV4 {
    packets: Vec<(Vec<u8>, libc::sockaddr_in, (Ipv4Addr, u16))>,
    len: usize,
}

impl BatchV4 {
    fn new(batch_size: usize) -> Self {
        let packets = (0..batch_size.max(1))
            .map(|_| {
                (
                    Vec::with_capacity(60),
                    sockaddr_v4_raw(Ipv4Addr::UNSPECIFIED),
                    (Ipv4Addr::UNSPECIFIED, 0),
                )
            })
            .collect();
        Self { packets, len: 0 }
    }

    fn len(&self) -> usize {
        self.len
    }

    fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Append an IPv4 SYN or ACK probe; the packet buffer is reused across probes.
    #[expect(clippy::too_many_arguments)]
    fn push(
        &mut self,
        target: Ipv4Addr,
        source: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        seq: u32,
        mode: ProbeMode,
        ttl: u8,
    ) {
        if self.len >= self.packets.len() {
            self.packets.push((
                Vec::with_capacity(40),
                sockaddr_v4_raw(target),
                (target, dst_port),
            ));
        }
        let (buffer, dest, key) = &mut self.packets[self.len];
        buffer.clear();
        let mut packet_buf = [0u8; 40];
        match mode {
            ProbeMode::Syn => packet::write_ipv4_syn_packet_into(
                &mut packet_buf,
                u32::from(source),
                u32::from(target),
                src_port,
                dst_port,
                seq,
                ttl,
            ),
            ProbeMode::Ack => packet::write_ipv4_ack_packet_into(
                &mut packet_buf,
                u32::from(source),
                u32::from(target),
                src_port,
                dst_port,
                seq,
                seq,
                ttl,
            ),
        }
        buffer.extend_from_slice(&packet_buf);
        *dest = sockaddr_v4_raw(target);
        *key = (target, dst_port);
        self.len += 1;
    }

    fn clear(&mut self) {
        self.len = 0;
    }
}

/// Sends a batch of raw IPv4 packets using `sendmmsg(2)`.
fn send_v4_frames_batch(fd: i32, batch: &BatchV4) -> Result<(), io::Error> {
    if batch.is_empty() {
        return Ok(());
    }

    let mut iovs: Vec<libc::iovec> = Vec::with_capacity(batch.len);
    let mut msgs: Vec<libc::mmsghdr> = Vec::with_capacity(batch.len);

    for (frame, dest, _) in batch.packets[..batch.len].iter() {
        let iov = libc::iovec {
            iov_base: frame.as_ptr() as *mut libc::c_void,
            iov_len: frame.len(),
        };
        iovs.push(iov);
        let last_iov_idx = iovs.len() - 1;

        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_name = dest as *const _ as *mut libc::c_void;
        msg.msg_namelen = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
        msg.msg_iov = &mut iovs[last_iov_idx];
        msg.msg_iovlen = 1;

        msgs.push(libc::mmsghdr {
            msg_hdr: msg,
            msg_len: 0,
        });
    }

    let mut sent = 0;
    while sent < msgs.len() {
        // SAFETY: `fd` is a valid open socket descriptor. `msgs` points to an array of valid
        // `libc::mmsghdr` structs with corresponding valid iovecs and sockaddr_in addresses.
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

fn flush_v4_batch(
    fd: i32,
    pacer: &mut Pacer,
    batch: &mut BatchV4,
    tx_times: &mut HashMap<(Ipv4Addr, u16), Instant>,
) -> Result<(), io::Error> {
    if batch.is_empty() {
        return Ok(());
    }

    pacer.wait_for_batch(batch.len);
    let now = Instant::now();
    for &(_, _, key) in batch.packets[..batch.len].iter() {
        tx_times.insert(key, now);
    }
    send_v4_frames_batch(fd, batch)?;
    batch.clear();
    Ok(())
}

pub(crate) fn source_for(target: Ipv4Addr, port: u16) -> Result<Ipv4Addr, AppError> {
    let socket = UdpSocket::bind("0.0.0.0:0").map_err(|error| {
        AppError::runtime(format!("cannot create IPv4 route probe socket: {error}"))
    })?;
    socket
        .connect(SocketAddrV4::new(target, port))
        .map_err(|error| {
            AppError::runtime(format!("cannot route to IPv4 target {target}: {error}"))
        })?;
    match socket.local_addr() {
        Ok(std::net::SocketAddr::V4(addr)) => Ok(*addr.ip()),
        _ => Err(AppError::runtime(format!(
            "cannot determine IPv4 source address for {target}"
        ))),
    }
}

/// Number of frames drained from the RX socket per `recvmmsg(2)` syscall.
const RX_BATCH: usize = 64;
/// Per-datagram receive buffer size.
const RX_SLOT_SIZE: usize = 2048;

struct RxBatch {
    data: Vec<[u8; RX_SLOT_SIZE]>,
    addrs: Vec<libc::sockaddr_in>,
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
            msg.msg_namelen = std::mem::size_of::<libc::sockaddr_in>() as u32;
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

fn send_rst_v4(
    fd: i32,
    source: Ipv4Addr,
    target: Ipv4Addr,
    source_port: u16,
    target_port: u16,
    seq: u32,
    ttl: u8,
) {
    if fd < 0 {
        return;
    }
    let mut packet = [0u8; 40];
    packet::write_ipv4_rst_packet_into(
        &mut packet,
        u32::from(source),
        u32::from(target),
        source_port,
        target_port,
        seq,
        ttl,
    );
    let dest = sockaddr_v4_raw(target);
    // SAFETY: `fd` is a valid raw socket; packet and dest are valid for the call.
    unsafe {
        libc::sendto(
            fd,
            packet.as_ptr().cast(),
            packet.len(),
            0,
            &dest as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        );
    }
}

#[expect(clippy::too_many_arguments)]
fn rx_loop(
    rx_fd: i32,
    rst_fd: i32,
    running: Arc<AtomicBool>,
    cookie_key: super::cookie::CookieKey,
    mode: ProbeMode,
    sources: HashMap<Ipv4Addr, Ipv4Addr>,
    ttl: u8,
    sender: crossbeam_channel::Sender<RxResponse>,
) {
    let _rst_socket = RawSocket(rst_fd);
    let mut batch = RxBatch::new(RX_BATCH);
    while running.load(Ordering::Acquire) {
        let count = match receive_batch(rx_fd, &mut batch) {
            Ok(count) => count,
            Err(error)
                if matches!(
                    error.kind(),
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
            if len == 0 {
                continue;
            }
            let now = Instant::now();
            match packet::parse_ipv4_tcp(&batch.data[index][..len]) {
                packet::ParsedV4Frame::SynAck {
                    src_ip,
                    src_port,
                    dst_port,
                    ack,
                } => {
                    if mode == ProbeMode::Syn
                        && cookie_key.validate(src_ip, src_port, dst_port, ack)
                    {
                        if let Some(&source) = sources.get(&Ipv4Addr::from(src_ip)) {
                            send_rst_v4(
                                rst_fd,
                                source,
                                Ipv4Addr::from(src_ip),
                                dst_port,
                                src_port,
                                ack,
                                ttl,
                            );
                        }
                        let _ = sender.send(RxResponse {
                            host: Ipv4Addr::from(src_ip),
                            port: src_port,
                            state: PortState::Open,
                            timestamp: now,
                        });
                    }
                }
                packet::ParsedV4Frame::Rst {
                    src_ip,
                    src_port,
                    dst_port,
                    seq,
                } => {
                    let state = match mode {
                        ProbeMode::Syn => PortState::Closed,
                        ProbeMode::Ack => {
                            let cookie = cookie_key.encode(src_ip, src_port, dst_port);
                            if seq != cookie {
                                continue;
                            }
                            PortState::Unfiltered
                        }
                    };
                    let _ = sender.send(RxResponse {
                        host: Ipv4Addr::from(src_ip),
                        port: src_port,
                        state,
                        timestamp: now,
                    });
                }
                packet::ParsedV4Frame::Other => {}
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
) {
    let key = (response.host, response.port);
    let latency = response
        .timestamp
        .saturating_duration_since(tx_times.get(&key).copied().unwrap_or(fallback));
    rtt.entry(response.host).or_default().observe(latency);
    *answered.entry(response.host).or_default() += 1;

    if matches!(
        responses.get(&key),
        Some((PortState::Open | PortState::Unfiltered, _))
    ) {
        return;
    }
    responses.insert(key, (response.state, latency));
}

fn drain_responses(
    receiver: &crossbeam_channel::Receiver<RxResponse>,
    tx_times: &HashMap<(Ipv4Addr, u16), Instant>,
    responses: &mut HashMap<(Ipv4Addr, u16), (PortState, Duration)>,
    fallback: Instant,
    rtt: &mut HashMap<Ipv4Addr, RttEstimator>,
    answered: &mut HashMap<Ipv4Addr, u32>,
) {
    while let Ok(response) = receiver.try_recv() {
        record_response(response, tx_times, responses, fallback, rtt, answered);
    }
}

#[expect(clippy::too_many_arguments)]
fn push_v4_probe(
    batch: &mut BatchV4,
    sources: &HashMap<Ipv4Addr, Ipv4Addr>,
    cookie_key: super::cookie::CookieKey,
    target: Ipv4Addr,
    port: u16,
    source_port: u16,
    mode: ProbeMode,
    ttl: u8,
) {
    let sequence = cookie_key.encode(u32::from(target), port, source_port);
    let source = sources[&target];
    batch.push(target, source, source_port, port, sequence, mode, ttl);
}

/// Execute a raw IPv4 SYN scan for the supplied targets.
pub(super) fn scan_v4_raw(
    targets: &[Ipv4Addr],
    opts: &SynScanOptions,
    progress: Option<&ProgressCallback>,
) -> Result<ScanReport, AppError> {
    if targets.is_empty() || opts.ports.is_empty() {
        return Err(AppError::usage(
            "scan needs at least one target and one port",
        ));
    }

    let total_probes = (targets.len() as u64)
        .checked_mul(opts.ports.len() as u64)
        .ok_or_else(|| AppError::usage("target/port combination count overflowed"))?;

    let mut sources: HashMap<Ipv4Addr, Ipv4Addr> = HashMap::new();
    for &target in targets {
        let source = source_for(target, opts.ports[0])?;
        sources.insert(target, source);
    }

    // SAFETY: probe whether an AF_INET raw TCP socket can be created.
    let rx_fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_TCP) };
    if rx_fd < 0 {
        return Err(AppError::runtime(format!(
            "failed to create IPv4 RX raw socket: {}",
            io::Error::last_os_error()
        )));
    }
    let _rx_socket = RawSocket(rx_fd);

    let bind_addr = sockaddr_v4(Ipv4Addr::UNSPECIFIED, 0);
    // SAFETY: rx_fd is a valid socket and bind_addr is fully initialized.
    if unsafe {
        libc::bind(
            rx_fd,
            &bind_addr as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        )
    } < 0
    {
        return Err(AppError::runtime(format!(
            "failed to bind IPv4 RX socket: {}",
            io::Error::last_os_error()
        )));
    }

    let timeout_us = 100_000;
    let tv = libc::timeval {
        tv_sec: 0,
        tv_usec: timeout_us,
    };
    let rcvbuf: libc::c_int = 4 * 1024 * 1024;
    // SAFETY: rx_fd is a valid socket; option pointers are valid for the call.
    unsafe {
        libc::setsockopt(
            rx_fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &tv as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        );
        libc::setsockopt(
            rx_fd,
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            &rcvbuf as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
    }

    // IPPROTO_RAW always expects the IPv4 header on Linux raw sockets.
    // SAFETY: creating a raw IPv4 transmit socket.
    let tx_fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_RAW, libc::IPPROTO_RAW) };
    if tx_fd < 0 {
        return Err(AppError::runtime(format!(
            "failed to create IPv4 TX raw socket: {}",
            io::Error::last_os_error()
        )));
    }
    let _tx_socket = RawSocket(tx_fd);

    // Duplicate the TX descriptor so the RX thread can send RSTs for accepted
    // SYN-ACKs without leaving half-open state on the target.
    // SAFETY: `tx_fd` is a valid open socket descriptor.
    let rst_fd = unsafe { libc::dup(tx_fd) };

    let (result_tx, result_rx) = crossbeam_channel::unbounded::<RxResponse>();
    let running = Arc::new(AtomicBool::new(true));
    let cookie_key = super::cookie::CookieKey::random();

    let rx_running = Arc::clone(&running);
    let rx_cookie = cookie_key;
    let rx_mode = opts.mode;
    let rx_sources = sources.clone();
    let rx_ttl = opts.ttl;
    let rx_handle = std::thread::Builder::new()
        .name("portensor-rx4".to_string())
        .spawn(move || {
            rx_loop(
                rx_fd, rst_fd, rx_running, rx_cookie, rx_mode, rx_sources, rx_ttl, result_tx,
            )
        })
        .map_err(|error| AppError::runtime(format!("failed to spawn IPv4 RX thread: {error}")))?;

    let blackrock = BlackRock::new(total_probes);
    let mut initial_pacer = Pacer::new(opts.rate_pps);
    let retry_rate = if opts.retry_rate_pps > 0 {
        opts.retry_rate_pps
    } else if opts.rate_pps > 0 {
        (opts.rate_pps / 4).max(100)
    } else {
        0
    };
    let mut retry_pacer = Pacer::new(retry_rate);
    let mut tx_times: HashMap<(Ipv4Addr, u16), Instant> = HashMap::new();
    let mut responses: HashMap<(Ipv4Addr, u16), (PortState, Duration)> = HashMap::new();
    let mut rtt: HashMap<Ipv4Addr, RttEstimator> = HashMap::new();
    let mut answered: HashMap<Ipv4Addr, u32> = HashMap::new();
    let mut retries: RetryQueue<(Ipv4Addr, u16)> = RetryQueue::new();
    let mut pending_initial: Vec<((Ipv4Addr, u16), u16, u32)> = Vec::new();
    let mut pending_retry: Vec<((Ipv4Addr, u16), u16, u32)> = Vec::new();

    let sport_lo = opts.sport_range.0;
    let sport_hi = opts.sport_range.1;
    let range_len = (sport_hi - sport_lo + 1) as u64;
    let ports_len = opts.ports.len() as u64;
    let start_time = Instant::now();
    let timeout_duration = Duration::from_millis(opts.timeout_ms);
    let mut initial_cursor = 0u64;
    let mut initial_done = false;
    let mut retries_allowed = true;
    let mut last_initial_send: Option<Instant> = None;

    let batch_size = opts.batch_size.max(1);
    let mut initial_batch = BatchV4::new(batch_size);
    let mut retry_batch = BatchV4::new(batch_size);

    loop {
        let now = Instant::now();
        let mut retry_probes = 0u64;

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
            if !initial_done && answered.get(&entry.key.0).copied().unwrap_or(0) == 0 {
                continue;
            }
            let attempt = entry.attempt + 1;
            let src_port = next_source_port(entry.src_port, sport_lo, total_probes, range_len);
            push_v4_probe(
                &mut retry_batch,
                &sources,
                cookie_key,
                entry.key.0,
                entry.key.1,
                src_port,
                opts.mode,
                opts.ttl,
            );
            pending_retry.push((entry.key, src_port, attempt));
            retry_probes += 1;
        }

        let mut initial_probes = 0u64;
        while initial_batch.len() < batch_size && initial_cursor < total_probes {
            let perm_index = blackrock.encrypt(initial_cursor);
            let target = targets[(perm_index / ports_len) as usize];
            let port = opts.ports[(perm_index % ports_len) as usize];
            let source_port = sport_lo + (perm_index % range_len) as u16;
            push_v4_probe(
                &mut initial_batch,
                &sources,
                cookie_key,
                target,
                port,
                source_port,
                opts.mode,
                opts.ttl,
            );
            pending_initial.push(((target, port), source_port, 0));
            initial_cursor += 1;
            initial_probes += 1;
        }

        if !retry_batch.is_empty() {
            flush_v4_batch(tx_fd, &mut retry_pacer, &mut retry_batch, &mut tx_times)
                .map_err(|error| AppError::runtime(format!("IPv4 TX send failed: {error}")))?;
            let sent_at = Instant::now();
            drain_responses(
                &result_rx,
                &tx_times,
                &mut responses,
                start_time,
                &mut rtt,
                &mut answered,
            );
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
            flush_v4_batch(tx_fd, &mut initial_pacer, &mut initial_batch, &mut tx_times)
                .map_err(|error| AppError::runtime(format!("IPv4 TX send failed: {error}")))?;
            let sent_at = Instant::now();
            last_initial_send = Some(sent_at);
            drain_responses(
                &result_rx,
                &tx_times,
                &mut responses,
                start_time,
                &mut rtt,
                &mut answered,
            );
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
            if let Some(callback) = progress {
                callback(ProgressEvent::default());
            }
        }

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
                    match result_rx.recv_timeout(wait) {
                        Ok(response) => record_response(
                            response,
                            &tx_times,
                            &mut responses,
                            start_time,
                            &mut rtt,
                            &mut answered,
                        ),
                        Err(crossbeam_channel::RecvTimeoutError::Timeout) => {}
                        Err(crossbeam_channel::RecvTimeoutError::Disconnected) => break,
                    }
                }
            }
        }
    }

    running.store(false, Ordering::Release);
    let _ = rx_handle.join();
    drain_responses(
        &result_rx,
        &tx_times,
        &mut responses,
        start_time,
        &mut rtt,
        &mut answered,
    );

    let mut counts = StateCounts::default();
    let mut results = Vec::new();
    let mut host_progress: HashMap<IpAddr, HostProgress> = HashMap::new();
    for &target in targets {
        for &port in &opts.ports {
            let (state, latency) = responses
                .get(&(target, port))
                .copied()
                .unwrap_or((PortState::Filtered, timeout_duration));
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
        workers: 2,
        elapsed: start_time.elapsed(),
        counts,
        results,
        os_fingerprints: HashMap::new(),
        probed_ports: opts.ports.clone(),
        host_progress,
        partial: false,
        defense_observations: Vec::new(),
    })
}
