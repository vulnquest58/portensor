//! Source-port rotation shared by raw probe backends.

/// Advances a retransmission to a fresh source port in the scan's range.
///
/// Fresh ports keep every retransmission a distinct SYN to the target stack;
/// reusing the original port lets a server coalesce duplicates and rely on its
/// own delayed SYN-ACK retransmission, which can outlast the scan window.
pub(super) fn next_source_port(current: u16, low: u16, probes: u64, range_len: u64) -> u16 {
    let mut step = probes.max(1) % range_len;
    if step == 0 {
        step = 1;
    }
    low + (((u64::from(current - low) + step) % range_len) as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_source_ports_advance_and_wrap() {
        assert_eq!(next_source_port(61000, 61000, 20, 1000), 61020);
        assert_eq!(next_source_port(61990, 61000, 20, 1000), 61010);
        assert_ne!(next_source_port(61000, 61000, 20, 1000), 61000);
        assert_ne!(next_source_port(61000, 61000, 1000, 1000), 61000);
    }
}
