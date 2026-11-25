#![no_main]

use libfuzzer_sys::fuzz_target;
use portensor::fingerprint::TcpFingerprint;

fuzz_target!(|data: &[u8]| {
    std::hint::black_box(portensor::syn::packet::parse_frame(data));
    let mut fingerprint = TcpFingerprint::default();
    portensor::fingerprint::parse_tcp_options(data, &mut fingerprint);
    std::hint::black_box(fingerprint);
});
