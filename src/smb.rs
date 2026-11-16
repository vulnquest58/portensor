//! Deep SMB negotiation.
//!
//! The passive classifier in [`crate::service`] names the dialect from a
//! banner.  This module performs an active SMB2 NEGOTIATE plus an SMB1
//! NEGOTIATE fallback and records what the banner cannot show: signing policy,
//! encryption capability, server GUID, capabilities, and the SMB1 Native OS /
//! LAN Manager strings that old servers leak.

use std::net::IpAddr;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::discovery::socket_addr;
use crate::model::{PortResult, PortState};

const MAX_RESPONSE: usize = 16 * 1024;
const IDLE: Duration = Duration::from_millis(300);

/// Facts extracted from an SMB negotiate exchange.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SmbInfo {
    pub dialect: Option<String>,
    pub signing_enabled: bool,
    pub signing_required: bool,
    pub capabilities: Vec<String>,
    pub server_guid: Option<String>,
    pub os: Option<String>,
    pub lan_manager: Option<String>,
    pub domain: Option<String>,
}

impl SmbInfo {
    fn has_facts(&self) -> bool {
        self.dialect.is_some() || self.os.is_some()
    }

    pub fn signing_label(&self) -> &'static str {
        if self.signing_required {
            "required"
        } else if self.signing_enabled {
            "enabled"
        } else {
            "off"
        }
    }

    fn product(&self) -> Option<String> {
        let os = self.os.as_deref().unwrap_or_default();
        if os.to_ascii_lowercase().contains("samba") {
            Some("Samba".to_string())
        } else if os.to_ascii_lowercase().contains("windows") || self.lan_manager.is_some() {
            Some("Microsoft Windows SMB".to_string())
        } else if self.dialect.is_some() {
            Some("SMB Server".to_string())
        } else {
            None
        }
    }
}

/// Probe every SMB-looking open result.
pub async fn apply(results: &mut [PortResult], timeout: Duration, quiet: bool) -> usize {
    let timeout = timeout.clamp(Duration::from_millis(200), Duration::from_secs(10));
    let mut matched = 0;
    for result in results.iter_mut() {
        if result.state != PortState::Open {
            continue;
        }
        if result
            .service
            .as_ref()
            .is_some_and(|service| service.name.starts_with("udp:"))
        {
            continue;
        }
        if !is_smb_candidate(result) {
            continue;
        }
        if let Some(info) = probe(result.host, result.port, timeout).await
            && info.has_facts()
        {
            annotate(result, info);
            matched += 1;
        }
    }
    if matched > 0 && !quiet {
        eprintln!("[smb] captured negotiation details for {matched} endpoint(s)");
    }
    matched
}

fn is_smb_candidate(result: &PortResult) -> bool {
    if result.port == 445 || result.port == 139 {
        return true;
    }
    if let Some(service) = &result.service {
        if service.name.eq_ignore_ascii_case("smb")
            || service.name.eq_ignore_ascii_case("microsoft-ds")
            || service.name.eq_ignore_ascii_case("netbios-ssn")
        {
            return true;
        }
        if service
            .product
            .as_deref()
            .is_some_and(|product| product.to_ascii_lowercase().contains("smb"))
        {
            return true;
        }
    }
    result
        .banner
        .as_deref()
        .is_some_and(|banner| banner.to_ascii_uppercase().contains("SMB"))
}

async fn probe(host: IpAddr, port: u16, timeout: Duration) -> Option<SmbInfo> {
    let mut info = SmbInfo::default();
    if let Some(response) = exchange(host, port, &smb2_negotiate(), timeout).await
        && let Some(mut parsed) = parse_smb2_negotiate(&response)
    {
        info.dialect = parsed.dialect.take();
        info.signing_enabled = parsed.signing_enabled;
        info.signing_required = parsed.signing_required;
        info.capabilities = parsed.capabilities;
        info.server_guid = parsed.server_guid;
    }
    if let Some(response) = exchange(host, port, &smb1_negotiate(), timeout).await
        && let Some((os, lan_manager, domain)) = parse_smb1_native_strings(&response)
    {
        info.os = os;
        info.lan_manager = lan_manager;
        info.domain = domain;
    }
    Some(info)
}

async fn exchange(host: IpAddr, port: u16, payload: &[u8], timeout: Duration) -> Option<Vec<u8>> {
    let stream = tokio::time::timeout(timeout, TcpStream::connect(socket_addr(host, port)))
        .await
        .ok()?
        .ok()?;
    let _ = stream.set_nodelay(true);
    let mut stream = stream;
    tokio::time::timeout(timeout, stream.write_all(payload))
        .await
        .ok()?
        .ok()?;

    let deadline = Instant::now() + timeout;
    let mut response = Vec::new();
    let mut buffer = [0_u8; 4096];
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() || response.len() >= MAX_RESPONSE {
            break;
        }
        match tokio::time::timeout(IDLE.min(remaining), stream.read(&mut buffer)).await {
            Ok(Ok(0)) => break,
            Ok(Ok(read)) => {
                let take = read.min(MAX_RESPONSE - response.len());
                response.extend_from_slice(&buffer[..take]);
            }
            Ok(Err(_)) | Err(_) => break,
        }
    }
    (!response.is_empty()).then_some(response)
}

fn nbss_wrap(smb: &[u8]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(4 + smb.len());
    packet.push(0x00);
    let length = (smb.len() as u32).to_be_bytes();
    packet.extend_from_slice(&length[1..]);
    packet.extend_from_slice(smb);
    packet
}

fn smb2_negotiate() -> Vec<u8> {
    const DIALECTS: [u16; 5] = [0x0202, 0x0210, 0x0300, 0x0302, 0x0311];
    let body_len = 36 + DIALECTS.len() * 2;
    let mut smb = Vec::with_capacity(64 + body_len);
    smb.extend_from_slice(b"\xfeSMB");
    smb.extend_from_slice(&64u16.to_le_bytes()); // StructureSize
    smb.extend_from_slice(&0u16.to_le_bytes()); // CreditCharge
    smb.extend_from_slice(&0u32.to_le_bytes()); // Status
    smb.extend_from_slice(&0u16.to_le_bytes()); // Command: NEGOTIATE
    smb.extend_from_slice(&1u16.to_le_bytes()); // CreditRequest
    smb.extend_from_slice(&0u32.to_le_bytes()); // Flags
    smb.extend_from_slice(&0u32.to_le_bytes()); // NextCommand
    smb.extend_from_slice(&0u64.to_le_bytes()); // MessageId
    smb.extend_from_slice(&0xfeffu32.to_le_bytes()); // ProcessId
    smb.extend_from_slice(&0u32.to_le_bytes()); // TreeId
    smb.extend_from_slice(&0u64.to_le_bytes()); // SessionId
    smb.extend_from_slice(&[0u8; 16]); // Signature
    smb.extend_from_slice(&36u16.to_le_bytes()); // StructureSize (fixed base)
    smb.extend_from_slice(&(DIALECTS.len() as u16).to_le_bytes());
    smb.extend_from_slice(&1u16.to_le_bytes()); // SecurityMode: signing enabled
    smb.extend_from_slice(&0u16.to_le_bytes()); // Reserved
    smb.extend_from_slice(&0u32.to_le_bytes()); // Capabilities
    smb.extend_from_slice(&[0u8; 16]); // ClientGuid
    smb.extend_from_slice(&0u32.to_le_bytes()); // NegotiateContextOffset
    smb.extend_from_slice(&0u16.to_le_bytes()); // NegotiateContextCount
    smb.extend_from_slice(&0u16.to_le_bytes()); // Reserved2
    for dialect in DIALECTS {
        smb.extend_from_slice(&dialect.to_le_bytes());
    }
    nbss_wrap(&smb)
}

fn smb1_negotiate() -> Vec<u8> {
    let dialects: &[u8] = b"\x02NT LM 0.12\x00";
    let mut smb = Vec::with_capacity(32 + 3 + dialects.len());
    smb.extend_from_slice(b"\xffSMB");
    smb.push(0x72); // SMB_COM_NEGOTIATE
    smb.extend_from_slice(&[0, 0, 0, 0]); // status
    smb.push(0x18); // flags
    smb.extend_from_slice(&[0x01, 0x48]); // flags2 (extended security + unicode)
    smb.extend_from_slice(&[0, 0]); // PID high
    smb.extend_from_slice(&[0; 8]); // signature
    smb.extend_from_slice(&[0, 0]); // reserved
    smb.extend_from_slice(&[0, 0]); // TID
    smb.extend_from_slice(&[0, 0]); // PID
    smb.extend_from_slice(&[0, 0]); // UID
    smb.extend_from_slice(&[0, 0]); // MID
    smb.push(0); // word count
    smb.extend_from_slice(&(dialects.len() as u16).to_be_bytes());
    smb.extend_from_slice(dialects);
    nbss_wrap(&smb)
}

#[derive(Debug, Default)]
struct Smb2Negotiate {
    dialect: Option<String>,
    signing_enabled: bool,
    signing_required: bool,
    capabilities: Vec<String>,
    server_guid: Option<String>,
}

fn parse_smb2_negotiate(data: &[u8]) -> Option<Smb2Negotiate> {
    let start = data.windows(4).position(|window| window == b"\xfeSMB")?;
    let message = &data[start..];
    if message.len() < 64 + 64 {
        return None;
    }
    let body = &message[64..];
    let structure_size = u16::from_le_bytes([body[0], body[1]]);
    if structure_size != 65 {
        return None;
    }
    let security_mode = u16::from_le_bytes([body[2], body[3]]);
    let dialect_id = u16::from_le_bytes([body[4], body[5]]);
    let capabilities = u32::from_le_bytes([body[24], body[25], body[26], body[27]]);
    let guid = &body[8..24];

    Some(Smb2Negotiate {
        dialect: dialect_name(dialect_id).map(str::to_string),
        signing_enabled: security_mode & 0x0001 != 0,
        signing_required: security_mode & 0x0002 != 0,
        capabilities: capability_names(capabilities),
        server_guid: Some(format_guid(guid)),
    })
}

fn dialect_name(revision: u16) -> Option<&'static str> {
    match revision {
        0x0202 => Some("2.0.2"),
        0x0210 => Some("2.1"),
        0x0300 => Some("3.0"),
        0x0302 => Some("3.0.2"),
        0x0311 => Some("3.1.1"),
        0x02ff => Some("2.0"),
        _ => None,
    }
}

fn capability_names(capabilities: u32) -> Vec<String> {
    const FLAGS: [(u32, &str); 7] = [
        (0x0000_0001, "dfs"),
        (0x0000_0002, "leasing"),
        (0x0000_0004, "large_mtu"),
        (0x0000_0008, "multi_channel"),
        (0x0000_0010, "persistent_handles"),
        (0x0000_0020, "directory_leasing"),
        (0x0000_0040, "encryption"),
    ];
    FLAGS
        .iter()
        .filter(|(bit, _)| capabilities & bit != 0)
        .map(|(_, name)| (*name).to_string())
        .collect()
}

fn format_guid(guid: &[u8]) -> String {
    if guid.len() < 16 {
        return String::new();
    }
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        guid[3],
        guid[2],
        guid[1],
        guid[0],
        guid[5],
        guid[4],
        guid[7],
        guid[6],
        guid[8],
        guid[9],
        guid[10],
        guid[11],
        guid[12],
        guid[13],
        guid[14],
        guid[15]
    )
}

fn parse_smb1_native_strings(
    data: &[u8],
) -> Option<(Option<String>, Option<String>, Option<String>)> {
    let start = data.windows(4).position(|window| window == b"\xffSMB")?;
    let message = &data[start..];
    if message.len() < 33 || message[4] != 0x72 {
        return None;
    }
    let word_count = message[32] as usize;
    let byte_count_offset = 32 + 1 + word_count * 2;
    if message.len() < byte_count_offset + 2 {
        return None;
    }
    let byte_count =
        u16::from_be_bytes([message[byte_count_offset], message[byte_count_offset + 1]]) as usize;
    let byte_area_offset = byte_count_offset + 2;
    let end = (byte_area_offset + byte_count).min(message.len());
    if end <= byte_area_offset {
        return None;
    }
    let byte_area = &message[byte_area_offset..end];
    let challenge_length = if word_count >= 17 && message.len() > 66 {
        message[66] as usize
    } else {
        0
    };
    let byte_area = if challenge_length > 0 && challenge_length < byte_area.len() {
        &byte_area[challenge_length..]
    } else {
        byte_area
    };

    let mut strings = byte_area
        .split(|byte| *byte == 0)
        .map(str::from_utf8)
        .filter_map(Result::ok)
        .map(str::trim)
        .filter(|value| {
            value.len() >= 3
                && value
                    .chars()
                    .all(|character| character.is_ascii_graphic() || character == ' ')
        })
        .map(str::to_string);

    let os = strings.next();
    let lan_manager = strings.next();
    let domain = strings.next();
    Some((os, lan_manager, domain))
}

fn annotate(result: &mut PortResult, info: SmbInfo) {
    let previous = result.service.take();
    let mut service = previous.unwrap_or_default();
    service.name = "smb".to_string();
    if let Some(product) = info.product() {
        service.product = Some(product);
    }
    service.confidence =
        Some(
            service
                .confidence
                .unwrap_or(0.0)
                .max(if info.os.is_some() { 0.97 } else { 0.95 }),
        );
    service
        .info
        .insert("smb_signing".to_string(), info.signing_label().to_string());
    if let Some(dialect) = &info.dialect {
        service
            .info
            .insert("smb_dialect".to_string(), dialect.clone());
    }
    if !info.capabilities.is_empty() {
        service
            .info
            .insert("smb_capabilities".to_string(), info.capabilities.join(","));
    }
    if let Some(guid) = &info.server_guid
        && !guid.is_empty()
    {
        service
            .info
            .insert("smb_server_guid".to_string(), guid.clone());
    }
    if let Some(os) = &info.os {
        service.info.insert("smb_os".to_string(), os.clone());
    }
    if let Some(lan_manager) = &info.lan_manager {
        service
            .info
            .insert("smb_lan_manager".to_string(), lan_manager.clone());
    }
    if let Some(domain) = &info.domain {
        service
            .info
            .insert("smb_domain".to_string(), domain.clone());
    }

    result.service = Some(service);
    let detail = format!(
        "smb:{} signing={}",
        info.dialect.as_deref().unwrap_or("negotiated"),
        info.signing_label()
    );
    result.detail = Some(match result.detail.take() {
        Some(existing) if !existing.is_empty() => format!("{existing},{detail}"),
        _ => detail.clone(),
    });
    result.evidence = Some(match result.evidence.take() {
        Some(existing) if !existing.is_empty() => {
            format!("{existing} | {detail}")
        }
        _ => format!("active SMB negotiation: {detail}"),
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn smb2_response(security_mode: u16, dialect: u16, capabilities: u32) -> Vec<u8> {
        let mut message = Vec::new();
        message.extend_from_slice(b"\xfeSMB");
        message.extend_from_slice(&64u16.to_le_bytes());
        message.extend_from_slice(&1u16.to_le_bytes());
        message.extend_from_slice(&0u32.to_le_bytes());
        message.extend_from_slice(&0u16.to_le_bytes());
        message.extend_from_slice(&2u16.to_le_bytes());
        message.extend_from_slice(&0u32.to_le_bytes());
        message.extend_from_slice(&0u32.to_le_bytes());
        message.extend_from_slice(&[0u8; 8]);
        message.extend_from_slice(&0xfeffu32.to_le_bytes());
        message.extend_from_slice(&0u32.to_le_bytes());
        message.extend_from_slice(&[0u8; 8]);
        message.extend_from_slice(&[0u8; 16]);
        message.extend_from_slice(&65u16.to_le_bytes());
        message.extend_from_slice(&security_mode.to_le_bytes());
        message.extend_from_slice(&dialect.to_le_bytes());
        message.extend_from_slice(&0u16.to_le_bytes());
        message.extend_from_slice(&[0x11; 16]);
        message.extend_from_slice(&capabilities.to_le_bytes());
        message.extend_from_slice(&[0u8; 40]);
        let mut packet = nbss_wrap(&message);
        packet.extend_from_slice(&[0u8; 16]);
        packet
    }

    #[test]
    fn parses_smb2_negotiate_fields() {
        let data = smb2_response(0x0003, 0x0311, 0x0000_0040 | 0x0000_0004);
        let parsed = parse_smb2_negotiate(&data).unwrap();
        assert_eq!(parsed.dialect.as_deref(), Some("3.1.1"));
        assert!(parsed.signing_enabled);
        assert!(parsed.signing_required);
        assert_eq!(parsed.capabilities, vec!["large_mtu", "encryption"]);
        assert_eq!(
            parsed.server_guid.as_deref(),
            Some("11111111-1111-1111-1111-111111111111")
        );
    }

    #[test]
    fn parses_smb1_native_strings_from_byte_area() {
        let mut message = Vec::new();
        message.extend_from_slice(b"\xffSMB");
        message.push(0x72);
        message.extend_from_slice(&[0, 0, 0, 0]);
        message.push(0x98);
        message.extend_from_slice(&[0, 0]);
        message.extend_from_slice(&[0; 20]);
        message.push(17); // word count
        let mut parameters = [0u8; 34];
        parameters[33] = 8; // ChallengeLength
        message.extend_from_slice(&parameters);
        let byte_area = b"\x01\x02\x03\x04\x05\x06\x07\x08Windows Server 2019\x00Windows Server 2019 6.3\x00WORKGROUP\x00";
        message.extend_from_slice(&(byte_area.len() as u16).to_be_bytes());
        message.extend_from_slice(byte_area);
        let data = nbss_wrap(&message);

        let (os, lan, domain) = parse_smb1_native_strings(&data).unwrap();
        assert_eq!(os.as_deref(), Some("Windows Server 2019"));
        assert_eq!(lan.as_deref(), Some("Windows Server 2019 6.3"));
        assert_eq!(domain.as_deref(), Some("WORKGROUP"));
    }

    #[test]
    fn signing_label_reflects_policy() {
        let mut info = SmbInfo::default();
        assert_eq!(info.signing_label(), "off");
        info.signing_enabled = true;
        assert_eq!(info.signing_label(), "enabled");
        info.signing_required = true;
        assert_eq!(info.signing_label(), "required");
    }
}
