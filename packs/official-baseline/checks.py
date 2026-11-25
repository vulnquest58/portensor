#!/usr/bin/env python3

import datetime
import json
import os
import sys

MAX_INPUT_BYTES = 1024 * 1024
MAX_FINDINGS = 16
EXPIRING_DAYS = 30


def as_text(value):
    if not isinstance(value, str):
        return ""
    return value.strip()


def as_int(value):
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    return None


def short(value, limit=180):
    text = as_text(value)
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


def timestamp(value):
    seconds = as_int(value)
    if seconds is None:
        return ""
    try:
        moment = datetime.datetime.fromtimestamp(seconds, datetime.timezone.utc)
    except (OverflowError, OSError, ValueError):
        return ""
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def add(findings, identifier, title, severity, confidence, description, evidence):
    findings.append(
        {
            "id": identifier,
            "title": title,
            "severity": severity,
            "confidence": confidence,
            "description": description,
            "evidence": evidence,
        }
    )


def tls_findings(context):
    tls = context.get("tls")
    if not isinstance(tls, dict):
        return []

    findings = []
    days = as_int(tls.get("days_remaining"))
    not_after = timestamp(tls.get("not_after"))
    not_before = timestamp(tls.get("not_before"))
    subject = short(tls.get("subject"))
    issuer = short(tls.get("issuer"))
    signature = short(tls.get("signature_algorithm"), 80)

    expired = tls.get("expired") is True
    not_yet_valid = tls.get("not_yet_valid") is True
    self_signed = tls.get("self_signed") is True

    if expired:
        parts = []
        if not_after:
            parts.append("not_after=" + not_after)
        if days is not None:
            parts.append("days_remaining=" + str(days))
        if subject:
            parts.append("subject=" + subject)
        add(
            findings,
            "tls-certificate-expired",
            "TLS certificate has expired",
            "high",
            0.99,
            "The certificate presented by the endpoint is outside its validity period. Clients that enforce certificate validation will reject the connection.",
            " ".join(parts) or "expired=true",
        )

    if not_yet_valid:
        parts = []
        if not_before:
            parts.append("not_before=" + not_before)
        if subject:
            parts.append("subject=" + subject)
        add(
            findings,
            "tls-certificate-not-yet-valid",
            "TLS certificate is not yet valid",
            "medium",
            0.99,
            "The certificate presented by the endpoint has a start date in the future. The host clock or the certificate itself may be incorrect.",
            " ".join(parts) or "not_yet_valid=true",
        )

    if not expired and not not_yet_valid and days is not None and 0 <= days <= EXPIRING_DAYS:
        parts = ["days_remaining=" + str(days)]
        if not_after:
            parts.append("not_after=" + not_after)
        if subject:
            parts.append("subject=" + subject)
        add(
            findings,
            "tls-certificate-expiring",
            "TLS certificate expires soon",
            "low",
            0.98,
            "The certificate expires within the configured renewal window. Renew it before clients begin rejecting the endpoint.",
            " ".join(parts),
        )

    if self_signed:
        parts = []
        if subject:
            parts.append("subject=" + subject)
        if issuer:
            parts.append("issuer=" + issuer)
        add(
            findings,
            "tls-certificate-self-signed",
            "TLS certificate is self-signed",
            "low",
            0.97,
            "The certificate subject matches its issuer. Clients cannot build a public trust path without explicitly trusting this certificate.",
            " ".join(parts) or "self_signed=true",
        )

    lowered = as_text(tls.get("signature_algorithm")).lower()
    weak_signature = (
        "sha1" in lowered
        or "md5" in lowered
        or "1.2.840.113549.1.1.4" in lowered
        or "1.2.840.113549.1.1.5" in lowered
        or "1.3.14.3.2.29" in lowered
    )
    if weak_signature:
        add(
            findings,
            "tls-certificate-weak-signature",
            "TLS certificate uses a weak signature algorithm",
            "medium",
            0.97,
            "The certificate is signed with SHA-1 or MD5, which is unsuitable for new deployments and may be rejected by modern clients.",
            "signature_algorithm=" + (signature or "unknown"),
        )

    return findings


def smb_findings(context):
    service = context.get("service")
    if not isinstance(service, dict):
        return []
    if as_text(service.get("name")).lower() != "smb":
        return []

    info = service.get("info")
    if not isinstance(info, dict):
        return []

    findings = []
    signing = as_text(info.get("smb_signing")).lower()
    dialect = short(info.get("smb_dialect"), 40)
    signing_evidence = "smb_signing=" + (signing or "unknown")
    if dialect:
        signing_evidence += " smb_dialect=" + dialect

    if dialect and signing == "off":
        add(
            findings,
            "smb-signing-not-required",
            "SMB signing is not required",
            "high",
            0.95,
            "The SMB server negotiated without signing support. SMB relay and tampering attacks are possible unless another control prevents them.",
            signing_evidence,
        )
    elif dialect and signing == "enabled":
        add(
            findings,
            "smb-signing-not-required",
            "SMB signing is not required",
            "medium",
            0.95,
            "The SMB server supports signing but does not require it. Clients that do not sign are exposed to SMB relay and tampering attacks.",
            signing_evidence,
        )

    os_name = short(info.get("smb_os"))
    lan_manager = short(info.get("smb_lan_manager"))
    domain = short(info.get("smb_domain"))
    if os_name or lan_manager:
        parts = []
        if os_name:
            parts.append("smb_os=" + os_name)
        if lan_manager:
            parts.append("smb_lan_manager=" + lan_manager)
        if domain:
            parts.append("smb_domain=" + domain)
        add(
            findings,
            "smb-v1-negotiation-accepted",
            "SMBv1 negotiation was accepted",
            "medium",
            0.90,
            "The server answered an SMBv1 negotiate request and disclosed legacy native strings. SMBv1 has known weaknesses and should be disabled where possible.",
            " ".join(parts),
        )

    return findings


def redis_findings(context):
    service = context.get("service")
    if not isinstance(service, dict):
        return []
    if as_text(service.get("name")).lower() != "redis":
        return []

    info = service.get("info")
    if not isinstance(info, dict):
        info = {}

    version = short(service.get("version"), 80)
    product = as_text(service.get("product")).lower()
    mode = short(info.get("mode"), 40)
    config_file = short(info.get("config_file"))
    if "redis" not in product and not version and not mode and not config_file:
        return []

    port = as_int(context.get("port")) or 0
    findings = []

    parts = []
    if version:
        parts.append("redis_version=" + version)
    if mode:
        parts.append("mode=" + mode)
    if config_file:
        parts.append("config_file=" + config_file)
    parts.append("port=" + str(port))

    add(
        findings,
        "redis-unauthenticated",
        "Redis accepts unauthenticated INFO requests",
        "high",
        0.95 if version else 0.85,
        "The Redis endpoint returned server information without authentication. This exposes configuration and indicates that unauthenticated commands are accepted.",
        " ".join(parts),
    )
    return findings


def docker_findings(context):
    service = context.get("service")
    if not isinstance(service, dict):
        return []
    name = as_text(service.get("name")).lower()
    if name not in ("docker", "docker-tls"):
        return []

    info = service.get("info")
    if not isinstance(info, dict):
        info = {}

    product = as_text(service.get("product")).lower()
    api_version = short(info.get("api_version"), 40)
    min_api_version = short(info.get("min_api_version"), 40)
    if name == "docker-tls" and "docker" not in product and not api_version:
        return []

    port = as_int(context.get("port")) or 0
    findings = []

    parts = ["port=" + str(port)]
    if api_version:
        parts.append("api_version=" + api_version)
    if min_api_version:
        parts.append("min_api_version=" + min_api_version)

    add(
        findings,
        "docker-api-unauthenticated",
        "Docker Engine API answered without authentication",
        "high",
        0.97 if api_version else 0.90,
        "The Docker Engine API answered an unauthenticated version or ping request. Unless a proxy enforces authentication, this grants powerful control over containers and host resources.",
        " ".join(parts),
    )
    return findings


def service_of(context):
    service = context.get("service")
    if not isinstance(service, dict):
        return {}
    return service


def service_name(context):
    return as_text(service_of(context).get("name")).lower()


def tls_weak_protocol_findings(context):
    tls = context.get("tls")
    if not isinstance(tls, dict):
        return []
    version = as_text(tls.get("version"))
    lowered = version.lower()
    weak = (
        lowered in ("sslv2", "sslv3", "tlsv1", "tlsv1.0", "tlsv1.1")
        or lowered.startswith("tlsv1.0")
        or lowered.startswith("tlsv1.1")
        or lowered.startswith("sslv3")
    )
    if not weak:
        return []
    return [
        {
            "id": "tls-weak-protocol",
            "title": "TLS endpoint negotiates a deprecated protocol",
            "severity": "medium",
            "confidence": 0.99,
            "description": "The endpoint negotiated SSLv3, TLS 1.0, or TLS 1.1. These protocol versions are deprecated and do not provide modern security properties.",
            "evidence": "tls_version=" + (short(version, 40) or "unknown"),
        }
    ]


def tls_weak_cipher_findings(context):
    tls = context.get("tls")
    if not isinstance(tls, dict):
        return []
    cipher = as_text(tls.get("cipher"))
    lowered = cipher.lower()
    weak_tokens = ("rc4", "3des", "des_", "_des", "export", "null", "md5", "anon")
    if not cipher or not any(token in lowered for token in weak_tokens):
        return []
    return [
        {
            "id": "tls-weak-cipher",
            "title": "TLS endpoint negotiated a weak cipher suite",
            "severity": "medium",
            "confidence": 0.97,
            "description": "The negotiated cipher suite uses RC4, 3DES, DES, NULL encryption, EXPORT-grade cryptography, or anonymous key exchange.",
            "evidence": "tls_cipher=" + short(cipher, 80),
        }
    ]


def tls_hostname_mismatch_findings(context):
    tls = context.get("tls")
    if not isinstance(tls, dict) or tls.get("hostname_matches") is not False:
        return []
    parts = []
    subject = short(tls.get("subject"))
    if subject:
        parts.append("subject=" + subject)
    parts.append("hostname_matches=false")
    return [
        {
            "id": "tls-hostname-mismatch",
            "title": "TLS certificate does not match the requested hostname",
            "severity": "medium",
            "confidence": 0.98,
            "description": "The certificate presented by the endpoint does not match the requested hostname. Strict clients will reject the connection or the endpoint may be served by the wrong virtual host.",
            "evidence": " ".join(parts),
        }
    ]


def cleartext_findings(context, names, identifier, title, protocol):
    if service_name(context) not in names:
        return []
    if isinstance(context.get("tls"), dict):
        return []
    port = as_int(context.get("port")) or 0
    return [
        {
            "id": identifier,
            "title": title,
            "severity": "medium",
            "confidence": 0.95,
            "description": protocol
            + " traffic is transmitted without TLS. Credentials, session data, and application content can be observed or modified by an on-path attacker.",
            "evidence": "service=" + service_name(context) + " port=" + str(port),
        }
    ]


def version_disclosure_findings(context, names, identifier, title, product=None):
    service = service_of(context)
    if as_text(service.get("name")).lower() not in names:
        return []
    if product is not None and product.lower() not in as_text(service.get("product")).lower():
        return []
    version = short(service.get("version"), 80)
    detected_product = short(service.get("product"), 80)
    if not version and service_name(context) == "ssh":
        banner = as_text(context.get("banner"))
        if banner.startswith("SSH-"):
            parts = banner.split("-", 2)
            if len(parts) == 3:
                version = short(parts[2], 80)
    if not version:
        return []
    parts = ["version=" + version]
    if detected_product:
        parts.insert(0, "product=" + detected_product)
    port = as_int(context.get("port")) or 0
    parts.append("port=" + str(port))
    return [
        {
            "id": identifier,
            "title": title,
            "severity": "low",
            "confidence": 0.94,
            "description": "The service disclosed its product or version in a passive response. This information helps attackers select matching exploits and should be minimized where practical.",
            "evidence": " ".join(parts),
        }
    ]


def exposed_service_findings(context, names, identifier, title, severity="medium", product=None):
    service = service_of(context)
    if as_text(service.get("name")).lower() not in names:
        return []
    if product is not None and product.lower() not in as_text(service.get("product")).lower():
        return []
    port = as_int(context.get("port")) or 0
    return [
        {
            "id": identifier,
            "title": title,
            "severity": severity,
            "confidence": 0.90,
            "description": "The service is reachable from the scanned network. Exposed management or data services should be restricted to trusted networks and protected by authentication.",
            "evidence": "service=" + service_name(context) + " port=" + str(port),
        }
    ]


def main():
    check = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("PORTENSOR_SCRIPT_NAME", "")
    handlers = {
        "tls-certificate": tls_findings,
        "tls-weak-protocol": tls_weak_protocol_findings,
        "tls-weak-cipher": tls_weak_cipher_findings,
        "tls-hostname-mismatch": tls_hostname_mismatch_findings,
        "smb-hardening": smb_findings,
        "redis-unauthenticated": redis_findings,
        "docker-unauthenticated": docker_findings,
        "cleartext-ftp": lambda context: cleartext_findings(
            context,
            ("ftp",),
            "cleartext-ftp",
            "FTP service transmits data in cleartext",
            "FTP",
        ),
        "cleartext-telnet": lambda context: cleartext_findings(
            context,
            ("telnet",),
            "cleartext-telnet",
            "Telnet service transmits data in cleartext",
            "Telnet",
        ),
        "cleartext-http": lambda context: cleartext_findings(
            context,
            ("http",),
            "cleartext-http",
            "HTTP service transmits data in cleartext",
            "HTTP",
        ),
        "cleartext-smtp": lambda context: cleartext_findings(
            context,
            ("smtp",),
            "cleartext-smtp",
            "SMTP service transmits data in cleartext",
            "SMTP",
        ),
        "cleartext-pop3": lambda context: cleartext_findings(
            context,
            ("pop3",),
            "cleartext-pop3",
            "POP3 service transmits data in cleartext",
            "POP3",
        ),
        "cleartext-imap": lambda context: cleartext_findings(
            context,
            ("imap",),
            "cleartext-imap",
            "IMAP service transmits data in cleartext",
            "IMAP",
        ),
        "ssh-version-disclosure": lambda context: version_disclosure_findings(
            context,
            ("ssh",),
            "ssh-version-disclosure",
            "SSH service discloses its version",
        ),
        "http-version-disclosure": lambda context: version_disclosure_findings(
            context,
            ("http",),
            "http-version-disclosure",
            "HTTP service discloses its product or version",
        ),
        "mysql-version-disclosure": lambda context: version_disclosure_findings(
            context,
            ("mysql",),
            "mysql-version-disclosure",
            "MySQL service discloses its version",
        ),
        "postgresql-version-disclosure": lambda context: version_disclosure_findings(
            context,
            ("postgresql",),
            "postgresql-version-disclosure",
            "PostgreSQL service discloses its version",
        ),
        "redis-version-disclosure": lambda context: version_disclosure_findings(
            context,
            ("redis",),
            "redis-version-disclosure",
            "Redis service discloses its version",
        ),
        "mongodb-version-disclosure": lambda context: version_disclosure_findings(
            context,
            ("mongodb",),
            "mongodb-version-disclosure",
            "MongoDB service discloses its version",
        ),
        "memcached-version-disclosure": lambda context: version_disclosure_findings(
            context,
            ("memcached",),
            "memcached-version-disclosure",
            "Memcached service discloses its version",
        ),
        "vnc-exposed": lambda context: exposed_service_findings(
            context,
            ("vnc",),
            "vnc-exposed",
            "VNC service is reachable from the scanned network",
        ),
        "rdp-exposed": lambda context: exposed_service_findings(
            context,
            ("rdp",),
            "rdp-exposed",
            "RDP service is reachable from the scanned network",
        ),
        "mongodb-exposed": lambda context: exposed_service_findings(
            context,
            ("mongodb",),
            "mongodb-exposed",
            "MongoDB service is reachable from the scanned network",
        ),
        "elasticsearch-exposed": lambda context: exposed_service_findings(
            context,
            ("http",),
            "elasticsearch-exposed",
            "Elasticsearch service is reachable from the scanned network",
            product="Elasticsearch",
        ),
    }
    handler = handlers.get(check)
    if handler is None:
        sys.stderr.write("unknown official check: " + check + "\n")
        return 2

    raw = sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)
    if len(raw) > MAX_INPUT_BYTES:
        sys.stderr.write("input exceeds the 1 MiB official-script limit\n")
        return 2
    try:
        context = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        sys.stderr.write("invalid JSON input: " + str(error) + "\n")
        return 2
    if not isinstance(context, dict) or context.get("api") != 1:
        sys.stderr.write("unsupported script API\n")
        return 2

    findings = handler(context)[:MAX_FINDINGS]
    json.dump({"findings": findings}, sys.stdout, separators=(",", ":"))
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
