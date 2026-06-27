"""
Parse CT log entries from RFC 6962 get-entries responses.

RFC 6962 leaf_input is a base64-encoded MerkleTreeLeaf:
  [1 byte: version (0x00)]
  [1 byte: leaf_type (0x00)]
  [8 bytes: timestamp_ms]
  [2 bytes: entry_type]  0=x509  1=precert
  x509:    [3 bytes: cert_len][cert_len bytes: DER certificate]
  precert: [32 bytes: issuer_key_hash][3 bytes: tbs_len][tbs_len bytes: TBS DER]
  [2 bytes: extensions_len][extensions_len bytes: extensions]

Dedup key: SHA-256 of TBS bytes. Pre-cert and its final cert share the same
TBS, so they collapse to one row in the certificates table.
"""

import base64
import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone

import tldextract
from cryptography import x509
from cryptography.x509.oid import NameOID


@dataclass
class ParsedCert:
    sha256_tbs: bytes        # 32 bytes — dedup key
    sha256_leaf: bytes       # 32 bytes — SHA-256 of raw leaf_input bytes
    log_id: str
    leaf_index: int
    not_before: datetime
    not_after: datetime
    issuer_cn: str
    issuer_org: str
    subject_cn: str
    is_precert: bool
    sans: list[str] = field(default_factory=list)


@dataclass
class ParsedDomain:
    domain: str
    apex_domain: str
    is_wildcard: bool
    is_apex: bool


def parse_leaf_input(leaf_input_b64: str, log_id: str, leaf_index: int) -> ParsedCert | None:
    """Parse a single base64-encoded leaf_input from a get-entries response."""
    try:
        raw = base64.b64decode(leaf_input_b64)
    except Exception:
        return None
    return _parse_entry(raw, log_id, leaf_index)


def parse_entries_response(
    entries: list[dict], log_id: str, start_index: int
) -> list[ParsedCert]:
    """
    Parse a list of entry dicts from a ct/v1/get-entries JSON response.
    Each dict has 'leaf_input' (and optionally 'extra_data') as base64 strings.
    Skips malformed entries silently.
    """
    results: list[ParsedCert] = []
    for i, entry in enumerate(entries):
        leaf_input_b64 = entry.get("leaf_input", "")
        parsed = parse_leaf_input(leaf_input_b64, log_id, start_index + i)
        if parsed:
            results.append(parsed)
    return results


def extract_domains(sans: list[str]) -> list[ParsedDomain]:
    """Expand a SAN list into ParsedDomain records, one per unique domain."""
    seen: set[str] = set()
    results: list[ParsedDomain] = []

    for san in sans:
        is_wildcard = san.startswith("*.")
        raw_domain = san[2:] if is_wildcard else san
        raw_domain = raw_domain.lower().strip()

        if not raw_domain or raw_domain in seen:
            continue
        seen.add(raw_domain)

        ext = tldextract.extract(raw_domain)
        if not ext.domain or not ext.suffix:
            continue  # bare IPs, localhost, single-label names

        apex = f"{ext.domain}.{ext.suffix}"
        is_apex = (raw_domain == apex) and not is_wildcard

        results.append(
            ParsedDomain(
                domain=raw_domain,
                apex_domain=apex,
                is_wildcard=is_wildcard,
                is_apex=is_apex,
            )
        )

    return results


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _parse_entry(raw: bytes, log_id: str, leaf_index: int) -> ParsedCert | None:
    """
    Parse a full MerkleTreeLeaf byte sequence.
    Bytes 0-1: version + leaf_type (skipped).
    Bytes 2+:  TimestampedEntry.
    """
    sha256_leaf = hashlib.sha256(raw).digest()

    # MerkleTreeLeaf header: version(1) + leaf_type(1)
    if len(raw) < 12:
        return None
    pos = 2  # skip version + leaf_type

    # timestamp: 8 bytes (ms since epoch)
    pos += 8  # we don't need the timestamp — use cert not_before/not_after

    # entry_type: 2 bytes
    entry_type = int.from_bytes(raw[pos : pos + 2], "big")
    pos += 2

    if entry_type == 0:  # x509_entry
        if pos + 3 > len(raw):
            return None
        cert_len = int.from_bytes(raw[pos : pos + 3], "big")
        pos += 3
        if pos + cert_len > len(raw):
            return None
        cert_der = raw[pos : pos + cert_len]
        try:
            cert = x509.load_der_x509_certificate(cert_der)
        except Exception:
            return None
        tbs_bytes = cert.tbs_certificate_bytes
        is_precert = False

    elif entry_type == 1:  # precert_entry
        if pos + 32 + 3 > len(raw):
            return None
        pos += 32  # skip issuer_key_hash
        tbs_len = int.from_bytes(raw[pos : pos + 3], "big")
        pos += 3
        if pos + tbs_len > len(raw):
            return None
        tbs_bytes = raw[pos : pos + tbs_len]
        cert = _load_tbs_as_cert(tbs_bytes)
        if cert is None:
            return None
        is_precert = True

    else:
        return None

    sha256_tbs = hashlib.sha256(tbs_bytes).digest()

    return ParsedCert(
        sha256_tbs=sha256_tbs,
        sha256_leaf=sha256_leaf,
        log_id=log_id,
        leaf_index=leaf_index,
        not_before=_to_utc(cert.not_valid_before_utc),
        not_after=_to_utc(cert.not_valid_after_utc),
        issuer_cn=_attr(cert.issuer, NameOID.COMMON_NAME),
        issuer_org=_attr(cert.issuer, NameOID.ORGANIZATION_NAME),
        subject_cn=_attr(cert.subject, NameOID.COMMON_NAME),
        is_precert=is_precert,
        sans=_get_sans(cert),
    )


def _to_utc(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


def _load_tbs_as_cert(tbs_der: bytes) -> x509.Certificate | None:
    """
    Wrap a raw TBSCertificate DER in a minimal Certificate envelope so the
    cryptography library can parse it. The fake signature is never verified.
    """
    sig_alg = bytes.fromhex("300d06092a864886f70d01010b0500")
    sig_val = bytes.fromhex("03020000")
    inner = tbs_der + sig_alg + sig_val
    fake_cert_der = b"\x30" + _der_length(len(inner)) + inner
    try:
        return x509.load_der_x509_certificate(fake_cert_der)
    except Exception:
        return None


def _der_length(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    elif n < 0x100:
        return bytes([0x81, n])
    elif n < 0x10000:
        return bytes([0x82, n >> 8, n & 0xFF])
    else:
        return bytes([0x83, n >> 16, (n >> 8) & 0xFF, n & 0xFF])


def _attr(name: x509.Name, oid: x509.ObjectIdentifier) -> str:
    try:
        return name.get_attributes_for_oid(oid)[0].value
    except (IndexError, Exception):
        return ""


def _get_sans(cert: x509.Certificate) -> list[str]:
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        return [n.value for n in ext.value if isinstance(n, x509.DNSName)]
    except x509.ExtensionNotFound:
        cn = _attr(cert.subject, NameOID.COMMON_NAME)
        return [cn] if cn else []
    except Exception:
        return []
