"""
Tests for ingestion/parser.py

Fixture-based tests require fixtures — generate them first:
    python tests/generate_fixtures.py
"""

import pathlib

import pytest

from ingestion.parser import ParsedCert, extract_domains, parse_leaf_input

FIXTURES = pathlib.Path(__file__).parent / "fixtures"


def _has_fixtures() -> bool:
    return (FIXTURES / "entry_x509_0.bin").exists()


# ---------------------------------------------------------------------------
# leaf_input parsing — x509
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not _has_fixtures(), reason="run: python tests/generate_fixtures.py")
def test_parse_x509_entry():
    raw = (FIXTURES / "entry_x509_0.bin").read_bytes()
    import base64
    b64 = base64.b64encode(raw).decode()

    result = parse_leaf_input(b64, log_id="test-log", leaf_index=0)

    assert result is not None
    assert isinstance(result, ParsedCert)
    assert len(result.sha256_tbs) == 32
    assert len(result.sha256_leaf) == 32
    assert result.is_precert is False
    assert result.not_before is not None
    assert result.not_after is not None
    assert result.not_before < result.not_after
    assert result.log_id == "test-log"
    assert result.leaf_index == 0


@pytest.mark.skipif(not _has_fixtures(), reason="run: python tests/generate_fixtures.py")
def test_parse_precert_entry():
    raw = (FIXTURES / "entry_precert_0.bin").read_bytes()
    import base64
    b64 = base64.b64encode(raw).decode()

    result = parse_leaf_input(b64, log_id="test-log", leaf_index=0)

    assert result is not None
    assert result.is_precert is True
    assert len(result.sha256_tbs) == 32


@pytest.mark.skipif(not _has_fixtures(), reason="run: python tests/generate_fixtures.py")
def test_tbs_hash_stable_across_calls():
    """
    Critical invariant: parsing the same leaf_input twice yields the same
    sha256_tbs. This is a proxy for the pre-cert/cert dedup guarantee.
    """
    import base64
    raw = (FIXTURES / "entry_precert_0.bin").read_bytes()
    b64 = base64.b64encode(raw).decode()

    r1 = parse_leaf_input(b64, "test-log", 0)
    r2 = parse_leaf_input(b64, "test-log", 0)

    assert r1 is not None and r2 is not None
    assert r1.sha256_tbs == r2.sha256_tbs


@pytest.mark.skipif(not _has_fixtures(), reason="run: python tests/generate_fixtures.py")
def test_leaf_hash_differs_per_entry():
    """Two different entries must have different leaf hashes."""
    import base64
    p1 = FIXTURES / "entry_x509_0.bin"
    p2 = FIXTURES / "entry_x509_1.bin"
    if not p2.exists():
        pytest.skip("need at least 2 x509 fixtures")

    r1 = parse_leaf_input(base64.b64encode(p1.read_bytes()).decode(), "log", 0)
    r2 = parse_leaf_input(base64.b64encode(p2.read_bytes()).decode(), "log", 1)

    assert r1 is not None and r2 is not None
    assert r1.sha256_leaf != r2.sha256_leaf


# ---------------------------------------------------------------------------
# parse_entries_response
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not _has_fixtures(), reason="run: python tests/generate_fixtures.py")
def test_parse_entries_response_batch():
    import base64
    from ingestion.parser import parse_entries_response

    files = list(FIXTURES.glob("entry_x509_*.bin"))[:3]
    entries = [{"leaf_input": base64.b64encode(f.read_bytes()).decode()} for f in files]

    results = parse_entries_response(entries, "test-log", start_index=100)

    assert len(results) == len(files)
    assert results[0].leaf_index == 100
    assert results[-1].leaf_index == 100 + len(files) - 1


def test_parse_entries_response_empty():
    from ingestion.parser import parse_entries_response
    assert parse_entries_response([], "test-log", 0) == []


def test_parse_entries_response_bad_b64_skipped():
    from ingestion.parser import parse_entries_response
    entries = [{"leaf_input": "not-valid-base64!!!"}, {"leaf_input": ""}]
    results = parse_entries_response(entries, "test-log", 0)
    assert results == []


# ---------------------------------------------------------------------------
# domain extraction
# ---------------------------------------------------------------------------

def test_extract_domains_basic():
    domains = extract_domains(["www.example.com", "example.com", "api.example.com"])
    names = {d.domain for d in domains}
    assert names == {"www.example.com", "example.com", "api.example.com"}


def test_apex_flagged_correctly():
    domains = extract_domains(["example.com", "www.example.com"])
    by_name = {d.domain: d for d in domains}
    assert by_name["example.com"].is_apex is True
    assert by_name["www.example.com"].is_apex is False


def test_wildcard_stripped():
    domains = extract_domains(["*.example.com"])
    assert len(domains) == 1
    d = domains[0]
    assert d.domain == "example.com"
    assert d.is_wildcard is True
    assert d.is_apex is False


def test_dedup_within_sans():
    domains = extract_domains(["example.com", "example.com", "EXAMPLE.COM"])
    assert len(domains) == 1


def test_bare_ip_skipped():
    domains = extract_domains(["192.168.1.1", "example.com"])
    assert all(d.domain != "192.168.1.1" for d in domains)


def test_localhost_skipped():
    domains = extract_domains(["localhost", "example.com"])
    assert all(d.domain != "localhost" for d in domains)


def test_apex_domain_correct_for_subdomain():
    domains = extract_domains(["deep.sub.example.co.uk"])
    assert len(domains) == 1
    assert domains[0].apex_domain == "example.co.uk"


def test_parse_leaf_input_invalid_b64():
    result = parse_leaf_input("!!!notbase64", "test-log", 0)
    assert result is None


def test_parse_leaf_input_too_short():
    import base64
    result = parse_leaf_input(base64.b64encode(b"\x00" * 5).decode(), "test-log", 0)
    assert result is None
