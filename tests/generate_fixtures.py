"""
Fetch real entries from a CT log (RFC 6962 get-entries) to use as test fixtures.
Run once to regenerate fixtures:
    python tests/generate_fixtures.py

Writes to tests/fixtures/:
  entry_x509_<N>.bin     raw MerkleTreeLeaf bytes (base64-decoded leaf_input) for x509 entries
  entry_precert_<N>.bin  raw MerkleTreeLeaf bytes for precert entries
  README.txt             provenance info
"""

import asyncio
import base64
import pathlib

import httpx

FIXTURE_DIR = pathlib.Path(__file__).parent / "fixtures"
LOG_URL = "https://ct.cloudflare.com/logs/nimbus2025/"
# Fetch from a middle range so we get a mix of cert types
FETCH_START = 1_000_000
FETCH_END = FETCH_START + 999  # 1000 entries


async def main() -> None:
    FIXTURE_DIR.mkdir(exist_ok=True)

    async with httpx.AsyncClient(
        headers={"User-Agent": "signal-fixture-generator/0.1"},
        follow_redirects=True,
    ) as client:
        url = LOG_URL.rstrip("/") + f"/ct/v1/get-entries?start={FETCH_START}&end={FETCH_END}"
        print(f"Fetching {url} ...")
        r = await client.get(url, timeout=30)
        r.raise_for_status()
        entries = r.json().get("entries", [])
        print(f"  Got {len(entries)} entries")

    x509_count = 0
    precert_count = 0

    for entry in entries:
        leaf_input_b64 = entry.get("leaf_input", "")
        try:
            raw = base64.b64decode(leaf_input_b64)
        except Exception:
            continue

        if len(raw) < 12:
            continue

        # Bytes 10-11 = entry_type (after version=1, leaf_type=1, timestamp=8)
        entry_type = int.from_bytes(raw[10:12], "big")

        if entry_type == 0 and x509_count < 3:
            path = FIXTURE_DIR / f"entry_x509_{x509_count}.bin"
            path.write_bytes(raw)
            print(f"  Wrote {path} ({len(raw)} bytes)")
            x509_count += 1
        elif entry_type == 1 and precert_count < 3:
            path = FIXTURE_DIR / f"entry_precert_{precert_count}.bin"
            path.write_bytes(raw)
            print(f"  Wrote {path} ({len(raw)} bytes)")
            precert_count += 1

        if x509_count >= 3 and precert_count >= 3:
            break

    readme = FIXTURE_DIR / "README.txt"
    readme.write_text(
        f"Fixtures from {LOG_URL}\n"
        f"Entry range: {FETCH_START}-{FETCH_END}\n"
        "Format: base64-decoded leaf_input (full MerkleTreeLeaf with 2-byte header)\n"
        "entry_x509_*.bin    = x509 entries (entry_type=0)\n"
        "entry_precert_*.bin = pre-cert entries (entry_type=1)\n"
    )
    print(f"\nDone. {x509_count} x509 + {precert_count} precert fixtures.")


if __name__ == "__main__":
    asyncio.run(main())
