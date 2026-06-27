"""Dev CLI — live ingest stats. Phase 1 will flesh this out.

Usage:
    python scripts/cli.py stats
"""

import sys


def stats() -> None:
    print("Stats CLI — implemented in Phase 1.")
    print("Will show: ingest rate (certs/sec), dedup ratio, Redis queue depth, lag per log.")


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "stats"
    if cmd == "stats":
        stats()
    else:
        print(f"Unknown command: {cmd}")
        sys.exit(1)
