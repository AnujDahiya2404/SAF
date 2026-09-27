#!/usr/bin/env python3
"""
ns3sim/tools/crosscheck_hmac.py

Computes saf/crypto_utils.py's compute_alpha() on the exact same fixed
vectors as tools/crosscheck_hmac.cc, in the same output format. The two
scripts' output should be byte-for-byte identical -- run both and diff:

    ./ns3sim/build/saf-crosscheck-hmac > /tmp/cpp.txt
    python3 ns3sim/tools/crosscheck_hmac.py > /tmp/py.txt
    diff /tmp/cpp.txt /tmp/py.txt && echo "MATCH"

This is the evidence that ns3sim's C++ reimplementation of SAF's crypto
(a second implementation, not the literal Scyther-modeled Python code --
see README.md's ns-3 section) computes exactly the same alpha as the real
saf/crypto_utils.py on the same inputs, not just "the same algorithm in
spirit."
"""

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(REPO_ROOT))

from saf import crypto_utils as cu  # noqa: E402

# Fixed vectors -- must match ns3sim/tools/crosscheck_hmac.cc exactly.
VECTORS = [
    ("0" * 64, "2023-06-14T10:05:00Z", "30 mins", 0),
    ("f" * 64, "2023-06-14T10:05:00Z", "30 mins", 1),
    ("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e",
     "2026-09-27T00:00:00Z", "45 mins", 65535),
]


def main():
    for key_hex, session_time, estimated_duration, counter in VECTORS:
        key = bytes.fromhex(key_hex)
        state_bytes = cu.serialize_client_state(session_time, estimated_duration)
        x = cu.sha256(state_bytes)
        alpha = cu.compute_alpha(key, x, counter)

        print(f"key={key_hex} session_time={session_time} "
              f"estimated_duration={estimated_duration} counter={counter}")
        print(f"  x={x.hex()}")
        print(f"  alpha={alpha.hex()}")


if __name__ == "__main__":
    main()
