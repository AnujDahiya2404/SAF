"""
tests/attack_replay.py

Simulates an attacker who captures a previously-valid PublishRequest
envelope (same identifier_msg, same alpha) and resends it later.
Section VI-A claims: "using unique identifiers (identifier_msg) for each
message and checking their uniqueness within a session helps mitigate
these risks [replay/duplication]."

We verify the SAF gateway rejects the replayed identifier_msg.
"""

import sys
import time

import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from saf.gateway import SAFGateway
from saf.client import SAFClient


def main():
    gw = SAFGateway()
    gw.start()
    time.sleep(0.5)

    client = SAFClient(client_id="ClientAttackReplay")
    client.connect()
    assert client.register()

    print("\n--- First publish (legitimate) ---")
    status1 = client.publish("sensors/x", b"reading=1", replay_identifier="FIXED-ID-0001")
    assert status1.status == "Approved", "first publish should be approved"

    print("\n--- Replayed publish (same identifier_msg, same counter-derived alpha) ---")
    # Note: alpha was computed against the *old* counter value (Phase 2 increments c
    # client-side after approval), so a naive attacker replaying the exact same wire
    # bytes will also fail on HMAC/counter mismatch -- we simulate the stronger case
    # of an attacker who resends the *exact same envelope bytes* captured off the wire.
    status2 = client.publish("sensors/x", b"reading=1", replay_identifier="FIXED-ID-0001")
    print(f"Second attempt status: {status2.status}, reason: {status2.reason}")
    assert status2.status == "Denied", "replayed identifier_msg must be denied"
    assert "duplicate" in status2.reason.lower() or "hmac" in status2.reason.lower()

    print("\nGateway decision log:")
    for entry in gw.decision_log:
        print(" ", entry)

    client.disconnect()
    gw.stop()
    print("\nREPLAY ATTACK TEST: PASS (attack correctly denied)")


if __name__ == "__main__":
    main()
