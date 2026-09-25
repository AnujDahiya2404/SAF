"""
tests/attack_tamper.py

Simulates a man-in-the-middle who tampers with alpha (the HMAC) or with
the message content without knowing the session key k. Section VI-A:
"the broker checks the validity of t_msg and identifier_msg... [and]
computes the HMAC value using the received client_state, c, and k to
verify the authenticity of the client."

We test two things:
  1. A publish with a deliberately corrupted alpha is Denied.
  2. A publish with an unregistered client_id (never completed Phase 1)
     is Denied outright.
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

    print("=== Attack 1: tampered HMAC (alpha) ===")
    client = SAFClient(client_id="ClientAttackTamper")
    client.connect()
    assert client.register()

    status = client.publish("sensors/y", b"reading=99", tamper_alpha=True)
    print(f"Status: {status.status}, reason: {status.reason}")
    assert status.status == "Denied"
    assert "hmac" in status.reason.lower()
    print("Tampered-HMAC publish correctly denied.\n")

    # sanity: the SAME client, untampered, should still work (proves the
    # denial above was really about the tamper, not a broken client)
    status_ok = client.publish("sensors/y", b"reading=100")
    assert status_ok.status == "Approved"
    print("Follow-up legitimate publish from same client correctly approved.\n")
    client.disconnect()

    print("=== Attack 2: publish attempt with no Phase-1 registration ===")
    ghost = SAFClient(client_id="GhostClientNeverRegistered")
    ghost.connect()
    # deliberately skip ghost.register() -- fabricate Phase-2 fields locally
    from saf import crypto_utils as cu
    from saf import protocol as proto
    import base64

    fake_alpha = cu.hmac_sha256(b"\x00" * 32, b"fake-state" + cu.counter_to_bytes(0))
    req = proto.PublishRequest(
        client_id=ghost.client_id,
        alpha_hex=fake_alpha.hex(),
        t_msg=cu.current_timestamp(),
        identifier_msg=cu.new_message_identifier(),
        level1_info="never-registered",
        topic="sensors/z",
        payload_b64=base64.b64encode(b"malicious").decode("ascii"),
        encrypted=False,
    )
    import paho.mqtt.client as mqtt
    ghost._mqtt.publish(proto.TOPIC_SESSION_PUBLISH, req.to_json(), qos=1)
    time.sleep(0.5)

    denied_entries = [e for e in gw.decision_log
                       if e["client_id"] == "GhostClientNeverRegistered"]
    print(f"Gateway log entries for ghost client: {denied_entries}")
    assert len(denied_entries) == 1 and denied_entries[0]["status"] == "Denied"
    print("Unregistered client publish correctly denied.\n")

    ghost.disconnect()
    gw.stop()
    print("TAMPER / UNREGISTERED-CLIENT ATTACK TESTS: PASS (attacks correctly denied)")


if __name__ == "__main__":
    main()
