"""
tests/demo_normal_flow.py

End-to-end happy-path demo:
  1. Start the SAFGateway (acts as the "MQTT Broker" role in the paper).
  2. A SAFClient completes Phase 1 (pre-session / offline registration).
  3. The client publishes a few Phase-2-authenticated messages, one of
     them with ASCON encryption (Step 7, "high protection" data).
  4. A plain subscriber (no SAF involved) subscribes to the relayed
     app/<topic> and prints what actually reaches it -- demonstrating the
     gateway only relays *validated* traffic.
"""

import sys
import time
import threading
import paho.mqtt.client as mqtt

import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from saf.gateway import SAFGateway
from saf.client import SAFClient
from saf.ascon_enc import ascon_decrypt


def make_subscriber(topic, received):
    def on_message(client, userdata, msg):
        received.append((msg.topic, msg.payload))
        print(f"[SUBSCRIBER] received on {msg.topic}: {msg.payload}")

    sub = mqtt.Client(client_id="plain-subscriber")
    sub.on_message = on_message
    sub.connect("127.0.0.1", 1883, keepalive=30)
    sub.subscribe(topic, qos=1)
    sub.loop_start()
    return sub


def main():
    gw = SAFGateway()
    gw.start()
    time.sleep(0.5)

    received = []
    sub = make_subscriber("app/sensors/temp1", received)
    time.sleep(0.3)

    client = SAFClient(client_id="ClientMAC123")
    client.connect()

    print("\n=== Phase 1: Pre-Session ===")
    ok = client.register()
    assert ok, "Phase 1 registration failed"

    print("\n=== Phase 2: In-Session (plaintext) ===")
    status = client.publish("sensors/temp1", b"temp=23.5C")
    assert status.status == "Approved"

    print("\n=== Phase 2: In-Session (ASCON-encrypted, high protection) ===")
    status = client.publish("sensors/temp1", b"temp=24.1C;secure=true", encrypt=True)
    assert status.status == "Approved"

    time.sleep(0.5)
    print(f"\nSubscriber received {len(received)} messages: {received}")
    assert len(received) == 2, "expected both approved messages to be relayed"

    print("\nGateway decision log:")
    for entry in gw.decision_log:
        print(" ", entry)

    client.disconnect()
    sub.loop_stop()
    gw.stop()
    print("\nNORMAL FLOW DEMO: PASS")


if __name__ == "__main__":
    main()
