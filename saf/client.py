"""
saf/client.py

SAFClient plays the role of "MQTT Client" in Algorithms 1 & 2: it performs
the Phase-1 pre-session handshake, then wraps every application publish in
a Phase-2-authenticated envelope sent to the SAF gateway.
"""

import base64
import json
import logging
import queue
import time

import paho.mqtt.client as mqtt

from . import crypto_utils as cu
from . import protocol as proto
from .ascon_enc import ascon_encrypt
from .telemetry import bus as telemetry_bus

def _make_client_logger(client_id: str) -> logging.Logger:
    logger = logging.getLogger(f"saf.client.{client_id}")
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter(f"[CLIENT:{client_id}] %(message)s"))
        logger.addHandler(handler)
        logger.setLevel(logging.INFO)
        logger.propagate = False
    return logger


class SAFClient:
    def __init__(self, client_id: str, host="127.0.0.1", port=1883):
        self.client_id = client_id
        self.host = host
        self.port = port
        self.log = _make_client_logger(client_id)

        self._mqtt = mqtt.Client(client_id=f"saf-client-{client_id}", protocol=mqtt.MQTTv311)
        self._mqtt.on_message = self._on_message
        self._mqtt.on_connect = self._on_connect

        # Phase-1 state (Algorithm 1, Step 7: client stores x, k, c)
        self.x: bytes = None
        self.k: bytes = None
        self.c: int = None
        self.session_time: str = None
        self.last_session_time: str = None
        self.registered = False

        self._presession_q: "queue.Queue" = queue.Queue()
        self._status_q: "queue.Queue" = queue.Queue()

    # ------------------------------------------------------------------ #

    def connect(self):
        self._mqtt.connect(self.host, self.port, keepalive=30)
        self._mqtt.loop_start()
        # wait for on_connect subscriptions to land
        time.sleep(0.2)

    def disconnect(self):
        self._mqtt.loop_stop()
        self._mqtt.disconnect()

    def _on_connect(self, client, userdata, flags, rc, properties=None):
        client.subscribe(
            proto.TOPIC_PRESESSION_RESPONSE_FMT.format(client_id=self.client_id), qos=1
        )
        client.subscribe(
            proto.TOPIC_SESSION_STATUS_FMT.format(client_id=self.client_id), qos=1
        )

    def _on_message(self, client, userdata, msg):
        payload = msg.payload.decode("utf-8")
        if msg.topic == proto.TOPIC_PRESESSION_RESPONSE_FMT.format(client_id=self.client_id):
            self._presession_q.put(payload)
        elif msg.topic == proto.TOPIC_SESSION_STATUS_FMT.format(client_id=self.client_id):
            self._status_q.put(payload)

    # ---------------------- Phase 1: Pre-Session (Algorithm 1) ---------------------- #

    def register(self, timeout: float = 5.0) -> bool:
        """Steps 1, 7, 8 of Algorithm 1 (client side)."""
        request_time = proto.now_iso()
        req = proto.PreSessionRequest(client_id=self.client_id, request_time=request_time)
        self._mqtt.publish(proto.TOPIC_PRESESSION_REQUEST, req.to_json(), qos=1)
        self.log.info(f"[Phase1] sent pre-session request, request_time={request_time}")
        telemetry_bus.publish(f"client:{self.client_id}", "phase1_request_sent",
                               client_id=self.client_id, request_time=request_time)

        try:
            payload = self._presession_q.get(timeout=timeout)
        except queue.Empty:
            self.log.error("[Phase1] timed out waiting for broker response "
                            "(offline registration failed, would repeat per Algorithm 1 else-branch)")
            telemetry_bus.publish(f"client:{self.client_id}", "phase1_timeout",
                                   client_id=self.client_id)
            return False

        resp = proto.PreSessionResponse.from_json(payload)

        # Step 7: client stores x, k, c (see protocol.py docstring re: client
        # possessing x rather than raw client_state)
        self.x = bytes.fromhex(resp.x_hex)
        self.k = bytes.fromhex(resp.k_hex)
        self.c = resp.c
        self.session_time = resp.session_time
        self.last_session_time = resp.session_time
        self.registered = True

        # Step 8: client sends ack
        ack = proto.PreSessionAck(client_id=self.client_id)
        self._mqtt.publish(
            proto.TOPIC_PRESESSION_RESPONSE_FMT.format(client_id=self.client_id) + "/ack",
            ack.to_json(), qos=1,
        )
        self.log.info(f"[Phase1] client-state established, x={self.x.hex()[:16]}..., "
                       f"k={self.k.hex()[:16]}..., c={self.c}")
        telemetry_bus.publish(f"client:{self.client_id}", "phase1_established",
                               client_id=self.client_id, x_hex=self.x.hex(),
                               k_hex=self.k.hex(), c=self.c, session_time=self.session_time)
        return True

    # ---------------------- Phase 2: In-Session (Algorithm 2) ---------------------- #

    def publish(self, topic: str, payload: bytes, encrypt: bool = False,
                timeout: float = 5.0, tamper_alpha: bool = False,
                replay_identifier: str = None, hardened: bool = False) -> "proto.VerificationStatus":
        """Steps 1-4 (client) then waits for the broker's Step 6 status.

        tamper_alpha / replay_identifier are attack-simulation hooks used
        by the tests/attack_*.py scripts -- they let us deliberately send
        a bad HMAC or a reused identifier_msg to verify the broker rejects it.

        hardened selects which alpha binding to use: False (default) is the
        base paper's Algorithm 2 exactly as specified -- HMAC_k(x||c), the
        variant scyther/saf_phase2.spdl finds Niagree/Nisynch failing for.
        True uses the sequence/message-bound binding verified all-pass in
        scyther/saf_phase2_hardened_final.spdl, and additionally verifies
        the broker's statusMac on the reply (see crypto_utils.compute_alpha /
        compute_status_mac).
        """
        if not self.registered:
            raise RuntimeError("client must complete Phase 1 (register()) before publishing")

        # Step 1: determine Level-1 information
        level1_info = self.last_session_time or self.session_time

        t_msg = cu.current_timestamp()
        identifier_msg = replay_identifier or cu.new_message_identifier()

        # Step 4: alpha -- see crypto_utils.compute_alpha for the as-specified
        # vs. hardened formulas
        alpha = cu.compute_alpha(self.k, self.x, self.c, hardened=hardened,
                                  identifier_msg=identifier_msg, t_msg=t_msg)
        if tamper_alpha:
            alpha = bytes([alpha[0] ^ 0xFF]) + alpha[1:]  # flip a bit -> invalid HMAC

        body = payload
        encrypted_flag = False
        if encrypt:
            body = ascon_encrypt(self.k, payload)
            encrypted_flag = True

        req = proto.PublishRequest(
            client_id=self.client_id,
            alpha_hex=alpha.hex(),
            t_msg=t_msg,
            identifier_msg=identifier_msg,
            level1_info=level1_info,
            topic=topic,
            payload_b64=base64.b64encode(body).decode("ascii"),
            encrypted=encrypted_flag,
            hardened=hardened,
        )
        self._mqtt.publish(proto.TOPIC_SESSION_PUBLISH, req.to_json(), qos=1)
        self.log.info(f"[Phase2] sent publish request topic={topic} "
                       f"identifier={identifier_msg} encrypted={encrypted_flag} hardened={hardened}")
        telemetry_bus.publish(
            f"client:{self.client_id}", "phase2_request_sent", client_id=self.client_id,
            alpha_hex=alpha.hex(), t_msg=t_msg, identifier_msg=identifier_msg,
            topic=topic, encrypted=encrypted_flag, counter_used=self.c,
            tampered=tamper_alpha, replayed=(replay_identifier is not None), hardened=hardened,
        )

        try:
            status_payload = self._status_q.get(timeout=timeout)
        except queue.Empty:
            self.log.error("[Phase2] timed out waiting for verification status")
            telemetry_bus.publish(f"client:{self.client_id}", "phase2_timeout",
                                   client_id=self.client_id, identifier_msg=identifier_msg)
            return None

        status = proto.VerificationStatus.from_json(status_payload)
        status_mac_valid = None
        if hardened and status.status_mac_hex is not None:
            expected_mac = cu.compute_status_mac(self.k, status.identifier_msg, status.status)
            status_mac_valid = cu.constant_time_eq(expected_mac, bytes.fromhex(status.status_mac_hex))
            if not status_mac_valid:
                self.log.warning("[Phase2] broker statusMac did NOT verify -- reply may be forged")
        if status.status == "Approved":
            self.c += 1  # counter increments with each new session/message, mirroring broker
            self.last_session_time = proto.now_iso()
            self.log.info(f"[Phase2] Approved (identifier={status.identifier_msg})")
        else:
            self.log.warning(f"[Phase2] Denied: {status.reason}")
        telemetry_bus.publish(
            f"client:{self.client_id}", "phase2_status_received", client_id=self.client_id,
            identifier_msg=status.identifier_msg, status=status.status, reason=status.reason,
            hardened=hardened, status_mac_hex=status.status_mac_hex, status_mac_valid=status_mac_valid,
        )
        return status
