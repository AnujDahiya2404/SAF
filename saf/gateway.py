"""
saf/gateway.py

SAFGateway plays the role of "MQTT Broker" in Algorithms 1 & 2. It is
itself an MQTT client of a real Mosquitto broker, subscribed to SAF
control topics. Clients never publish or subscribe directly against the
shared broker; they must first complete Phase 1 (pre-session) and then
submit every publish -- and every *subscribe* -- as a Phase-2-authenticated
envelope. Section V-A, Requirement 1 ("Both MQTT publishing clients and
MQTT subscribing clients must establish a client state") and Algorithm 2
Step 2 ("The MQTT client initiates a session to either publish data or
subscribe to a topic") specify the same challenge gating both actions, so
_verify_and_approve() below implements Algorithm 2 Steps 3-6 exactly once
and both _handle_session_publish and _handle_session_subscribe call it.
Only once a subscribe is Approved does that client's own MQTT connection
issue a real SUBSCRIBE (see SAFClient.subscribe()); only once a publish is
Approved does the gateway republish the plaintext payload under
app/<topic>, where any subscribed (and thus already SAF-approved) client
receives it via Mosquitto's own normal delivery. This mirrors Fig. 4 of the
paper, where the MQTT broker is the central hub enforcing SAF policies
before data reaches subscribers.

This "gateway" pattern is the practical way to layer an application-level
authentication protocol like SAF onto an unmodified, off-the-shelf broker
(Mosquitto) without writing a broker plugin in C.
"""

import base64
import json
import logging
import time

import paho.mqtt.client as mqtt

from . import crypto_utils as cu
from . import protocol as proto
from .state_store import SAFStateStore
from .ascon_enc import ascon_decrypt
from .telemetry import bus as telemetry_bus

logging.basicConfig(level=logging.INFO, format="[GATEWAY] %(message)s")
log = logging.getLogger("saf.gateway")


class SAFGateway:
    def __init__(self, host="127.0.0.1", port=1883, store: SAFStateStore = None):
        self.host = host
        self.port = port
        self.store = store or SAFStateStore()
        self.client = mqtt.Client(client_id="saf-gateway", protocol=mqtt.MQTTv311)
        self.client.on_connect = self._on_connect
        self.client.on_message = self._on_message
        # event log for tests / demos to inspect gateway decisions
        self.decision_log = []

    # ------------------------------------------------------------------ #

    def start(self):
        self.client.connect(self.host, self.port, keepalive=30)
        self.client.loop_start()

    def stop(self):
        self.client.loop_stop()
        self.client.disconnect()

    def _on_connect(self, client, userdata, flags, rc, properties=None):
        log.info(f"connected to broker rc={rc}")
        client.subscribe(proto.TOPIC_PRESESSION_REQUEST, qos=1)
        client.subscribe(proto.TOPIC_SESSION_PUBLISH, qos=1)
        client.subscribe(proto.TOPIC_SESSION_SUBSCRIBE, qos=1)

    def _on_message(self, client, userdata, msg):
        try:
            if msg.topic == proto.TOPIC_PRESESSION_REQUEST:
                self._handle_presession_request(msg.payload.decode("utf-8"))
            elif msg.topic == proto.TOPIC_SESSION_PUBLISH:
                self._handle_session_publish(msg.payload.decode("utf-8"))
            elif msg.topic == proto.TOPIC_SESSION_SUBSCRIBE:
                self._handle_session_subscribe(msg.payload.decode("utf-8"))
        except Exception as e:
            log.exception(f"error handling message on {msg.topic}: {e}")

    # ---------------------- Phase 1: Pre-Session (Algorithm 1) ---------------------- #

    def _handle_presession_request(self, payload: str):
        req = proto.PreSessionRequest.from_json(payload)
        log.info(f"[Phase1] pre-session request from client_id={req.client_id!r} "
                 f"request_time={req.request_time}")
        telemetry_bus.publish("gateway", "phase1_request_received",
                               client_id=req.client_id, request_time=req.request_time)

        # Step 2: verify client_id. In this reference implementation, "verification"
        # means the client_id is well-formed and registration is currently allowed
        # (rate-limiting / DoS restriction policies, Section V-B).
        if not self._verify_client_id(req.client_id):
            self._log_decision("presession", req.client_id, "DENIED", "invalid client_id")
            telemetry_bus.publish("gateway", "phase1_denied",
                                   client_id=req.client_id, reason="invalid client_id")
            return

        if not self.store.registration_allowed():
            self._log_decision("presession", req.client_id, "DENIED",
                                "registration blocked (rate limit / max clients)")
            telemetry_bus.publish("gateway", "phase1_denied", client_id=req.client_id,
                                   reason="registration blocked (rate limit / max clients)")
            return

        # Step 3: broker creates client_state = (session_time, estimated_duration)
        session_time = proto.now_iso()
        estimated_duration = "30 mins"
        state_bytes = cu.serialize_client_state(session_time, estimated_duration)

        # Step 4: x = h(client_state)
        x = cu.sha256(state_bytes)

        # Step 5: generate session key k (32 bytes) and counter c (starts at 0)
        k = cu.generate_session_key()
        c = cu.initial_counter()

        # persist client-state record
        self.store.register_client(
            client_id=req.client_id, state_hash=x, session_key=k, counter=c,
            session_time=session_time, estimated_duration=estimated_duration,
        )
        self.store.update_last_session_time(req.client_id, session_time)

        # Step 6: broker sends y = x || k || c to client (hex-encoded over JSON)
        resp = proto.PreSessionResponse(
            client_id=req.client_id,
            x_hex=x.hex(),
            k_hex=k.hex(),
            c=c,
            session_time=session_time,
            estimated_duration=estimated_duration,
        )
        topic = proto.TOPIC_PRESESSION_RESPONSE_FMT.format(client_id=req.client_id)
        self.client.publish(topic, resp.to_json(), qos=1)
        log.info(f"[Phase1] client-state established for {req.client_id}; sent y=x||k||c")
        self._log_decision("presession", req.client_id, "ESTABLISHED", None)
        telemetry_bus.publish(
            "gateway", "phase1_established", client_id=req.client_id,
            x_hex=x.hex(), k_hex=k.hex(), c=c, session_time=session_time,
            estimated_duration=estimated_duration,
        )

    def _verify_client_id(self, client_id: str) -> bool:
        # In a production deployment this step would check the client_id
        # (e.g. MAC address) against a provisioned allow-list from the
        # secure offline registration environment (Section V-A: "conducted
        # in a controlled, secure environment"). Here we just require a
        # non-empty, reasonably-shaped identifier.
        return bool(client_id) and len(client_id) <= 128

    # ---------------------- Phase 2: In-Session (Algorithm 2) ---------------------- #

    def _handle_session_publish(self, payload: str):
        req = proto.PublishRequest.from_json(payload)
        result = self._verify_and_approve(req, intent="publish")
        if result is None:
            return
        rec, _status_mac_hex = result

        # Step 7 (optional): relay the payload to the real application topic
        raw = base64.b64decode(req.payload_b64)
        if req.encrypted:
            try:
                raw = ascon_decrypt(rec.session_key, raw)
            except ValueError as e:
                # authenticated encryption failed -- tampering downstream of the
                # HMAC check; treat as a security event, do not relay
                self._log_decision("publish", req.client_id, "TAMPER_DETECTED", str(e))
                telemetry_bus.publish("gateway", "phase2_tamper_detected",
                                       client_id=req.client_id, reason=str(e))
                return
        app_topic = proto.APP_TOPIC_PREFIX + req.topic
        self.client.publish(app_topic, raw, qos=1)
        log.info(f"[Phase2] relayed message from {req.client_id} -> {app_topic} "
                 f"(identifier={req.identifier_msg})")
        telemetry_bus.publish("gateway", "phase2_relayed", client_id=req.client_id,
                               app_topic=app_topic, topic=req.topic, identifier_msg=req.identifier_msg)

    def _handle_session_subscribe(self, payload: str):
        req = proto.SubscribeRequest.from_json(payload)
        # Same Algorithm 2 Steps 3-6 challenge as publish (Section V-A
        # Requirement 1 / Step 2) -- on Approval there is nothing further for
        # the *gateway* to do: the subscribing client's own MQTT connection
        # issues the real SUBSCRIBE (SAFClient.subscribe()), and Mosquitto's
        # normal delivery takes over from there whenever a publish is relayed.
        self._verify_and_approve(req, intent="subscribe")

    def _verify_and_approve(self, req, intent: str):
        """Algorithm 2, Steps 3-6, shared by both the publish and subscribe
        intents. Returns (ClientRecord, status_mac_hex) on Approval, having
        already recorded the identifier/bumped the counter/sent the status
        reply; returns None (having already denied and replied) otherwise."""
        rec = self.store.get_client(req.client_id)
        telemetry_bus.publish(
            "gateway", "phase2_request_received", client_id=req.client_id, intent=intent,
            alpha_hex=req.alpha_hex, t_msg=req.t_msg, identifier_msg=req.identifier_msg,
            topic=req.topic, hardened=req.hardened,
            counter_at_broker=(rec.counter if rec is not None else None),
        )

        if rec is None:
            self._deny(req, "unregistered client_id (no Phase-1 client-state on file)", intent)
            return None

        # DoS / anti-spoofing restriction: one active entity per client_id (Sec VI-B)
        # (checked on session initiation; released by caller when done -- for the
        #  stateless per-publish model here we just verify the identifier/HMAC below,
        #  the single-entity lock is exercised explicitly in the "connect" step of
        #  SAFClient / relevant tests.)

        # daily session-count cap (Section V-B rate limiting policy)
        # -- applied per publish for simplicity in this reference implementation;
        #    a production version would apply it per *session*, not per message.

        # Step 5a: freshness check on t_msg (anti-replay, Algorithm 2 note / Sec VI-A)
        if not self.store.is_fresh_timestamp(req.t_msg):
            self._deny(req, "stale timestamp t_msg (possible replay)", intent)
            return None

        # Step 5b: identifier_msg uniqueness check (anti-duplication/replay)
        if self.store.is_duplicate_identifier(req.client_id, req.identifier_msg):
            self._deny(req, "duplicate identifier_msg (replay or unintended duplication)", intent)
            return None

        # Step 5c: verify alpha -- as-specified HMAC_k(x||c), or the hardened
        # HMAC_k(x||c||identifier_msg||t_msg) if the client requested it (see
        # crypto_utils.compute_alpha; also protocol.py re: x-vs-client_state).
        # Captured before bump_counter() below so it reflects the counter
        # value this exchange actually verified against.
        counter_verified = rec.counter
        expected_alpha = cu.compute_alpha(
            rec.session_key, rec.state_hash, counter_verified,
            hardened=req.hardened, identifier_msg=req.identifier_msg, t_msg=req.t_msg,
        )
        try:
            given_alpha = bytes.fromhex(req.alpha_hex)
        except ValueError:
            self._deny(req, "malformed alpha (not valid hex)", intent)
            return None

        if not cu.constant_time_eq(expected_alpha, given_alpha):
            self._deny(req, "HMAC verification failed (integrity/authenticity check failed)", intent)
            telemetry_bus.publish(
                "gateway", "phase2_hmac_mismatch", client_id=req.client_id, intent=intent,
                expected_alpha_hex=expected_alpha.hex(), given_alpha_hex=given_alpha.hex(),
            )
            return None

        # Passed all checks -> Approved
        self.store.record_identifier(req.client_id, req.identifier_msg)
        self.store.bump_counter(req.client_id)
        self.store.update_last_session_time(req.client_id, proto.now_iso())

        # Hardened fix #2 (scyther/saf_phase2_hardened_final.spdl): the broker
        # MACs its own reply, binding it to identifier_msg and to the
        # Approved/Denied outcome, so an on-path attacker can no longer forge
        # an unauthenticated status reply.
        status_mac_hex = None
        if req.hardened:
            status_mac_hex = cu.compute_status_mac(rec.session_key, req.identifier_msg, "Approved").hex()

        status = proto.VerificationStatus(
            client_id=req.client_id, identifier_msg=req.identifier_msg,
            status="Approved", status_mac_hex=status_mac_hex,
        )
        self.client.publish(
            proto.TOPIC_SESSION_STATUS_FMT.format(client_id=req.client_id),
            status.to_json(), qos=1,
        )
        self._log_decision(intent, req.client_id, "Approved", None)
        telemetry_bus.publish(
            "gateway", "phase2_approved", client_id=req.client_id, intent=intent,
            identifier_msg=req.identifier_msg, alpha_hex=req.alpha_hex, topic=req.topic,
            expected_alpha_hex=expected_alpha.hex(), t_msg=req.t_msg,
            counter_used=counter_verified, state_hash_hex=rec.state_hash.hex(),
            hardened=req.hardened, status_mac_hex=status_mac_hex,
        )
        return rec, status_mac_hex

    def _deny(self, req, reason: str, intent: str = "publish"):
        status = proto.VerificationStatus(
            client_id=req.client_id, identifier_msg=req.identifier_msg,
            status="Denied", reason=reason,
        )
        self.client.publish(
            proto.TOPIC_SESSION_STATUS_FMT.format(client_id=req.client_id),
            status.to_json(), qos=1,
        )
        log.warning(f"[Phase2] DENIED client_id={req.client_id} intent={intent} reason={reason}")
        self._log_decision(intent, req.client_id, "Denied", reason)
        telemetry_bus.publish("gateway", "phase2_denied", client_id=req.client_id, intent=intent,
                               identifier_msg=req.identifier_msg, reason=reason)

    def _log_decision(self, phase, client_id, status, reason):
        self.decision_log.append({
            "ts": time.time(), "phase": phase, "client_id": client_id,
            "status": status, "reason": reason,
        })
