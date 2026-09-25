"""
saf/protocol.py

Message envelopes for SAF Phase 1 (Pre-Session) and Phase 2 (In-Session),
serialized as JSON and carried over dedicated MQTT control topics by the
SAF gateway (saf/gateway.py). Field names mirror Table V and Algorithms 1-2.

Implementation note on an ambiguity in the base paper
-------------------------------------------------------
Algorithm 1 has the broker compute x = h(client_state) (Step 4) and send
y = x || k || c to the client (Step 6); the client then stores x, k, c
(Step 7) -- i.e. the client never receives or stores the *raw*
client_state, only its hash x.

Algorithm 2, Step 4 then has the client compute
    alpha = HMAC_k(client_state || c)
which is only literally computable if the client possesses the raw
client_state. The paper does not reconcile this.

We resolve the ambiguity by having the client use the one value it
actually possesses -- x = h(client_state) -- in place of raw client_state
in the Phase-2 HMAC, i.e.:
    alpha = HMAC_k(x || c)
The broker, which does possess (or can recompute) client_state and hence
x, performs the identical computation for verification. This preserves
the protocol's security property (HMAC keyed on a secret the client holds,
binding it to counter c) while being concretely implementable. This
ambiguity is worth flagging explicitly in the SAF-SP writeup as a
clarification made when reproducing the base protocol.
"""

import json
import time
from dataclasses import dataclass, asdict
from typing import Optional


# ---------------------------------------------------------------------------
# Phase 1: Pre-Session  (Algorithm 1)
# ---------------------------------------------------------------------------

@dataclass
class PreSessionRequest:
    """Algorithm 1, Step 1."""
    client_id: str
    request_time: str  # ISO8601, "Level 1 information"

    def to_json(self) -> str:
        return json.dumps(asdict(self))

    @staticmethod
    def from_json(payload: str) -> "PreSessionRequest":
        d = json.loads(payload)
        return PreSessionRequest(**d)


@dataclass
class PreSessionResponse:
    """Algorithm 1, Step 6: y = x || k || c, sent to client.
    Fields are hex-encoded for JSON transport."""
    client_id: str
    x_hex: str      # h(client_state), hex
    k_hex: str       # session key, hex  (Sec V-A: 32 bytes)
    c: int           # counter (starts at 0)
    session_time: str
    estimated_duration: str
    status: str = "ESTABLISHED"

    def to_json(self) -> str:
        return json.dumps(asdict(self))

    @staticmethod
    def from_json(payload: str) -> "PreSessionResponse":
        d = json.loads(payload)
        return PreSessionResponse(**d)


@dataclass
class PreSessionAck:
    """Algorithm 1, Steps 7-8."""
    client_id: str
    ack: str = "Acknowledged"

    def to_json(self) -> str:
        return json.dumps(asdict(self))

    @staticmethod
    def from_json(payload: str) -> "PreSessionAck":
        d = json.loads(payload)
        return PreSessionAck(**d)


# ---------------------------------------------------------------------------
# Phase 2: In-Session  (Algorithm 2)
# ---------------------------------------------------------------------------

@dataclass
class PublishRequest:
    """Algorithm 2, Steps 1-4: client sends alpha (HMAC), t_msg,
    identifier_msg, plus the Level-1 info and the actual MQTT
    topic/payload it wants relayed once authenticated."""
    client_id: str
    alpha_hex: str          # HMAC_k(x || c), hex -- or the hardened binding, see `hardened`
    t_msg: float            # timestamp
    identifier_msg: str     # unique per-message id
    level1_info: str        # last session's timestamp (or pre-session time if first)
    topic: str               # real application topic the client wants to publish to
    payload_b64: str         # base64 payload (may be ASCON-encrypted, see ascon_enc.py)
    encrypted: bool = False  # whether Step 7 (ASCON authenticate-then-encrypt) was applied
    hardened: bool = False   # alpha = HMAC_k(x||c||identifier_msg||t_msg), per
                              # scyther/saf_phase2_hardened_final.spdl, instead of the
                              # as-specified HMAC_k(x||c) (scyther/saf_phase2.spdl)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

    @staticmethod
    def from_json(payload: str) -> "PublishRequest":
        d = json.loads(payload)
        return PublishRequest(**d)


@dataclass
class SubscribeRequest:
    """Algorithm 2, Steps 1-4, for the subscribe intent: Section V-A
    Requirement 1 ("Both MQTT publishing clients and MQTT subscribing
    clients must establish a client state with the MQTT broker") and
    Algorithm 2 Step 2 ("The MQTT client initiates a session to either
    publish data or subscribe to a topic") specify the *same* session-
    authentication challenge gating either action -- this mirrors
    PublishRequest exactly, minus the fields that only make sense for an
    outgoing payload (payload_b64/encrypted)."""
    client_id: str
    alpha_hex: str
    t_msg: float
    identifier_msg: str
    level1_info: str
    topic: str               # the topic the client wants to subscribe to
    hardened: bool = False

    def to_json(self) -> str:
        return json.dumps(asdict(self))

    @staticmethod
    def from_json(payload: str) -> "SubscribeRequest":
        d = json.loads(payload)
        return SubscribeRequest(**d)


@dataclass
class VerificationStatus:
    """Algorithm 2, Step 6."""
    client_id: str
    identifier_msg: str
    status: str          # "Approved" | "Denied"
    reason: Optional[str] = None
    status_mac_hex: Optional[str] = None  # HMAC_k(identifier_msg||status); only set when the
                                            # request was hardened (closes the unauthenticated-
                                            # reply gap, scyther/saf_phase2_hardened_final.spdl)

    def to_json(self) -> str:
        return json.dumps(asdict(self))

    @staticmethod
    def from_json(payload: str) -> "VerificationStatus":
        d = json.loads(payload)
        return VerificationStatus(**d)


# ---------------------------------------------------------------------------
# Topic conventions used by the SAF gateway (saf/gateway.py)
# ---------------------------------------------------------------------------

TOPIC_PRESESSION_REQUEST = "saf/presession/request"
TOPIC_PRESESSION_RESPONSE_FMT = "saf/presession/response/{client_id}"
TOPIC_SESSION_PUBLISH = "saf/session/publish"
TOPIC_SESSION_SUBSCRIBE = "saf/session/subscribe"
TOPIC_SESSION_STATUS_FMT = "saf/session/status/{client_id}"
APP_TOPIC_PREFIX = "app/"  # authenticated payloads are relayed under app/<topic>


def now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
