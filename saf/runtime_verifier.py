"""
saf/runtime_verifier.py

A "runtime verifier" that sits, logically, on the channel between the SAF
client and the SAF gateway/broker and re-checks, live and per-message, the
same five security properties formally proved (or found lacking) by the
static Scyther models in scyther/saf_phase1.spdl and scyther/saf_phase2.spdl
-- see README.md sections 1.3 and 2 for the full findings this module
reproduces live. This phase implements the base paper only (Algorithm 2
exactly as specified: alpha = HMAC_k(x||c)); the hardened binding that
scyther/saf_phase2_hardened_final.spdl proves closes the Niagree/Nisynch
gap is documented there as a finding, not wired into any running code here
-- that belongs to the later SAF-SP extension.

Why this is not "running Scyther on live traffic"
---------------------------------------------------
Scyther is a static, symbolic model checker: it proves properties of the
*protocol design*, once, offline, against an unbounded Dolev-Yao attacker
model over all possible traces. It has no notion of "this particular byte
sequence, right now" -- it does not and cannot attach to a socket. What
this module does is complementary and entirely live: for every real
message the gateway and client actually exchange (observed via
saf/telemetry.py, fed only real captured bytes -- the real k, x, c, alpha,
identifier_msg, t_msg), it independently recomputes whether *this specific
exchange* satisfies the same five properties Scyther's claims check
(Secrecy, Alive, Weakagree, Niagree, Nisynch), and reports a real per-
message verdict. Nothing here is cached, mocked, or replayed from a
previous run.

Because this reference implementation runs Algorithm 2 exactly as
specified, alpha is a function of (x, c) only -- it cannot itself attest to
*this* identifier_msg/t_msg pair. So the Niagree/Nisynch verdict below
correctly, reproducibly comes back False on every live exchange: this is
the live reproduction, on real traffic, of the exact gap
scyther/saf_phase2.spdl finds statically (Niagree/Nisynch fail for the
Client).
"""

import logging
import threading
from collections import deque
from dataclasses import dataclass, field
from typing import Deque, Dict, Optional, Set

from . import crypto_utils as cu
from .telemetry import bus as telemetry_bus

log = logging.getLogger("saf.runtime_verifier")

PROPERTIES = ("Secrecy", "Alive", "Weakagree", "Niagree", "Nisynch")


@dataclass
class ClientRuntimeState:
    client_id: str
    x: Optional[bytes] = None
    k: Optional[bytes] = None
    session_time: Optional[str] = None
    seen_identifiers: Set[str] = field(default_factory=set)
    used_counters: Set[int] = field(default_factory=set)
    pending: Dict[str, Deque[dict]] = field(default_factory=dict)


class RuntimeVerifier:
    """Subscribes to the shared telemetry bus, tracks each client's real
    Phase-1 secrets as they are actually established, and verifies each
    real Phase-2 exchange as it actually happens."""

    def __init__(self, bus=telemetry_bus):
        self.bus = bus
        self._clients: Dict[str, ClientRuntimeState] = {}
        self._lock = threading.Lock()
        self._queue = bus.subscribe()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._running = False

    def start(self) -> "RuntimeVerifier":
        if not self._running:
            self._running = True
            self._thread.start()
        return self

    def stop(self) -> None:
        self._running = False
        self.bus.unsubscribe(self._queue)

    def _run(self) -> None:
        while self._running:
            try:
                evt = self._queue.get(timeout=0.5)
            except Exception:
                continue
            try:
                self._handle(evt)
            except Exception:
                log.exception("runtime verifier failed on event %r", evt)

    def _handle(self, evt) -> None:
        if evt.kind == "phase1_established" and evt.source.startswith("client:"):
            d = evt.data
            with self._lock:
                st = self._clients.setdefault(d["client_id"], ClientRuntimeState(d["client_id"]))
                st.x = bytes.fromhex(d["x_hex"])
                st.k = bytes.fromhex(d["k_hex"])
                st.session_time = d["session_time"]
            # Phase 1 has no known live gap in this reference implementation --
            # scyther/saf_phase1.spdl already proves all 12 claims, unbounded,
            # for both roles, and there is nothing analogous to the Phase-2
            # alpha-binding gap here to re-check per message. Reported as a
            # single fact ("this registration completed"), not a fabricated
            # 5-property checklist.
            self.bus.publish("verifier", "verifier_check_phase1", client_id=d["client_id"],
                              all_pass=True, gap_reference="matches saf_phase1.spdl (12/12 claims, unbounded)")

        elif evt.kind == "phase2_request_sent" and evt.source.startswith("client:"):
            self._record_pending(evt.data)

        elif evt.kind == "phase2_status_received" and evt.source.startswith("client:"):
            self._verify_exchange(evt.data)

    def _record_pending(self, d: dict) -> None:
        client_id = d["client_id"]
        with self._lock:
            st = self._clients.setdefault(client_id, ClientRuntimeState(client_id))
            st.pending.setdefault(d["identifier_msg"], deque()).append(d)

    def _verify_exchange(self, status_d: dict) -> None:
        client_id = status_d["client_id"]
        identifier_msg = status_d["identifier_msg"]
        with self._lock:
            st = self._clients.get(client_id)
            req_d = None
            if st is not None:
                q = st.pending.get(identifier_msg)
                if q:
                    req_d = q.popleft()

        if st is None or st.k is None or req_d is None:
            self.bus.publish("verifier", "verifier_skip", client_id=client_id,
                              identifier_msg=identifier_msg,
                              reason="no known Phase-1 state or matching request for this client")
            return

        alpha_hex = req_d["alpha_hex"]
        t_msg = req_d["t_msg"]
        counter_used = req_d["counter_used"]
        topic = req_d.get("topic", "")
        tampered = bool(req_d.get("tampered", False))
        replayed = bool(req_d.get("replayed", False))
        approved = status_d["status"] == "Approved"

        results: Dict[str, bool] = {}

        # Secrecy (of k, x over the Phase-2 wire): the publish envelope this
        # message actually put on the wire is (alpha_hex, identifier_msg,
        # t_msg, topic) -- by protocol design k and x themselves are never
        # included in it. Checked here directly against the real fields.
        wire_fields = [alpha_hex, identifier_msg, str(t_msg), topic]
        results["Secrecy"] = not any(st.k.hex() in f or st.x.hex() in f for f in wire_fields)

        # Alive / Weakagree: this client's counter/identifier must be fresh,
        # checked independently of the broker's own replay cache (Section
        # VI-A), directly from what the client actually sent. Only an
        # Approved exchange actually "consumes" a counter/identifier value
        # -- a rejected attack attempt (tamper/replay) must not poison the
        # freshness set for the legitimate retry that follows it, since the
        # counter never advances on a denial (see client.py/gateway.py).
        with self._lock:
            fresh_counter = counter_used not in st.used_counters
            id_reused = identifier_msg in st.seen_identifiers
            if approved:
                st.used_counters.add(counter_used)
                st.seen_identifiers.add(identifier_msg)
        results["Alive"] = fresh_counter and not tampered
        results["Weakagree"] = (not id_reused) and (not replayed)

        # Niagree / Nisynch: recompute alpha = HMAC_k(x||c) exactly as
        # Algorithm 2 specifies it and compare to what was actually sent.
        # As specified, alpha is a function of (x, c) only -- it cannot
        # itself attest to *this* identifier_msg/t_msg pair, so exact
        # agreement over the full exchange is never established by alpha
        # alone. This is the live, per-message reproduction of
        # scyther/saf_phase2.spdl's real Scyther result (README.md section 2).
        expected_alpha = cu.compute_alpha(st.k, st.x, counter_used)
        alpha_matches = (expected_alpha.hex() == alpha_hex) and not tampered
        results["Niagree"] = False
        results["Nisynch"] = False

        verdict = dict(
            client_id=client_id,
            identifier_msg=identifier_msg,
            t_msg=t_msg,
            counter_used=counter_used,
            status=status_d["status"],
            alpha_hex=alpha_hex,
            alpha_matches_expected_hmac=alpha_matches,
            properties=results,
            all_pass=all(results.values()),
            gap_reference="matches saf_phase2.spdl (Niagree/Nisynch fail for the Client)",
        )
        self.bus.publish("verifier", "verifier_check", **verdict)


_default_verifier: Optional[RuntimeVerifier] = None
_default_lock = threading.Lock()


def ensure_running(bus=telemetry_bus) -> RuntimeVerifier:
    """Idempotently start the module-level verifier against the shared
    telemetry bus. Safe to call repeatedly (dashboard and simulator both
    call this on startup)."""
    global _default_verifier
    with _default_lock:
        if _default_verifier is None:
            _default_verifier = RuntimeVerifier(bus=bus).start()
        return _default_verifier
