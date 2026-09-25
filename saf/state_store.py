"""
saf/state_store.py

Broker-side bookkeeping for SAF:
  1. The client-state table (Algorithm 1): per-client hashed state, session
     key k, and counter c.
  2. The identifier_msg replay/duplicate cache (Section VI-A / Algorithm 2,
     Step 5) used to detect replayed or duplicated messages.
  3. The rate-limiting / DoS-restriction policies described in Section V-B
     ("These policies also constitute rate limiting") and used again as the
     SAF-side response hook for the LLM-based IDS (Section V-B, Fig. 4):
        - limit number of MQTT publishing/subscribing clients
        - limit number of sessions per client per day
        - block new registrations for a defined time window
        - restrict each client_id (MAC) to a single simultaneously-active
          entity (anti-spoofing, Section VI-B)
"""

import threading
import time
from dataclasses import dataclass, field
from typing import Dict, Optional, Set, Deque
from collections import deque


@dataclass
class ClientRecord:
    client_id: str
    state_hash: bytes            # x = h(client_state)          (Algorithm 1, Step 4)
    session_key: bytes           # k                              (Algorithm 1, Step 5)
    counter: int                 # c                              (Algorithm 1, Step 5)
    session_time: str            # session_time in client_state   (Algorithm 1, Step 3)
    estimated_duration: str
    registered_at: float = field(default_factory=time.time)
    last_session_time: Optional[str] = None   # Level-1 info bookkeeping (Sec V-A Phase 2, step 1)
    sessions_today: int = 0
    day_bucket: str = ""         # yyyy-mm-dd bucket used for the daily session cap
    active_connection: bool = False           # single-entity-per-client_id enforcement


class SAFStateStore:
    """Thread-safe broker-side state, mirroring what the paper calls the
    broker's client-state records (Section V-A, bullet list before V-B)."""

    def __init__(
        self,
        max_clients: int = 50,
        max_sessions_per_day: int = 200,
        replay_window_seconds: float = 30.0,
        identifier_cache_size: int = 5000,
        registration_cooldown_seconds: float = 0.0,
    ):
        self._lock = threading.RLock()
        self.clients: Dict[str, ClientRecord] = {}
        self.max_clients = max_clients
        self.max_sessions_per_day = max_sessions_per_day
        self.replay_window_seconds = replay_window_seconds
        self.identifier_cache_size = identifier_cache_size
        self.registration_cooldown_seconds = registration_cooldown_seconds
        self._registration_blocked_until: float = 0.0

        # per-client seen identifier_msg values within the current session,
        # used to reject duplicates/replays (Algorithm 2, Step 5 notes).
        self._seen_identifiers: Dict[str, Set[str]] = {}
        self._identifier_order: Dict[str, Deque[str]] = {}

    # ---------------- registration / DoS restrictions (Sec V-B) ----------------

    def registration_allowed(self) -> bool:
        with self._lock:
            if time.time() < self._registration_blocked_until:
                return False
            if len(self.clients) >= self.max_clients:
                return False
            return True

    def block_new_registrations(self, seconds: float) -> None:
        """'No new registration of MQTT client or broker is allowed for a
        defined time' (Section V-B)."""
        with self._lock:
            self._registration_blocked_until = time.time() + seconds

    def register_client(
        self, client_id: str, state_hash: bytes, session_key: bytes,
        counter: int, session_time: str, estimated_duration: str,
    ) -> ClientRecord:
        with self._lock:
            rec = ClientRecord(
                client_id=client_id,
                state_hash=state_hash,
                session_key=session_key,
                counter=counter,
                session_time=session_time,
                estimated_duration=estimated_duration,
            )
            self.clients[client_id] = rec
            self._seen_identifiers[client_id] = set()
            self._identifier_order[client_id] = deque()
            if self.registration_cooldown_seconds > 0:
                self.block_new_registrations(self.registration_cooldown_seconds)
            return rec

    def get_client(self, client_id: str) -> Optional[ClientRecord]:
        with self._lock:
            return self.clients.get(client_id)

    def client_exists(self, client_id: str) -> bool:
        with self._lock:
            return client_id in self.clients

    # ---------------- single-entity-per-client_id (anti MAC-spoofing) ----------------

    def try_acquire_single_entity(self, client_id: str) -> bool:
        """'Each MAC address is restricted to a single entity if there is
        simultaneous communication from the same' (Section V-B / VI-B)."""
        with self._lock:
            rec = self.clients.get(client_id)
            if rec is None:
                return False
            if rec.active_connection:
                return False
            rec.active_connection = True
            return True

    def release_single_entity(self, client_id: str) -> None:
        with self._lock:
            rec = self.clients.get(client_id)
            if rec is not None:
                rec.active_connection = False

    # ---------------- daily session cap ----------------

    def check_and_increment_daily_sessions(self, client_id: str) -> bool:
        today = time.strftime("%Y-%m-%d", time.gmtime())
        with self._lock:
            rec = self.clients.get(client_id)
            if rec is None:
                return False
            if rec.day_bucket != today:
                rec.day_bucket = today
                rec.sessions_today = 0
            if rec.sessions_today >= self.max_sessions_per_day:
                return False
            rec.sessions_today += 1
            return True

    # ---------------- session counter / Level-1 info ----------------

    def bump_counter(self, client_id: str) -> Optional[int]:
        with self._lock:
            rec = self.clients.get(client_id)
            if rec is None:
                return None
            rec.counter += 1
            return rec.counter

    def update_last_session_time(self, client_id: str, session_time: str) -> None:
        with self._lock:
            rec = self.clients.get(client_id)
            if rec is not None:
                rec.last_session_time = session_time

    # ---------------- identifier_msg replay / duplication detection ----------------

    def is_duplicate_identifier(self, client_id: str, identifier_msg: str) -> bool:
        """Algorithm 2 / Section VI-A: 'if a message with the same identifier
        is received more than once, SAF recognizes it as a duplicate.'"""
        with self._lock:
            seen = self._seen_identifiers.setdefault(client_id, set())
            return identifier_msg in seen

    def record_identifier(self, client_id: str, identifier_msg: str) -> None:
        with self._lock:
            seen = self._seen_identifiers.setdefault(client_id, set())
            order = self._identifier_order.setdefault(client_id, deque())
            seen.add(identifier_msg)
            order.append(identifier_msg)
            while len(order) > self.identifier_cache_size:
                old = order.popleft()
                seen.discard(old)

    def is_fresh_timestamp(self, t_msg: float) -> bool:
        """The broker checks t_msg falls within an acceptable time window
        (Algorithm 2 note, Section VI-A) to prevent replay of a captured
        message at a later time."""
        return abs(time.time() - t_msg) <= self.replay_window_seconds
