"""
saf/telemetry.py

In-process publish/subscribe event bus used to give external observers
(the live dashboard, the network simulator's metrics collector) real-time
visibility into what the protocol code is actually doing, as it happens.

This module carries no protocol logic of its own and fabricates no data:
every event it distributes is handed to it, verbatim and synchronously, by
the code performing the real cryptographic/networking work (saf/gateway.py,
saf/client.py, saf/runtime_verifier.py). A subscriber sees the same values
-- the same hex strings, counters, timestamps -- that the protocol actually
computed and put on the wire; nothing here is mocked or replayed.
"""

import itertools
import queue
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class Event:
    seq: int
    ts: float
    source: str   # "client:<client_id>" | "gateway" | "verifier"
    kind: str     # e.g. "phase1_request", "phase2_denied", "verifier_check"
    data: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {"seq": self.seq, "ts": self.ts, "source": self.source,
                "kind": self.kind, "data": self.data}


class EventBus:
    """Thread-safe fan-out pub/sub. Each subscriber gets its own queue and
    receives every event published after it subscribed; `recent()` lets a
    late subscriber (e.g. a dashboard tab opened mid-run) backfill from the
    bounded in-memory history."""

    def __init__(self, history_limit: int = 4000):
        self._lock = threading.Lock()
        self._subscribers: List["queue.Queue[Event]"] = []
        self._seq = itertools.count(1)
        self._history: List[Event] = []
        self._history_limit = history_limit

    def publish(self, source: str, kind: str, **data: Any) -> Event:
        evt = Event(seq=next(self._seq), ts=time.time(), source=source, kind=kind, data=data)
        with self._lock:
            self._history.append(evt)
            if len(self._history) > self._history_limit:
                del self._history[: len(self._history) - self._history_limit]
            subs = list(self._subscribers)
        for q in subs:
            q.put(evt)
        return evt

    def subscribe(self) -> "queue.Queue[Event]":
        q: "queue.Queue[Event]" = queue.Queue()
        with self._lock:
            self._subscribers.append(q)
        return q

    def unsubscribe(self, q: "queue.Queue[Event]") -> None:
        with self._lock:
            if q in self._subscribers:
                self._subscribers.remove(q)

    def recent(self, n: int = 200) -> List[Event]:
        with self._lock:
            return list(self._history[-n:])

    def clear(self) -> None:
        with self._lock:
            self._history.clear()


# Module-level default bus shared by gateway/client/runtime_verifier and any
# consumer (dashboard, simulator). A single process (one dashboard run, one
# simulator run) has exactly one bus, so every component's events interleave
# on it in true chronological order.
bus = EventBus()
