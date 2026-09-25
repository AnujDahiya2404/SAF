"""
simulator/netsim.py

A network simulator for SAF: many simulated clients, real network
conditions, real protocol code.

How it works
------------
simpy.rt.RealtimeEnvironment paces *when* each simulated client acts (its
Phase-1 registration, then a stream of Phase-2 publishes at a random
inter-arrival time), applying a per-link latency/jitter/loss profile before
each action. What actually happens at that moment is never faked: it is a
real call into saf.client.SAFClient, which does real HMAC/ASCON
cryptography and a real MQTT round trip against a real Mosquitto broker and
the real saf.gateway.SAFGateway. Those real, potentially slow network calls
are dispatched to a thread pool (not run inline on SimPy's single-threaded
clock) so that many clients' real round trips genuinely overlap, the way
they would on a real congested network, rather than being serialized by the
simulator itself.

Why SimPy, not Mininet/NS-3/OMNeT++
------------------------------------
See README.md. In short: Mininet needs real Linux network namespaces
(unavailable on macOS without standing up a Docker/VM layer); NS-3 and
OMNeT++ have no native MQTT support and would mean reimplementing the
already-formally-verified protocol logic in C++, throwing away the exact
code this dissertation verified. SimPy is a legitimate, widely used Python
discrete-event simulation library; run here in real-time mode so every
event it schedules drives the real, unmodified saf/ implementation.

Output
------
Every run writes two files to --out-dir (default simulator/results/<ts>/):
  events.json   -- the complete, real telemetry stream captured during the run
  metrics.json  -- derived summary statistics computed from those real events
                    (registration outcomes, per-message latency, approval/
                    denial counts and reasons, rate-limiter triggers)
simulator/report.py turns these into figures.
"""

import argparse
import concurrent.futures
import dataclasses
import json
import logging
import random
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Dict, List, Optional

import simpy
import simpy.rt

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

from saf.client import SAFClient  # noqa: E402
from saf.gateway import SAFGateway  # noqa: E402
from saf.state_store import SAFStateStore  # noqa: E402
from saf.telemetry import bus, Event  # noqa: E402
from saf import runtime_verifier  # noqa: E402

log = logging.getLogger("saf.netsim")
logging.basicConfig(level=logging.INFO, format="[NETSIM] %(message)s")
logging.getLogger("saf.gateway").setLevel(logging.WARNING)

BROKER_HOST = "127.0.0.1"
BROKER_PORT = 1883
MOSQUITTO_CONF = REPO_ROOT / "mosquitto_conf" / "mosquitto.conf"


@dataclasses.dataclass
class LinkProfile:
    name: str
    latency_ms_mean: float
    latency_ms_jitter: float
    loss_prob: float


LINK_PROFILES: Dict[str, LinkProfile] = {
    "lan":       LinkProfile("lan", 5, 2, 0.00),
    "wifi":      LinkProfile("wifi", 25, 15, 0.01),
    "wan":       LinkProfile("wan", 80, 40, 0.03),
    "lossy_iot": LinkProfile("lossy_iot", 120, 80, 0.08),
}


def sample_latency_seconds(profile: LinkProfile, rng: random.Random) -> float:
    ms = max(0.0, rng.gauss(profile.latency_ms_mean, profile.latency_ms_jitter))
    return ms / 1000.0


def port_open(host: str, port: int, timeout: float = 0.3) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        try:
            return s.connect_ex((host, port)) == 0
        except OSError:
            return False


def ensure_broker() -> None:
    if port_open(BROKER_HOST, BROKER_PORT):
        log.info(f"broker already listening on {BROKER_HOST}:{BROKER_PORT}, reusing it")
        return
    log.info("no broker detected -- starting mosquitto from mosquitto_conf/mosquitto.conf")
    try:
        subprocess.Popen(["mosquitto", "-c", str(MOSQUITTO_CONF)],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except FileNotFoundError:
        raise RuntimeError("'mosquitto' not found on PATH -- install it (macOS: brew install "
                            "mosquitto) or start it yourself first")
    for _ in range(30):
        if port_open(BROKER_HOST, BROKER_PORT):
            return
        time.sleep(0.2)
    raise RuntimeError("mosquitto did not come up in time")


class EventRecorder:
    """Subscribes to the shared telemetry bus for the lifetime of a
    simulation run and keeps every real event, so metrics can be derived
    after the fact without touching the live protocol code."""

    def __init__(self):
        self.events: List[dict] = []
        self._lock = threading.Lock()
        self._queue = bus.subscribe()
        self._running = False
        self._thread = threading.Thread(target=self._run, daemon=True)

    def start(self):
        self._running = True
        self._thread.start()

    def stop(self):
        self._running = False
        bus.unsubscribe(self._queue)

    def _run(self):
        while self._running:
            try:
                evt: Event = self._queue.get(timeout=0.5)
            except Exception:
                continue
            with self._lock:
                self.events.append(evt.to_dict())

    def snapshot(self) -> List[dict]:
        with self._lock:
            return list(self.events)


class Simulation:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.rng = random.Random(args.seed)
        n_workers = args.n_clients + args.n_attackers + 4
        self.executor = concurrent.futures.ThreadPoolExecutor(max_workers=n_workers)
        self.store = SAFStateStore(
            max_clients=args.max_clients,
            registration_cooldown_seconds=args.registration_cooldown,
        )
        self.gateway = SAFGateway(host=BROKER_HOST, port=BROKER_PORT, store=self.store)
        self.env = simpy.rt.RealtimeEnvironment(factor=args.time_scale, strict=False)
        self.clients: List[SAFClient] = []
        self.recorder = EventRecorder()

    # ------------------------------------------------------------------ #

    def _await_future(self, env, fut: concurrent.futures.Future):
        """Bridge a real (blocking) network call, running on a worker
        thread, back into SimPy's generator protocol without blocking the
        simulator's single-threaded clock -- other simulated clients keep
        advancing while this one's real round trip is in flight."""
        while not fut.done():
            yield env.timeout(0.02)
        return fut.result()

    def _client_process(self, env, client_id: str, profile: LinkProfile, is_attacker: bool):
        client = SAFClient(client_id, host=BROKER_HOST, port=BROKER_PORT)
        self.clients.append(client)

        def do_register():
            client.connect()
            return client.register(timeout=5.0)

        yield env.timeout(sample_latency_seconds(profile, self.rng))
        fut = self.executor.submit(do_register)
        ok = yield env.process(self._await_future(env, fut))
        if not ok:
            return  # registration denied (rate limit) or timed out -- client stops here

        mean_interval = self.args.attacker_mean_interval if is_attacker else self.args.mean_interval
        end_time = env.now + self.args.duration
        last_approved_id: Optional[str] = None

        while env.now < end_time:
            yield env.timeout(self.rng.expovariate(1.0 / mean_interval))

            if self.rng.random() < profile.loss_prob:
                continue  # real network loss: this message is genuinely never sent

            yield env.timeout(sample_latency_seconds(profile, self.rng))

            tamper = False
            replay_id = None
            if is_attacker:
                roll = self.rng.random()
                if roll < self.args.attacker_tamper_prob:
                    tamper = True
                elif roll < self.args.attacker_tamper_prob + self.args.attacker_replay_prob and last_approved_id:
                    replay_id = last_approved_id

            encrypt = (not is_attacker) and (self.rng.random() < self.args.encrypt_prob)

            def do_publish(_client=client, _tamper=tamper, _replay=replay_id, _encrypt=encrypt):
                return _client.publish(
                    f"sensors/{client_id}", b"reading=live",
                    encrypt=_encrypt, tamper_alpha=_tamper, replay_identifier=_replay,
                )

            fut = self.executor.submit(do_publish)
            status = yield env.process(self._await_future(env, fut))
            if status is not None and status.status == "Approved":
                last_approved_id = status.identifier_msg

    # ------------------------------------------------------------------ #

    def run(self) -> Path:
        ensure_broker()
        runtime_verifier.ensure_running(bus=bus)
        self.recorder.start()
        self.gateway.start()
        time.sleep(0.5)
        bus.publish("simulator", "run_started",
                    n_clients=self.args.n_clients, n_attackers=self.args.n_attackers,
                    duration=self.args.duration, max_clients=self.args.max_clients,
                    time_scale=self.args.time_scale, seed=self.args.seed)

        profile_names = list(LINK_PROFILES)
        for i in range(self.args.n_clients):
            profile = LINK_PROFILES[self.rng.choice(profile_names)]
            self.env.process(self._client_process(self.env, f"LegitClient-{i:03d}", profile, False))
        for i in range(self.args.n_attackers):
            self.env.process(self._client_process(self.env, f"AttackerClient-{i:03d}", LINK_PROFILES["wan"], True))

        log.info(f"running: {self.args.n_clients} legitimate + {self.args.n_attackers} attacker clients, "
                 f"{self.args.duration}s simulated @ time_scale={self.args.time_scale}, "
                 f"state store max_clients={self.args.max_clients}")
        self.env.run(until=self.args.duration + 5)
        time.sleep(1.5)  # drain in-flight telemetry before stopping

        bus.publish("simulator", "run_finished")
        time.sleep(0.3)

        out_dir = Path(self.args.out_dir) if self.args.out_dir else (
            REPO_ROOT / "simulator" / "results" / time.strftime("%Y%m%d-%H%M%S")
        )
        out_dir.mkdir(parents=True, exist_ok=True)
        events = self.recorder.snapshot()
        (out_dir / "events.json").write_text(json.dumps(events, indent=2))
        metrics = compute_metrics(events, self.args)
        (out_dir / "metrics.json").write_text(json.dumps(metrics, indent=2))
        log.info(f"wrote {len(events)} real events and metrics to {out_dir}")

        self._shutdown()
        return out_dir

    def _shutdown(self):
        self.recorder.stop()
        for c in self.clients:
            try:
                c.disconnect()
            except Exception:
                pass
        self.gateway.stop()
        self.executor.shutdown(wait=True)


def compute_metrics(events: List[dict], args: argparse.Namespace) -> dict:
    """Derive summary statistics purely from the real captured event
    stream -- no value here is assumed or fabricated."""
    phase1_established = [e for e in events if e["kind"] == "phase1_established" and e["source"].startswith("client:")]
    phase1_denied = [e for e in events if e["kind"] == "phase1_denied"]
    phase2_status = [e for e in events if e["kind"] == "phase2_status_received" and e["source"].startswith("client:")]

    # Correlate each status_received back to the *specific* request_sent that
    # produced it, per (client, identifier_msg), FIFO -- a plain
    # identifier_msg-keyed lookup breaks for replay attacks, which by
    # design reuse the same identifier_msg more than once.
    from collections import deque
    pending: Dict[tuple, deque] = {}
    for e in events:
        if e["kind"] == "phase2_request_sent" and e["source"].startswith("client:"):
            key = (e["data"]["client_id"], e["data"]["identifier_msg"])
            pending.setdefault(key, deque()).append(e["ts"])

    latencies_ms = []
    approved = 0
    denied_reasons: Dict[str, int] = {}
    for e in phase2_status:
        key = (e["data"]["client_id"], e["data"]["identifier_msg"])
        q = pending.get(key)
        if q:
            sent_ts = q.popleft()
            latencies_ms.append((e["ts"] - sent_ts) * 1000.0)
        if e["data"]["status"] == "Approved":
            approved += 1
        else:
            reason = e["data"].get("reason") or "unknown"
            denied_reasons[reason] = denied_reasons.get(reason, 0) + 1

    verifier_checks = [e["data"] for e in events if e["kind"] == "verifier_check"]
    niagree_gap_live_count = sum(1 for v in verifier_checks if not v["properties"]["Niagree"])

    latencies_ms.sort()

    def pct(p):
        if not latencies_ms:
            return None
        idx = min(len(latencies_ms) - 1, int(len(latencies_ms) * p))
        return round(latencies_ms[idx], 2)

    return {
        "config": vars(args),
        "clients_attempted": args.n_clients + args.n_attackers,
        "phase1_established": len(phase1_established),
        "phase1_denied": len(phase1_denied),
        "phase1_denied_reasons": _count_reasons(phase1_denied),
        "phase2_messages_total": len(phase2_status),
        "phase2_approved": approved,
        "phase2_denied": len(phase2_status) - approved,
        "phase2_denied_reasons": denied_reasons,
        "latency_ms": {
            "n": len(latencies_ms), "min": round(min(latencies_ms), 2) if latencies_ms else None,
            "p50": pct(0.50), "p90": pct(0.90), "p99": pct(0.99),
            "max": round(max(latencies_ms), 2) if latencies_ms else None,
        },
        "runtime_verifier_checks": len(verifier_checks),
        "runtime_verifier_niagree_gap_reproduced_live": niagree_gap_live_count,
    }


def _count_reasons(events: List[dict]) -> Dict[str, int]:
    out: Dict[str, int] = {}
    for e in events:
        r = e["data"].get("reason") or "unknown"
        out[r] = out.get(r, 0) + 1
    return out


def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--n-clients", type=int, default=40, help="number of legitimate simulated clients")
    p.add_argument("--n-attackers", type=int, default=10, help="number of attacker-behavior simulated clients")
    p.add_argument("--max-clients", type=int, default=35,
                    help="broker-side registration cap (Section V-B) -- set below n-clients+n-attackers "
                         "to observe the real rate-limiter denying late registrations")
    p.add_argument("--registration-cooldown", type=float, default=0.0,
                    help="seconds to block ALL new registrations after each one (0 = disabled)")
    p.add_argument("--duration", type=float, default=20.0, help="simulated seconds of steady-state traffic per client")
    p.add_argument("--mean-interval", type=float, default=2.0, help="mean seconds between publishes, legitimate clients")
    p.add_argument("--attacker-mean-interval", type=float, default=0.5, help="mean seconds between publishes, attackers")
    p.add_argument("--attacker-tamper-prob", type=float, default=0.5, help="probability an attacker publish is HMAC-tampered")
    p.add_argument("--attacker-replay-prob", type=float, default=0.4, help="probability an attacker publish replays its last identifier_msg")
    p.add_argument("--encrypt-prob", type=float, default=0.3, help="probability a legitimate publish uses ASCON encryption")
    p.add_argument("--time-scale", type=float, default=1.0, help="SimPy RealtimeEnvironment factor (lower = faster than real time)")
    p.add_argument("--seed", type=int, default=42)
    p.add_argument("--out-dir", type=str, default=None)
    return p


def main():
    args = build_arg_parser().parse_args()
    sim = Simulation(args)
    out_dir = sim.run()
    metrics = json.loads((out_dir / "metrics.json").read_text())
    log.info(json.dumps(metrics, indent=2))
    print(f"\nResults written to {out_dir}")


if __name__ == "__main__":
    main()
