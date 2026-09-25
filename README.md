# SAF (Stateful Authentication Framework) — Base Reference Implementation

Reproduction of the protocol in:

> Jamil, N., Shariq, M., Shah, S.S.H., Mehdy, H.S., Alyasseri, Z.A.A., Hosseini, E.,
> Berini, A.D.E., & Zain, Z.M. "A Novel Stateful Authentication Framework Approach
> with LLM-based IDS for MQTT Security." *IEEE Internet of Things Journal*, 2026 (in press).
> DOI: 10.1109/JIOT.2025.3646115

Built as the foundation for the **SAF-SP** (Sequence-Aware and Privacy-Preserving
Stateful Authentication Framework) extension.

## 1. What's implemented

### 1.1 Real MQTT deployment (`saf/`)
- A local **Mosquitto** broker (real, unmodified, off-the-shelf).
- `SAFGateway` (`saf/gateway.py`): an MQTT client of its own that plays the "MQTT
  Broker" role from Algorithms 1 & 2 — mediates all traffic, since Mosquitto has no
  native support for an application-level protocol like SAF (a C plugin would be
  needed to hook into Mosquitto internals; a gateway is the practical alternative).
- `SAFClient` (`saf/client.py`): plays the "MQTT Client" role — Phase 1 registration,
  then Phase 2 per-publish authentication.
- `saf/crypto_utils.py`: SHA-256 hashing, HMAC-SHA256, 32-byte session keys, 16-bit
  counters — all per Table V.
- `saf/ascon_enc.py`: ASCON-128 authenticate-then-encrypt for Algorithm 2 Step 7
  ("high protection" data), using the `ascon` PyPI package.
- `saf/state_store.py`: broker-side client-state table, `identifier_msg` replay/
  duplicate cache, and the Section V-B rate-limiting policies (max clients, daily
  session cap, single-entity-per-`client_id`, registration cooldown).

### 1.2 Tests (`tests/`)
| Script | What it proves | Result |
|---|---|---|
| `demo_normal_flow.py` | Full Phase 1 + Phase 2 happy path, plaintext and ASCON-encrypted, over a real broker | **PASS** |
| `attack_replay.py` | A replayed `identifier_msg` is denied | **PASS** |
| `attack_tamper.py` | A tampered HMAC is denied; an unregistered `client_id` is denied outright | **PASS** |

Run them with the Mosquitto broker already running on `127.0.0.1:1883`:
```bash
python3 tests/demo_normal_flow.py
python3 tests/attack_replay.py
python3 tests/attack_tamper.py
```

### 1.3 Formal verification (`scyther/`)
Built `scyther-linux` from source (official repo: github.com/cascremers/scyther)
since it isn't packaged for apt/pip. Binary at `scyther/bin/scyther-linux`.

| Model | Claims | Result |
|---|---|---|
| `saf_phase1.spdl` — Pre-Session (Algorithm 1) | Secret ×2, Niagree, Nisynch, Alive, Weakagree, per role | **All 12 pass, unbounded** |
| `saf_phase2.spdl` — In-Session, **as literally specified** (Algorithm 2) | same 5 properties × 2 roles | **Secret passes; Niagree/Nisynch/Alive/Weakagree fail for the Client** |
| `saf_phase2_hardened_final.spdl` — In-Session with proposed fix | same | **All 10 pass, unbounded ("proof of correctness")** |

Run any of them:
```bash
./scyther/bin/scyther-linux --unbounded scyther/saf_phase1.spdl     # Linux
./scyther/bin/scyther-mac --unbounded scyther/saf_phase1.spdl       # macOS (incl. Apple Silicon)
```

### 1.4 Live protocol dashboard (`dashboard/`)
A real-time web UI over the exact same, unmodified `saf/` code above — built so the
protocol's own behaviour, not just a pass/fail line in a terminal, is what gets
demonstrated. Every value it shows is computed live by the real client/gateway
code over a real Mosquitto broker; nothing is mocked, cached across runs, or
hand-written. See `dashboard/server.py`'s module docstring and `saf/runtime_verifier.py`
for the full rationale.

- **Topology view**: MQTT Client — Runtime Verifier — SAF Gateway/Broker, animated
  per real message, with a live phase indicator (Phase 1 / Phase 2 / Approved / Denied).
- **Runtime Verifier ("Scyther node")** (`saf/runtime_verifier.py`): sits, in the
  diagram, on the channel between client and broker. It is *not* Scyther running on
  live traffic — Scyther is a static, offline model checker, it has no notion of "this
  byte sequence, right now". What it does instead: for every real message, it
  independently recomputes, from the real captured `k`, `x`, `c`, `identifier_msg`,
  `t_msg`, whether *this specific exchange* satisfies the same five properties Scyther's
  claims check (Secrecy, Alive, Weakagree, Niagree, Nisynch) — and, because this
  reference implementation runs Algorithm 2 exactly as specified, it live-reproduces
  the Niagree/Nisynch gap from §2 below on every single message, alongside the
  hardened `alpha` the fix would have produced for that same real data.
- **Live message data panel**: the real `x`, `k`, `c`, `alpha`, `identifier_msg`, `t_msg`
  of the last exchange, in hex, as actually sent/received.
- **Attack controls**: buttons that drive the *real* `tamper_alpha=True` /
  `replay_identifier=...` hooks already used by `tests/attack_*.py`, so a tampered-HMAC
  or replayed-identifier denial happens live, on the real gateway.
- **Static verification panel**: shells out, on demand, to the real `scyther-linux` /
  `scyther-mac` binary against the three real `.spdl` files and parses its real stdout —
  the same three results tabulated in §1.3, reproduced live rather than pasted in.

Run it:
```bash
pip install -r requirements.txt
python3 -m dashboard.server        # starts mosquitto (if not already running) + the gateway
```
Then open **http://127.0.0.1:8000/**.

### 1.5 Network simulator (`simulator/`)
A multi-client network simulation — the "how does this behave at scale, under real
network conditions" complement to the single-client dashboard above. See
`simulator/netsim.py`'s module docstring for the full design rationale, summarised here:

**Why SimPy, and not Mininet / NS-3 / OMNeT++:** Mininet needs real Linux network
namespaces, unavailable on macOS without standing up a Docker/VM layer first; NS-3 and
OMNeT++ have no native MQTT support, so using either would mean reimplementing this
already formally-verified protocol logic in C++ — throwing away the exact code
`scyther/` verified and `tests/` exercises. `simpy.rt.RealtimeEnvironment` is a
legitimate, widely-used Python discrete-event simulation engine that instead paces
*when* each simulated client acts (arrival process, per-link latency/jitter, packet
loss) while every action it schedules is a real call into `saf.client.SAFClient` /
`saf.gateway.SAFGateway` — real HMAC/ASCON crypto, a real MQTT round trip over a real
Mosquitto broker. Real network calls are dispatched to a thread pool so many clients'
round trips genuinely overlap, instead of being serialised by the simulator itself.
Nothing about this is a shortcut taken to avoid the "real" simulators — it's the
option that keeps the verified protocol code in the loop; this trade-off is worth
stating explicitly in the SAF-SP write-up.

Each run produces `events.json` (the complete real telemetry stream) and
`metrics.json` (derived, real summary statistics — registration outcomes under the
Section V-B rate limiter, per-message latency, approval/denial counts and reasons,
how often the live runtime verifier reproduced the Niagree/Nisynch gap).
`simulator/report.py` turns a run into six report-ready figures, two of which do
their own live measurement at report time rather than reading the run's data: a
microbenchmark of the as-specified vs. hardened HMAC cost, and a fresh, live
`scyther` subprocess run per model.

Run it:
```bash
python3 -m simulator.netsim --n-clients 40 --n-attackers 10 --max-clients 35 --duration 20
python3 -m simulator.report simulator/results/<timestamp>/
```
Figures land in `simulator/results/<timestamp>/figures/`. `python3 -m simulator.netsim --help`
lists every tunable (client count, link-condition mix, attacker behaviour mix, rate-limit
caps, simulated duration, real-time pacing factor).

## 2. Findings from the reproduction (relevant to SAF-SP)

Reproducing the paper's own Scyther methodology **more rigorously** (checking
agreement/liveness on the full round trip, not just secrecy up to the HMAC check)
surfaced two real gaps in SAF as literally specified in Algorithm 2:

1. **The broker's `VerificationStatus` reply is unauthenticated.** Step 6 sends
   `(identifier_msg, Approved)` in the clear with no MAC. An on-path attacker who
   merely observes `identifier_msg` (itself unencrypted in Step 4) can forge an
   `Approved` response to the client without ever knowing the session key `k`.
   This is outside the property set the original paper's Fig. 6 checks, so it isn't
   a contradiction of their result — just a gap their model didn't cover.

2. **`alpha = HMAC_k(client_state || c)` is not bound to `identifier_msg` or
   `t_msg`.** Because the per-message authenticator never covers the two fields
   that are supposed to provide freshness and uniqueness, a captured `alpha` can, in
   principle, be recombined with a different `identifier_msg`/`t_msg` pair — breaking
   exact session agreement (Niagree) even though the HMAC itself stays unforgeable.

**Fix verified in `saf_phase2_hardened_final.spdl`:**
```
alpha       = HMAC_k(client_state || c || identifier_msg || t_msg)   # was: HMAC_k(client_state || c)
statusMac   = HMAC_k(identifier_msg || Approved/Denied)               # new: broker MACs its reply
```
Both changes cost one extra HMAC each (negligible against the paper's own Section VII
efficiency budget, which already counts `1·T_oh` for "Verify HMAC and client-state")
and add no new round trip.

**Why this matters for SAF-SP:** your Sequence-Aware pillar is the natural place to
fold this in — binding `alpha` to a per-message sequence number closes this gap
*and* gives the broker the material it needs to detect/reorder out-of-order
messages, so it's one mechanism serving two of your stated goals.

## 3. Known modeling clarification

Algorithm 1 has the client store only `x = h(client_state)` (Step 7), never the raw
`client_state`. Algorithm 2 Step 4 then computes `HMAC_k(client_state || c)`, which
is only literally computable with the raw value. We resolve this by using `x` (what
the client actually possesses) in place of raw `client_state` throughout — see the
docstring in `saf/protocol.py` for the full reasoning. Worth flagging explicitly in
the SAF-SP writeup as a clarification made when reproducing the base protocol.

## 4. Project layout
```
saf_project/
├── saf/                       # protocol library
│   ├── crypto_utils.py
│   ├── state_store.py
│   ├── protocol.py
│   ├── ascon_enc.py
│   ├── gateway.py
│   ├── client.py
│   ├── telemetry.py           # real-time event bus (gateway/client -> dashboard/simulator)
│   └── runtime_verifier.py    # live per-message property checker, the dashboard's "Scyther node"
├── dashboard/
│   ├── server.py               # FastAPI + WebSocket backend
│   └── static/index.html       # topology view, live data panel, attack controls
├── simulator/
│   ├── netsim.py                # SimPy real-time multi-client network simulation
│   ├── report.py                # turns a run into report figures
│   └── results/<timestamp>/     # events.json, metrics.json, figures/ (generated, gitignored)
├── tests/
│   ├── demo_normal_flow.py
│   ├── attack_replay.py
│   └── attack_tamper.py
├── scyther/
│   ├── bin/scyther-linux
│   ├── bin/scyther-mac
│   ├── saf_phase1.spdl
│   ├── saf_phase2.spdl
│   └── saf_phase2_hardened_final.spdl
├── requirements.txt
└── mosquitto_conf/mosquitto.conf
```

## 5. Setup on macOS (Apple Silicon / M-series)
Every dependency here (`paho-mqtt`, `ascon`, `numpy`, `scipy`, `matplotlib`, `simpy`,
`fastapi`, `uvicorn`) is pure-Python/pip-installable — nothing needs to be compiled,
and `scyther/bin/scyther-mac` is already a native Apple Silicon binary. Only Mosquitto
itself comes from Homebrew:
```bash
brew install mosquitto        # or: ./setup.sh, which detects macOS and does this for you
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

./run_all.sh                          # CLI demo + attack tests
python3 -m dashboard.server           # live dashboard -> http://127.0.0.1:8000
python3 -m simulator.netsim && python3 -m simulator.report simulator/results/<timestamp>/
```
`dashboard/server.py` and `simulator/netsim.py` both auto-detect and start Mosquitto
from `mosquitto_conf/mosquitto.conf` if nothing is already listening on `127.0.0.1:1883`,
so no separate terminal/step is required for the broker.

## 6. Next steps (SAF-SP)
1. **Pillar 1 (Sequence-Aware):** extend `alpha`'s HMAC input with a session
   sequence number as motivated above; build the chaos-injection buffering logic
   on top of `SAFGateway`.
2. **Pillar 2 (Privacy-Preserving topic obfuscation):** HMAC-derived rotating
   topic pseudonyms, replacing `req.topic` in `saf/protocol.py`'s `PublishRequest`;
   entropy/MI analysis via SciPy/NumPy.
3. Re-run the Scyther models for SAF-SP's modified Phase 2 to confirm the new
   design doesn't reintroduce any of the gaps found here.
4. Extend `saf/runtime_verifier.py` and the dashboard/simulator to reflect SAF-SP's
   hardened Phase 2 once implemented, so the same live-verification story carries
   forward rather than needing to be rebuilt.
