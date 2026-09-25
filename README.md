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
./scyther/bin/scyther-linux --unbounded scyther/saf_phase1.spdl
```

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
├── saf/                    # protocol library
│   ├── crypto_utils.py
│   ├── state_store.py
│   ├── protocol.py
│   ├── ascon_enc.py
│   ├── gateway.py
│   └── client.py
├── tests/
│   ├── demo_normal_flow.py
│   ├── attack_replay.py
│   └── attack_tamper.py
├── scyther/
│   ├── bin/scyther-linux
│   ├── saf_phase1.spdl
│   ├── saf_phase2.spdl
│   └── saf_phase2_hardened_final.spdl
└── mosquitto_conf/mosquitto.conf
```

## 5. Next steps (SAF-SP)
1. **Pillar 1 (Sequence-Aware):** extend `alpha`'s HMAC input with a session
   sequence number as motivated above; build the chaos-injection buffering logic
   on top of `SAFGateway`.
2. **Pillar 2 (Privacy-Preserving topic obfuscation):** HMAC-derived rotating
   topic pseudonyms, replacing `req.topic` in `saf/protocol.py`'s `PublishRequest`;
   entropy/MI analysis via SciPy/NumPy.
3. Re-run the Scyther models for SAF-SP's modified Phase 2 to confirm the new
   design doesn't reintroduce any of the gaps found here.
