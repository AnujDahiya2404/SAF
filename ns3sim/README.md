# SAF ns-3 simulation

A real ns-3 network simulation of the base paper's protocol (Algorithms 1 &
2), built after this project deliberately avoided ns-3 the first time
around (see the root `README.md`'s earlier reasoning, and the fork this
directory represents below).

## Why this exists, and what it trades away

ns-3 has no native MQTT support and is C++-only. Getting SAF's protocol
logic to actually run inside it means one of two paths:

1. **Reimplement the protocol as a real ns-3 `Application`, in C++.** The
   standard way these papers validate a protocol under ns-3: real
   packet-level metrics (latency, throughput, loss under configurable
   channel models) from ns-3's own `FlowMonitor`. This is what
   `ns3sim/` does.
2. **Bridge the real `saf/*.py` code into an ns-3-simulated network**
   (TapBridge / Direct Code Execution). Keeps a single true
   implementation, but DCE is largely unmaintained on modern ns-3,
   Linux-only, needs root + tap devices, and is considerably more fragile
   to set up and keep working.

Path 1 was chosen. The real cost of that choice: `ns3sim/src/*.cc` is a
**second implementation** of Algorithm 1/2, not the literal Python code
`scyther/` verified and `tests/` exercises — it mirrors the same steps,
field names, and (importantly) the same denial-reason strings, but it is
not the same code, so it needs to be kept honest rather than trusted by
construction. Two things do that:

- **`tools/crosscheck_hmac.{cc,py}`**: the exact same fixed test vectors,
  run through `ns3sim`'s C++ `safcrypto::ComputeAlpha()` and through the
  real `saf/crypto_utils.compute_alpha()`, output in the same format so a
  plain `diff` proves they're byte-identical:
  ```bash
  ./ns3sim/build/saf-crosscheck-hmac > /tmp/cpp.txt
  python3 ns3sim/tools/crosscheck_hmac.py > /tmp/py.txt
  diff /tmp/cpp.txt /tmp/py.txt && echo MATCH
  ```
- **The same attack scenarios `tests/attack_*.py` exercise against the
  real implementation** are built into the simulated client roles
  (`kTamperAttacker`, `kReplayAttacker`, `kGhostAttacker` in
  `saf-client-app.h`) and produce the exact same denial-reason strings
  gateway.py returns (`"HMAC verification failed (integrity/authenticity
  check failed)"`, `"duplicate identifier_msg (replay or unintended
  duplication)"`, `"unregistered client_id (no Phase-1 client-state on
  file)"`) -- run a simulation and grep the output for these to confirm
  the C++ broker denies exactly what the Python one does, for the same
  reasons.

## What's simulated

A star topology: one broker node, N client nodes, each on its own
point-to-point link (not a shared LAN -- each link is a separate subnet,
so there's no routing to configure, every client just dials the broker's
address on its own direct link). Links cycle through three profiles
(`good`: 2ms/0% loss, `medium`: 20ms/1% loss, `poor`: 80ms/5% loss) so a
run produces a real spread of network conditions, not one flat number.

Every client is one of:
- **Publisher** -- registers, then performs `publishMessages` full
  Phase-2 round trips (SessionInitiate → Level1InfoRequest → PublishRequest
  with a real `alpha=HMAC_k(x‖c)` → VerificationStatus), spaced
  `publishInterval` seconds apart.
- **Subscriber** -- registers, subscribes once; receives real `AppData`
  relays from the broker for every Approved publish on its topic *after*
  its subscription lands (the broker only relays to clients Approved as
  subscribed at relay time, same as `saf/gateway.py`'s real relay path).
- **Tamper attacker** -- registers, sends a message with a bit-flipped
  `alpha` (denied), then a normal one (approved) -- exactly
  `tests/attack_tamper.py`'s scenario.
- **Replay attacker** -- registers, publishes normally, then replays the
  *same* `identifier_msg` a second time (denied) -- exactly
  `tests/attack_replay.py`'s scenario.
- **Ghost attacker** -- skips Phase 1 entirely and sends a fabricated
  `PublishRequest` for a `client_id` that was never registered (denied)
  -- the "unregistered client" case from `tests/attack_tamper.py`.

A run produces one JSON file with:
- `broker_stats` / `decision_log` -- protocol-level outcomes (approvals,
  denials, and why), from the same `SafBrokerApp` that verified every
  message.
- `client_events` -- per-client registration/approval/denial/received
  events with real simulated timestamps.
- `flow_monitor` -- ns-3's own real per-flow packet counts, loss, mean
  delay, and throughput, straight from `FlowMonitor`.

## Build

### Linux (this repo's dev/CI environment)
```bash
sudo apt-get install libns3-dev libns3.41t64 libgsl-dev libssl-dev nlohmann-json3-dev cmake g++
./ns3sim/run.sh          # configures, builds, and runs with defaults
```

### macOS (Apple Silicon incl. M-series)
Confirmed working on a real M3 MacBook (macOS, Apple Silicon) via
Homebrew's `ns-3` formula (installs ns-3.48 with prebuilt arm64 bottles --
no source build needed):
```bash
xcode-select --install                          # if not already installed
brew install ns-3 openssl nlohmann-json cmake
export PKG_CONFIG_PATH="$(brew --prefix ns-3)/lib/pkgconfig:$PKG_CONFIG_PATH"
./ns3sim/run.sh
```
Three real issues turned up getting an actual M3 build green, all now
fixed in `CMakeLists.txt` and confirmed not to affect the Linux build:
1. Homebrew's ns-3 depends on `open-mpi` and is built with MPI support,
   so its exported library list names the `MPI::MPI_CXX` CMake target --
   resolved with `find_package(MPI COMPONENTS CXX)`.
2. That same build's `.pc` files (e.g. `ns3-core.pc`) contain a literal
   `-linterface_libs-NOTFOUND` token -- an unresolved CMake variable
   baked in at ns-3's own build time (an upstream packaging bug, not
   something on our end). Filtered out with `list(FILTER NS3_LIBRARIES
   EXCLUDE REGEX ".*-NOTFOUND$")`.
3. ns-3 3.48's headers use C++20 (`std::strong_ordering`, the `<=>`
   operator, `std::remove_cvref_t`) -- `CMAKE_CXX_STANDARD` raised from
   17 to 20.

If `PKG_CONFIG_PATH` still doesn't find the modules, or a Homebrew update
changes the formula's layout entirely, point CMake at the prefix directly:
```bash
cmake -S ns3sim -B ns3sim/build -DCMAKE_PREFIX_PATH=$(brew --prefix ns-3)
cmake --build ns3sim/build
```
If a Homebrew `ns-3` package isn't available at all, see
[the ns-3 wiki's macOS build notes](https://www.nsnam.org/docs/installation/html/)
for building from the official source tarball instead (`./ns3 configure`,
`./ns3 build`, both of which work on Apple Silicon) -- untested in this
session, since the Homebrew path worked.

## Run
```bash
./ns3sim/run.sh                                            # defaults: 15 pub, 10 sub, 3+3+3 attackers, 30s
./ns3sim/run.sh --nPublishers=40 --nSubscribers=15 --duration=60
./ns3sim/run.sh --rebuild                                  # force a clean reconfigure+rebuild first
cd ns3sim/build && ./saf-ns3-sim --help                    # every tunable (client counts, topic, intervals, ...)
```

**Registration rate limit:** the broker's `--maxClients` (default 50)
mirrors `saf/state_store.py`'s own `SAFStateStore(max_clients=50)`
default -- Section V-B's real rate-limiting policy, not a simulator
limitation. If `nPublishers + nSubscribers + nTamperAttackers +
nReplayAttackers` (ghost attackers skip registration, so they don't
count) exceeds it, the excess are correctly `Denied` at Phase 1, exactly
as the real broker would. Raise the cap explicitly for larger runs:
```bash
./ns3sim/run.sh --nPublishers=40 --nSubscribers=15 --maxClients=70 --duration=60
```

**Results**: land at `ns3sim/build/ns3sim-results.json` by default (i.e.
directly inside the `ns3sim/build/` directory `run.sh` builds in) --
`cat ns3sim/build/ns3sim-results.json | python3 -m json.tool` to browse
it, or pass `--out=/some/other/path.json` to write somewhere else. The
whole `ns3sim/build/` directory (binaries and results alike) is
gitignored, same as `simulator/results/` used to be.
