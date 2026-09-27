#!/usr/bin/env bash
# ns3sim/run.sh -- configure+build (if needed) and run the ns-3 SAF
# simulation. Any extra arguments are forwarded to the simulation binary
# (see `./ns3sim/run.sh -- --help` for its own options).
#
# Usage:
#   ./ns3sim/run.sh                                    # build (if needed) + run with defaults
#   ./ns3sim/run.sh --nPublishers=40 --duration=60      # forwarded straight to saf-ns3-sim
#   ./ns3sim/run.sh --rebuild                           # force a clean reconfigure+rebuild first

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

REBUILD=0
ARGS=()
for arg in "$@"; do
  if [[ "$arg" == "--rebuild" ]]; then
    REBUILD=1
  else
    ARGS+=("$arg")
  fi
done

if [[ "$REBUILD" == "1" ]]; then
  rm -rf build
fi

if [[ ! -f build/Makefile ]]; then
  echo "[ns3sim] Configuring (cmake) ..."
  mkdir -p build
  (cd build && cmake .. -DCMAKE_BUILD_TYPE=Release)
fi

echo "[ns3sim] Building ..."
(cd build && make -j"$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 2)")

echo "[ns3sim] Running saf-ns3-sim ${ARGS[*]:-}"
(cd build && ./saf-ns3-sim "${ARGS[@]}")
