#!/usr/bin/env bash
# scyther/verify.sh
#
# Runs the real Scyther binary against the two models that pass every claim
# outright: Phase 1 (saf_phase1.spdl, Algorithm 1 exactly as specified) and
# the hardened Phase 2 variant (saf_phase2_hardened_final.spdl, the fix for
# the Niagree/Nisynch gap documented in README.md section 2). Deliberately
# does NOT run saf_phase2.spdl (Phase 2 exactly as the base paper specifies
# it) here -- that model's whole point is to document a real, reproducible
# gap (see its own header comment), not to demonstrate an all-green result,
# so bundling it into an "all green" command would misrepresent it. Run it
# on its own to see that finding:
#   ./scyther/bin/scyther-linux scyther/saf_phase2.spdl   # (or scyther-mac)
#
# Usage: ./scyther/verify.sh [--unbounded]

set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

if [[ "$(uname -s)" == "Darwin" ]]; then
  BIN="./bin/scyther-mac"
else
  BIN="./bin/scyther-linux"
fi

if [[ ! -x "$BIN" ]]; then
  echo "error: $BIN not found or not executable" >&2
  exit 1
fi

BOUND_FLAG=()
if [[ "${1:-}" == "--unbounded" ]]; then
  BOUND_FLAG=(--unbounded)
fi

run_model() {
  local title="$1" spdl="$2"
  echo "=================================================================="
  echo " $title"
  echo " ($spdl)"
  echo "=================================================================="
  # scyther-linux/-mac exits nonzero (observed: 3) even on an all-Ok run --
  # it's not a shell-style pass/fail code, so don't let `set -e` treat it
  # as a script failure; the actual per-claim Ok/Fail is in the output above.
  "$BIN" "${BOUND_FLAG[@]}" "$spdl" || true
  echo
}

run_model "Phase 1 -- Pre-Session (Algorithm 1)" "saf_phase1.spdl"
run_model "Phase 2 -- In-Session, hardened fix (closes the Niagree/Nisynch gap)" "saf_phase2_hardened_final.spdl"

BIN_NAME="$(basename "$BIN")"
echo "All claims above should read Ok. This intentionally skips"
echo "saf_phase2.spdl (Phase 2 exactly as the base paper specifies it),"
echo "which is expected to show real Fails -- see its header comment and"
echo "README.md section 2 for why, or run it directly:"
echo "  ./scyther/bin/$BIN_NAME scyther/saf_phase2.spdl"
