#!/usr/bin/env bash
# run_tests.sh -- starts the local Mosquitto broker if it isn't already
# running, then runs all three SAF test scripts in sequence, stopping
# immediately if any of them fails.
#
# Usage:
#   chmod +x run_tests.sh
#   ./run_tests.sh
#
# Place this file in the saf_project/ root (same level as tests/ and
# mosquitto_conf/).

set -e   # exit immediately if any command fails

cd "$(dirname "$0")"

PORT=1883

echo "=== Checking for an existing Mosquitto broker on port $PORT ==="
if nc -z 127.0.0.1 $PORT 2>/dev/null; then
    echo "[run_tests] Broker already running on port $PORT, reusing it."
else
    echo "[run_tests] No broker detected -- starting one from mosquitto_conf/mosquitto.conf"
    mosquitto -c mosquitto_conf/mosquitto.conf -d
    sleep 1
fi

echo ""
echo "########## 1/3: NORMAL FLOW DEMO ##########"
python3 tests/demo_normal_flow.py

echo ""
echo "########## 2/3: REPLAY ATTACK TEST ##########"
python3 tests/attack_replay.py

echo ""
echo "########## 3/3: TAMPER / UNREGISTERED-CLIENT ATTACK TEST ##########"
python3 tests/attack_tamper.py

echo ""
echo "=== All 3 tests completed successfully ==="
