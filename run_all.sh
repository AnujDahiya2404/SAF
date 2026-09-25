#!/usr/bin/env bash
# run_all.sh -- starts a local Mosquitto broker (if not already running)
# and runs the full SAF demo + attack test suite.
# Usage: ./run_all.sh
set -e

cd "$(dirname "$0")"

if [ -f venv/bin/activate ]; then
    source venv/bin/activate
fi

PORT=1883

echo "=== Checking for an existing Mosquitto broker on port $PORT ==="
if ! nc -z 127.0.0.1 $PORT 2>/dev/null; then
    echo "[run_all] No broker detected -- starting one from mosquitto_conf/mosquitto.conf"
    mosquitto -c mosquitto_conf/mosquitto.conf -d
    sleep 1
else
    echo "[run_all] Broker already running on port $PORT, reusing it"
fi

echo ""
echo "########## NORMAL FLOW DEMO ##########"
python3 tests/demo_normal_flow.py

echo ""
echo "########## REPLAY ATTACK TEST ##########"
python3 tests/attack_replay.py

echo ""
echo "########## TAMPER / UNREGISTERED-CLIENT ATTACK TEST ##########"
python3 tests/attack_tamper.py

echo ""
echo "=== All tests complete ==="
