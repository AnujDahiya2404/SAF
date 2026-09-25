#!/usr/bin/env bash
# setup.sh -- one-time environment setup for the SAF project.
# Usage: ./setup.sh
set -e

echo "=== SAF project setup ==="

OS="$(uname -s)"

if [ "$OS" = "Darwin" ]; then
    echo "[setup] Detected macOS -- using Homebrew"
    if ! command -v brew >/dev/null 2>&1; then
        echo "ERROR: Homebrew not found. Install it from https://brew.sh first."
        exit 1
    fi
    brew install mosquitto cmake flex bison || true
elif [ "$OS" = "Linux" ]; then
    echo "[setup] Detected Linux -- using apt"
    sudo apt-get update -qq
    sudo apt-get install -y mosquitto mosquitto-clients cmake flex bison libxml2-dev gcc
else
    echo "Unsupported OS: $OS. Please install mosquitto, cmake, flex, bison manually."
fi

echo "[setup] Creating Python virtual environment (venv/)"
python3 -m venv venv
source venv/bin/activate

echo "[setup] Installing Python dependencies"
pip install --upgrade pip -q
pip install -r requirements.txt -q

echo ""
echo "=== Setup complete ==="
echo "Activate the environment in future shells with:"
echo "    source venv/bin/activate"
echo ""
echo "Next:"
echo "    ./run_all.sh                        -- broker + demo + attack tests (CLI)"
echo "    python3 -m dashboard.server          -- live protocol dashboard, http://127.0.0.1:8000"
echo "    python3 -m simulator.netsim          -- multi-client network simulation"
echo "    python3 -m simulator.report <run-dir> -- turn a simulation run into report figures"
