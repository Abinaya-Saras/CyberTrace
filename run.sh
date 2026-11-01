#!/usr/bin/env bash
# =============================================================================
# CyberTrace - One-Step Launch Script for Evaluators & Judges
# =============================================================================
set -e

PORT=8000
HOST="0.0.0.0"

echo "================================================================="
echo "  CYBERTRACE: Autonomous Incident Correlation & Attack Graph"
echo "  Hackathon Evaluation Launcher"
echo "================================================================="

# 1. Check Python version
if ! command -v python3 &>/dev/null; then
    echo "[-] Error: python3 is required but not installed."
    exit 1
fi

PY_VER=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
echo "[+] Detected Python version: $PY_VER"

# 2. Virtual environment setup
if [ ! -d ".venv" ]; then
    echo "[*] Creating Python virtual environment in .venv..."
    python3 -m venv .venv
fi

echo "[*] Activating virtual environment..."
source .venv/bin/activate

# 3. Dependency check
echo "[*] Verifying dependencies..."
pip install --upgrade pip -q
pip install -r requirements.txt -q

# 4. Optional test suite run
if [ "$1" == "--test" ] || [ "$1" == "-t" ]; then
    echo "================================================================="
    echo "[*] Running Automated Test Suite (62 unit & regression tests)..."
    echo "================================================================="
    PYTHONPATH=. pytest tests/ -v
    echo "[+] All tests passed successfully!"
    echo ""
fi

# 5. Launch Server
if curl -s -f "http://127.0.0.1:$PORT/api/health" &>/dev/null; then
    echo "================================================================="
    echo "[+] CyberTrace is already actively running on http://localhost:$PORT"
    echo "[+] Health check passed. Open http://localhost:$PORT in your browser!"
    echo "================================================================="
    exit 0
fi

echo "================================================================="
echo "[+] Starting CyberTrace Engine on http://$HOST:$PORT"
echo "[+] Open http://localhost:$PORT in your browser to inspect incidents"
echo "================================================================="

export PYTHONPATH=.
exec uvicorn backend.api.main:app --host "$HOST" --port "$PORT" --reload
