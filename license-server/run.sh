#!/bin/bash
# Installs Python dependencies (if missing) and starts the license server.
set -e
cd "$(dirname "$0")"
PY=$(command -v python3 || command -v python)
[ -z "$PY" ] && { echo "Python 3 is required."; exit 1; }
if ! "$PY" -c "import flask, cryptography" 2>/dev/null; then
  echo "Installing dependencies from requirements.txt ..."
  "$PY" -m pip install -r requirements.txt
fi
[ -f .env ] && { set -a; . ./.env; set +a; }
exec "$PY" license_server.py
