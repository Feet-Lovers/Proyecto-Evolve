#!/bin/bash
mitmdump --listen-host 0.0.0.0 --listen-port 8080 --set block_global=false -s /app/services/mitm_addon.py &
MITM_PID=$!
echo "✓ mitmproxy arrancado (PID: $MITM_PID) en puerto 8080"
uvicorn main:app --host 0.0.0.0 --port 8000
