#!/bin/bash
echo "⏳ Esperando a Redis..."
until redis-cli -h redis -p 6379 ping 2>/dev/null; do
    sleep 1
done
echo "✓ Redis listo"

mitmdump \
    --listen-host 0.0.0.0 \
    --listen-port 8080 \
    --set block_global=false \
    --proxyauth hooksuite:audit2026 \
    -s /app/services/mitm_addon.py &

MITM_PID=$!
echo "✓ mitmproxy arrancado (PID: $MITM_PID) en puerto 8080"
uvicorn main:app --host 0.0.0.0 --port 8000
