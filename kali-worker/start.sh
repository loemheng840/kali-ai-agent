#!/bin/bash
# =============================================================================
# start.sh — launches MCP server (port 5001) + Go API server (port 8080)
# =============================================================================
set -e

echo "[kali-worker] Starting MCP server on :5001 ..."
/opt/mcp-venv/bin/python /opt/mcp_server.py &
MCP_PID=$!

echo "[kali-worker] Starting Go Agent Server on :9090 ..."
/usr/local/bin/kali-agent-server &
GO_PID=$!

echo "[kali-worker] Both services started (MCP=$MCP_PID, Go=$GO_PID)"

# If either process dies, kill the other and exit
wait -n $MCP_PID $GO_PID
EXIT_CODE=$?
kill $MCP_PID $GO_PID 2>/dev/null
exit $EXIT_CODE