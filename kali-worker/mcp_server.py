# kali-worker/mcp_server.py
# Compatible with mcp 1.26.0
# The fix: handle_sse must return Response() after the context manager exits

import json
import os
import httpx
import uvicorn

from mcp.server import Server
from mcp.server.sse import SseServerTransport
from mcp.types import Tool, TextContent
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Route, Mount

GO_SERVER = os.getenv("KALI_SERVER_URL", "http://localhost:9090")
PORT      = int(os.getenv("MCP_PORT", "5001"))

server = Server("kali-tools")

# ── Tool definitions ───────────────────────────────────────────────────────────

@server.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="nmap_scan",
            description="Run an nmap port/service scan against a target IP or hostname",
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "IP, hostname or CIDR"},
                    "flags":  {"type": "string", "description": "nmap flags", "default": "-sV --open -T4"}
                },
                "required": ["target"]
            }
        ),
        Tool(
            name="nikto_scan",
            description="Run a Nikto web vulnerability scan against a target URL",
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Target URL or IP"}
                },
                "required": ["target"]
            }
        ),
        Tool(
            name="ffuf_fuzz",
            description="Run ffuf directory fuzzing against a target URL",
            inputSchema={
                "type": "object",
                "properties": {
                    "target":   {"type": "string", "description": "URL with FUZZ keyword"},
                    "wordlist": {"type": "string", "description": "Path to wordlist",
                                 "default": "/usr/share/wordlists/dirb/common.txt"}
                },
                "required": ["target"]
            }
        ),
        Tool(
            name="sqlmap_scan",
            description="Run sqlmap SQL injection test (requires HITL approval)",
            inputSchema={
                "type": "object",
                "properties": {
                    "target": {"type": "string", "description": "Target URL"}
                },
                "required": ["target"]
            }
        ),
        Tool(
            name="dns_lookup",
            description="Perform DNS lookup on a domain",
            inputSchema={
                "type": "object",
                "properties": {
                    "domain": {"type": "string", "description": "Domain name"}
                },
                "required": ["domain"]
            }
        ),
    ]

# ── Tool execution ─────────────────────────────────────────────────────────────

@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    endpoint_map = {
        "nmap_scan":   "/tool/nmap",
        "nikto_scan":  "/tool/nikto",
        "ffuf_fuzz":   "/tool/ffuf",
        "sqlmap_scan": "/tool/sqlmap",
        "dns_lookup":  "/tool/dns",
    }
    endpoint = endpoint_map.get(name)
    if not endpoint:
        return [TextContent(type="text", text=f"Unknown tool: {name}")]

    if name in ["nmap_scan", "nmap"]:
        body = {"target": arguments["target"],
                "args": arguments.get("flags", "-sV --open -T4").split()}
    elif name in ["nikto_scan", "nikto"]:
        body = {"target": arguments["target"], "args": []}
    elif name in ["ffuf_fuzz", "ffuf"]:
        body = {"target": arguments["target"],
                "args": ["-w", arguments.get("wordlist", "/usr/share/wordlists/dirb/common.txt")]}
    elif name in ["sqlmap_scan", "sqlmap"]:
        body = {"target": arguments["target"], "args": ["--batch", "--level=1"]}
    elif name in ["dns_lookup", "dns"]:
        body = {"target": arguments["domain"], "args": []}
    else:
        body = {"target": arguments.get("target", ""), "args": []}

    try:
        async with httpx.AsyncClient(timeout=300) as client:
            resp = await client.post(f"{GO_SERVER}{endpoint}", json=body)
            resp.raise_for_status()
            job = resp.json()
            job_id = job.get("job_id")
            if not job_id:
                return [TextContent(type="text", text=json.dumps(job, indent=2))]

            output_lines: list[str] = []
            async with client.stream("GET", f"{GO_SERVER}/stream/{job_id}") as stream:
                async for line in stream.aiter_lines():
                    if not line.startswith("data:"):
                        continue
                    raw = line[5:].strip()
                    if not raw:
                        continue
                    try:
                        event = json.loads(raw)
                        etype = event.get("type", "")
                        data  = event.get("data", "")
                        if etype == "stdout":
                            output_lines.append(data)
                        elif etype == "stderr":
                            output_lines.append(f"[stderr] {data}")
                        elif etype in ("exit", "error", "close"):
                            break
                    except Exception:
                        continue

            output = "\n".join(output_lines) if output_lines else "No output received"
            return [TextContent(type="text", text=output)]

    except Exception as e:
        return [TextContent(type="text", text=f"Error: {e}")]

# ── SSE transport ──────────────────────────────────────────────────────────────

sse_transport = SseServerTransport("/messages/")

async def handle_sse(request: Request):
    async with sse_transport.connect_sse(
        request.scope, request.receive, request._send
    ) as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options(),
        )
    return Response()   # ← REQUIRED in mcp 1.26.0 to avoid NoneType error

async def handle_post_message(request: Request):
    """Wrapper for sse_transport.handle_post_message to ensure proper ASGI response."""
    response = await sse_transport.handle_post_message(request.scope, request.receive, request._send)
    return response if response is not None else Response()

# ── Starlette app ──────────────────────────────────────────────────────────────

app = Starlette(
    routes=[
        Route("/sse", endpoint=handle_sse, methods=["GET"]),
        Route("/mcp", endpoint=handle_sse, methods=["GET"]),
        Route("/messages/", endpoint=handle_post_message, methods=["POST"]),
    ]
)

# ── Entry point ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print(f"[mcp-server] Starting on port {PORT}")
    print(f"[mcp-server] Go server → {GO_SERVER}")
    uvicorn.run(app, host="0.0.0.0", port=PORT, log_level="info")