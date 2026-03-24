# gateway-fastapi/main.py
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import time
from contextlib import asynccontextmanager
from typing import Any, AsyncGenerator

import httpx
from openai import AsyncOpenAI
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from mcp import ClientSession
from mcp.client.sse import sse_client
from pydantic import BaseModel, field_validator

# ── Configuration ─────────────────────────────────────────────────────────────

KALI_SERVER_URL = os.getenv("KALI_SERVER_URL", "http://localhost:9090")
MCP_SERVER_URL  = os.getenv("MCP_SERVER_URL",  "http://localhost:5001/sse")
HITL_SECRET     = os.environ["HITL_SECRET"]
OLLAMA_HOST     = os.getenv("OLLAMA_HOST", "http://localhost:11434")
OLLAMA_MODEL    = os.getenv("OLLAMA_MODEL", "llama3.1")

DESTRUCTIVE_TOOLS = {"sqlmap_scan", "metasploit_run"}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
log = logging.getLogger("kali-gateway")

# ── App state ─────────────────────────────────────────────────────────────────

class AppState:
    mcp_tools: list[dict[str, Any]] = []
    ai_client: AsyncOpenAI | None = None
    http_client: httpx.AsyncClient | None = None

state = AppState()

# ── Lifespan ──────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    log.info("Gateway starting up …")

    # Ollama uses OpenAI-compatible API
    state.ai_client = AsyncOpenAI(
        base_url=f"{OLLAMA_HOST}/v1",
        api_key="ollama",   # required but ignored by Ollama
    )
    state.http_client = httpx.AsyncClient(base_url=KALI_SERVER_URL, timeout=600)

    try:
        state.mcp_tools = await fetch_mcp_tools()
        log.info("Loaded %d MCP tools: %s",
               len(state.mcp_tools), [t["function"]["name"] for t in state.mcp_tools])
    except Exception as exc:
        log.warning("Could not reach MCP server at startup: %s", exc)

    yield

    await state.http_client.aclose()
    log.info("Gateway shut down.")

# ── FastAPI app ───────────────────────────────────────────────────────────────

app = FastAPI(
    title="Kali AI Agent Gateway",
    version="1.0.0",
    description="AI-Powered Pentesting Agent using Ollama + Kali Linux tools.",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Request / Response models ─────────────────────────────────────────────────

class ChatMessage(BaseModel):
    role: str
    content: str

class ChatRequest(BaseModel):
    messages: list[ChatMessage]
    hitl_approved: dict[str, str] = {}

    @field_validator("messages")
    @classmethod
    def must_have_messages(cls, v):
        if not v:
            raise ValueError("messages must not be empty")
        return v

# ── MCP tool discovery ────────────────────────────────────────────────────────

async def fetch_mcp_tools() -> list[dict[str, Any]]:
    async with sse_client(MCP_SERVER_URL) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools_result = await session.list_tools()

    # MCP SDK v1.26.0 uses .name, .description, .inputSchema (capital S)
    return [
        {
            "type": "function",
            "function": {
                "name": tool.name,
                "description": tool.description or f"Run {tool.name}",
                "parameters": tool.inputSchema or {"type": "object", "properties": {}},
            }
        }
        for tool in tools_result.tools
    ]

# ── HITL token ────────────────────────────────────────────────────────────────

def generate_hitl_token(job_id: str) -> tuple[str, str]:
    ts = int(time.time())
    message = f"hitl:{job_id}:{ts}"
    token = hmac.new(
        HITL_SECRET.encode(), message.encode(), hashlib.sha256
    ).hexdigest()
    return token, f"{job_id}:{ts}"

# ── Go server proxy ───────────────────────────────────────────────────────────

async def call_go_server(
    tool_name: str,
    tool_input: dict[str, Any],
    hitl_approved: dict[str, str],
) -> str:
    endpoint_map = {
        "nmap_scan":      "/tool/nmap",
        "nikto_scan":     "/tool/nikto",
        "ffuf_fuzz":      "/tool/ffuf",
        "sqlmap_scan":    "/tool/sqlmap",
        "metasploit_run": "/tool/metasploit",
        "dns_lookup":     "/tool/dns",
    }
    endpoint = endpoint_map.get(tool_name)
    if not endpoint:
        raise HTTPException(400, f"Unknown tool: {tool_name}")

    headers: dict[str, str] = {"Content-Type": "application/json"}

    if tool_name in DESTRUCTIVE_TOOLS:
        approved = hitl_approved.get(tool_name)
        if not approved:
            raise HTTPException(403, f"Tool '{tool_name}' requires HITL approval.")
        token, payload = approved.split("|", 1)
        headers["X-HITL-Token"]   = token
        headers["X-HITL-Payload"] = payload

    # Start job
    response = await state.http_client.post(endpoint, json=tool_input, headers=headers)
    response.raise_for_status()
    job = response.json()
    job_id = job.get("job_id")

    if not job_id:
        return json.dumps(job)

    # Collect full SSE output
    output_lines: list[str] = []
    stream_url = f"{KALI_SERVER_URL}/stream/{job_id}"

    async with httpx.AsyncClient(timeout=300) as stream_client:
        async with stream_client.stream("GET", stream_url) as stream:
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

    return "\n".join(output_lines) if output_lines else "No output received"

# ── Agent loop ────────────────────────────────────────────────────────────────

SYSTEM_PROMPT = """You are KaliAgent, an expert penetration tester and security analyst.
You have access to Kali Linux tools. Your workflow:

1. Analyse the user request and pick the right tool.
2. Call the tool with precise arguments.
3. Read the full scan output and provide a structured analysis:
   - Executive summary
   - Open ports / vulnerabilities found
   - Risk level (Critical / High / Medium / Low / Info)
   - Recommended next steps

SAFETY RULES:
- Never scan targets without explicit permission.
- Prefer nmap/nikto before sqlmap/metasploit.
"""

async def agent_stream(
    messages: list[dict], hitl_approved: dict[str, str]
) -> AsyncGenerator[str, None]:

    if not state.mcp_tools:
        try:
            state.mcp_tools = await fetch_mcp_tools()
        except Exception as exc:
            yield f"data: {json.dumps({'type':'error','content':str(exc)})}\n\n"
            return

    conversation = [{"role": "system", "content": SYSTEM_PROMPT}] + list(messages)
    max_rounds = 6

    for round_num in range(max_rounds):
        log.info("Agent round %d", round_num + 1)

        response = await state.ai_client.chat.completions.create(
            model=OLLAMA_MODEL,
            messages=conversation,
            tools=state.mcp_tools,
            tool_choice="auto",
        )

        msg = response.choices[0].message

        # Stream text response
        if msg.content:
            yield f"data: {json.dumps({'type':'text','content':msg.content})}\n\n"

        # No tool calls — done
        if not msg.tool_calls:
            yield f"data: {json.dumps({'type':'done'})}\n\n"
            return

        # Process tool calls
        tool_results = []
        for tool_call in msg.tool_calls:
            tool_name  = tool_call.function.name
            tool_input = json.loads(tool_call.function.arguments)
            tool_id    = tool_call.id

            log.info("AI requested tool: %s  input: %s", tool_name, tool_input)
            yield f"data: {json.dumps({'type':'tool_call','tool':tool_name,'input':tool_input})}\n\n"

            # HITL check for destructive tools
            if tool_name in DESTRUCTIVE_TOOLS and tool_name not in hitl_approved:
                token, payload = generate_hitl_token(tool_id)
                yield f"data: {json.dumps({'type':'hitl_required','tool':tool_name,'token':token,'payload':payload})}\n\n"
                yield f"data: {json.dumps({'type':'done','reason':'awaiting_hitl'})}\n\n"
                return

            try:
                result = await call_go_server(tool_name, tool_input, hitl_approved)
                tool_results.append({
                    "role": "tool",
                    "tool_call_id": tool_id,
                    "content": result,
                })
                yield f"data: {json.dumps({'type':'tool_result','tool':tool_name,'result':result[:500]})}\n\n"
            except Exception as exc:
                log.error("Tool %s failed: %s", tool_name, exc)
                tool_results.append({
                    "role": "tool",
                    "tool_call_id": tool_id,
                    "content": f"Error: {exc}",
                })

        # Append assistant message + tool results to conversation
        conversation.append({"role": "assistant", "content": msg.content or "", "tool_calls": msg.tool_calls})
        conversation.extend(tool_results)

    yield f"data: {json.dumps({'type':'error','content':'Max rounds reached'})}\n\n"

# ── HTTP Endpoints ────────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    return {"status": "ok", "service": "kali-gateway", "model": OLLAMA_MODEL}

@app.get("/tools")
async def list_tools():
    if not state.mcp_tools:
        state.mcp_tools = await fetch_mcp_tools()
    return {"tools": state.mcp_tools}

@app.post("/chat")
async def chat(req: ChatRequest):
    """
    Streaming endpoint — returns Server-Sent Events.
    Event types: text | tool_call | tool_result | hitl_required | done | error
    """
    messages = [m.model_dump() for m in req.messages]

    async def event_generator():
        try:
            async for chunk in agent_stream(messages, req.hitl_approved):
                yield chunk
        except Exception as exc:
            log.exception("Unhandled error in agent_stream")
            yield f"data: {json.dumps({'type':'error','content':str(exc)})}\n\n"

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )