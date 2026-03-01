# BBHunter v2.0 — AI-Centered Transformation Plan

> **Goal:** When you run `python bbhunter.py` with no args, it spawns an interactive AI agent that uses all your tools autonomously. Legacy CLI flags still work for backward compatibility.

---

## Table of Contents

1. [Vision & Philosophy](#1-vision--philosophy)
2. [Architecture Overview](#2-architecture-overview)
3. [New Project Structure](#3-new-project-structure)
4. [Phase 1 — Tool Registry](#4-phase-1--tool-registry)
5. [Phase 2 — AI Agent Loop](#5-phase-2--ai-agent-loop)
6. [Phase 3 — Session Memory](#6-phase-3--session-memory)
7. [Phase 4 — Telegram Bot](#7-phase-4--telegram-bot)
8. [Phase 5 — Cron Scheduler](#8-phase-5--cron-scheduler)
9. [Phase 6 — Entry Point Refactor](#9-phase-6--entry-point-refactor-bbhunterpy)
10. [System Prompt](#10-system-prompt)
11. [Configuration](#11-configuration)
12. [Example Interactions](#12-example-interactions)
13. [Migration Checklist](#13-migration-checklist)
14. [Roadmap Integration](#14-roadmap-integration)

---

## 1. Vision & Philosophy

### Current State
```
User → python bbhunter.py [command] [flags] → Tool → (optional) AI analysis
```

### Target State
```
User → python bbhunter.py → AI Agent → decides what tools to run → reports findings
```

The LLM becomes the **primary decision-maker**. It receives a natural language goal (e.g. *"hunt example.com for vulns"*), plans the attack flow, calls your tools in sequence, interprets results, and delivers a final analysis — all autonomously.

### Design Principles
- **AI-first, CLI-compatible** — no flags = agent mode, flags = legacy CLI mode
- **Tool use over prompting** — LLM calls tools via Anthropic function calling, not string parsing
- **Memory between hunts** — SQLite stores all sessions, findings, and target history
- **Single binary** — still just `python bbhunter.py`, no new entry points needed
- **Zero new dependencies for core** — keep the pure stdlib philosophy, optional deps for Telegram

---

## 2. Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│                     bbhunter.py                         │
│           (entry point — detects mode)                  │
└────────────────────┬────────────────────────────────────┘
                     │
         ┌───────────┴────────────┐
         │                        │
    No args / -i            CLI flags passed
    (Agent Mode)            (Legacy Mode)
         │                        │
         ▼                        ▼
  ┌─────────────┐        ┌──────────────────┐
  │ Agent Loop  │        │ Original modules  │
  │ (LLM brain) │        │ recon/scan/etc.   │
  └──────┬──────┘        └──────────────────┘
         │
         ▼
  ┌─────────────────────────────────┐
  │         Tool Registry           │
  │  recon | scan | payloads        │
  │  report | ai_analyze | memory   │
  └──────────────┬──────────────────┘
                 │
         ┌───────┴────────┐
         │                │
    ┌────▼────┐     ┌─────▼──────┐
    │ SQLite  │     │  Providers  │
    │ Memory  │     │ Claude/GPT  │
    └─────────┘     └────────────┘
```

---

## 3. New Project Structure

```
bbhunter/
│
├── bbhunter.py              ← MODIFIED: detects agent vs CLI mode
│
├── agent/
│   ├── __init__.py
│   ├── loop.py              ← Core agent loop (LLM ↔ tools)
│   ├── context.py           ← System prompt builder
│   ├── planner.py           ← Multi-step hunt planning
│   └── memory.py            ← Session memory interface
│
├── tools/
│   ├── __init__.py
│   ├── registry.py          ← Tool definitions (JSON schema for LLM)
│   ├── executor.py          ← Dispatches LLM tool calls to real modules
│   ├── recon_tool.py        ← Wraps modules/recon logic
│   ├── scan_tool.py         ← Wraps modules/scan logic
│   ├── payload_tool.py      ← Wraps modules/payload logic
│   ├── report_tool.py       ← Wraps modules/report logic
│   └── analyze_tool.py      ← Wraps modules/ai analyzer logic
│
├── channels/
│   ├── __init__.py
│   ├── terminal.py          ← Interactive terminal chat (readline)
│   └── telegram.py          ← Telegram bot gateway
│
├── cron/
│   ├── __init__.py
│   └── scheduler.py         ← Schedule recurring hunts
│
├── providers/
│   ├── __init__.py
│   ├── anthropic.py         ← Claude API (tool use)
│   └── openai.py            ← OpenAI API (function calling)
│
├── memory/
│   ├── __init__.py
│   └── db.py                ← SQLite: sessions, findings, targets
│
├── modules/                 ← YOUR EXISTING CODE (untouched)
│   └── ...
│
├── config/
│   └── config.py            ← Loads ~/.bbhunter/config.json
│
├── bbhunter_output/
├── bbhunter_commands.txt
├── bbhunter_roadmap.md
└── README.md
```

---

## 4. Phase 1 — Tool Registry

This is the most important file. It tells the LLM what tools exist and how to call them.

### `tools/registry.py`

```python
"""
Tool definitions for LLM function/tool calling.
Each tool maps directly to a BBHunter module.
"""

TOOLS = [
    {
        "name": "recon",
        "description": (
            "Enumerate subdomains for a target domain. "
            "Performs DNS resolution, HTTP/HTTPS probing, and TLS cert analysis. "
            "Use this first when given a domain target."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "domain": {
                    "type": "string",
                    "description": "Target domain e.g. example.com (no https://)"
                },
                "threads": {
                    "type": "integer",
                    "description": "Thread count for enumeration. Default: 50. Max: 200."
                }
            },
            "required": ["domain"]
        }
    },
    {
        "name": "scan",
        "description": (
            "Scan a specific URL for vulnerabilities. "
            "Checks: security headers (HSTS, CSP, X-Frame-Options), "
            "sensitive paths (.env, .git, admin panels), "
            "CORS misconfigurations, cookie flags, TLS expiry. "
            "Use after recon to scan discovered subdomains."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "Full URL to scan e.g. https://admin.example.com"
                }
            },
            "required": ["url"]
        }
    },
    {
        "name": "generate_payloads",
        "description": (
            "Generate attack payloads for manual testing. "
            "Use when scan findings suggest a specific vulnerability type. "
            "Returns 100+ ready-to-use payloads."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "vuln_type": {
                    "type": "string",
                    "enum": ["xss", "sqli", "ssrf", "lfi", "ssti", "xxe", "open_redirect"],
                    "description": "Vulnerability type based on scan findings"
                },
                "category": {
                    "type": "string",
                    "enum": ["basic", "bypass", "blind", "all"],
                    "description": "Payload category. Default: all"
                }
            },
            "required": ["vuln_type"]
        }
    },
    {
        "name": "write_report",
        "description": (
            "Generate a professional bug bounty report in Markdown. "
            "Use when the user asks for a report or after confirming a valid finding. "
            "Auto-fills CVSS scores and remediation advice."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "Target URL or domain"
                },
                "vuln_type": {
                    "type": "string",
                    "enum": ["xss", "sqli", "ssrf", "lfi", "idor", "cors", "ssti", "xxe", "other"]
                },
                "severity": {
                    "type": "string",
                    "enum": ["critical", "high", "medium", "low"]
                },
                "summary": {
                    "type": "string",
                    "description": "Brief description of the vulnerability"
                },
                "findings": {
                    "type": "array",
                    "description": "List of finding objects from scan results",
                    "items": {"type": "object"}
                }
            },
            "required": ["target", "vuln_type", "severity", "summary"]
        }
    },
    {
        "name": "recall_memory",
        "description": (
            "Query past hunt sessions and findings from memory. "
            "Use when user asks about previous scans, known targets, or past findings."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "What to recall e.g. 'findings for example.com' or 'last 3 hunts'"
                }
            },
            "required": ["query"]
        }
    }
]
```

### `tools/executor.py`

```python
"""
Dispatches LLM tool calls to actual BBHunter modules.
"""
import json
from tools.recon_tool import run_recon
from tools.scan_tool import run_scan
from tools.payload_tool import run_payloads
from tools.report_tool import run_report
from memory.db import recall

DISPATCH = {
    "recon":             run_recon,
    "scan":              run_scan,
    "generate_payloads": run_payloads,
    "write_report":      run_report,
    "recall_memory":     recall,
}

def execute_tool(tool_name: str, tool_input: dict) -> str:
    """Execute a tool and return result as string for LLM."""
    if tool_name not in DISPATCH:
        return json.dumps({"error": f"Unknown tool: {tool_name}"})
    try:
        result = DISPATCH[tool_name](**tool_input)
        return json.dumps(result, indent=2) if isinstance(result, dict) else str(result)
    except Exception as e:
        return json.dumps({"error": str(e)})
```

---

## 5. Phase 2 — AI Agent Loop

The heart of the transformation. ~120 lines.

### `agent/loop.py`

```python
"""
BBHunter AI Agent Loop.
LLM decides what tools to call, iterates until task complete.
"""
import json
from providers.anthropic import call_claude
from tools.registry import TOOLS
from tools.executor import execute_tool
from agent.context import build_system_prompt
from memory.db import save_message, load_history


def run_agent(user_message: str, session_id: str, verbose: bool = True) -> str:
    """
    Run the agent loop for a single user message.
    Iterates: LLM → tool call → result → LLM → ... → final response
    """
    history = load_history(session_id)
    history.append({"role": "user", "content": user_message})
    save_message(session_id, "user", user_message)

    max_iterations = 20
    iteration = 0

    while iteration < max_iterations:
        iteration += 1

        # Call LLM with tools
        response = call_claude(
            system=build_system_prompt(),
            messages=history,
            tools=TOOLS
        )

        # Check if LLM wants to use a tool
        if response["stop_reason"] == "tool_use":
            assistant_message = {"role": "assistant", "content": response["content"]}
            history.append(assistant_message)

            # Process each tool call in the response
            tool_results = []
            for block in response["content"]:
                if block["type"] == "tool_use":
                    tool_name = block["name"]
                    tool_input = block["input"]
                    tool_use_id = block["id"]

                    if verbose:
                        print(f"\n🔧 [{tool_name}] {json.dumps(tool_input)}")

                    # Execute the tool
                    result = execute_tool(tool_name, tool_input)

                    if verbose:
                        # Show a preview of the result
                        preview = result[:200] + "..." if len(result) > 200 else result
                        print(f"   ✓ Result: {preview}")

                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": tool_use_id,
                        "content": result
                    })

            # Add tool results back to history
            history.append({"role": "user", "content": tool_results})

        else:
            # LLM has a final answer — extract text
            final = ""
            for block in response["content"]:
                if block.get("type") == "text":
                    final += block["text"]

            save_message(session_id, "assistant", final)
            return final

    return "Max iterations reached. Please try a more specific request."
```

### `agent/context.py`

```python
"""System prompt that defines BBHunter AI's personality and behavior."""

def build_system_prompt() -> str:
    return """You are BBHunter AI — an expert bug bounty hunter and security researcher assistant.

You have access to these tools:
- recon: Enumerate subdomains for a domain
- scan: Scan a URL for security vulnerabilities  
- generate_payloads: Generate attack payloads by vulnerability type
- write_report: Generate a professional bug bounty report
- recall_memory: Query past hunt sessions and findings

## Your Workflow

When given a target domain:
1. Run recon → enumerate subdomains
2. Identify live, interesting subdomains (admin panels, APIs, dev environments)
3. Run scan on high-value targets
4. Prioritize findings by severity: CRITICAL > HIGH > MEDIUM > LOW
5. Suggest relevant payloads based on findings
6. Offer to generate a report

## Rules

- ALWAYS think step by step before calling tools
- ALWAYS explain what you found in plain English after each tool call
- NEVER scan targets the user doesn't have explicit permission to test
- ALWAYS warn about rate limiting on aggressive configurations
- Be concise but thorough in findings summaries
- When findings are CRITICAL, highlight them prominently

## Output Style

- Use emojis for status: 🔍 scanning, ✅ found, ⚠️ warning, 🚨 critical, 📄 report
- Bold important findings
- Give actionable next steps after each phase

You have memory of all past hunts in this session and previous sessions."""
```

---

## 6. Phase 3 — Session Memory

### `memory/db.py`

```python
"""
SQLite-based memory for hunt sessions, findings, and message history.
"""
import sqlite3
import json
import os
from datetime import datetime

DB_PATH = os.path.expanduser("~/.bbhunter/memory.db")

def get_conn():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_conn()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS sessions (
            id TEXT PRIMARY KEY,
            created_at TEXT,
            target TEXT
        );
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT,
            role TEXT,
            content TEXT,
            timestamp TEXT
        );
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id TEXT,
            target TEXT,
            severity TEXT,
            vuln_type TEXT,
            description TEXT,
            timestamp TEXT
        );
    """)
    conn.commit()
    conn.close()

def save_message(session_id: str, role: str, content: str):
    init_db()
    conn = get_conn()
    conn.execute(
        "INSERT INTO messages (session_id, role, content, timestamp) VALUES (?, ?, ?, ?)",
        (session_id, role, content, datetime.now().isoformat())
    )
    conn.commit()
    conn.close()

def load_history(session_id: str) -> list:
    init_db()
    conn = get_conn()
    rows = conn.execute(
        "SELECT role, content FROM messages WHERE session_id = ? ORDER BY id",
        (session_id,)
    ).fetchall()
    conn.close()
    return [{"role": r["role"], "content": r["content"]} for r in rows]

def recall(query: str) -> dict:
    """Called by LLM to query memory."""
    init_db()
    conn = get_conn()
    findings = conn.execute(
        "SELECT * FROM findings ORDER BY timestamp DESC LIMIT 20"
    ).fetchall()
    sessions = conn.execute(
        "SELECT * FROM sessions ORDER BY created_at DESC LIMIT 10"
    ).fetchall()
    conn.close()
    return {
        "recent_findings": [dict(f) for f in findings],
        "recent_sessions": [dict(s) for s in sessions],
        "query": query
    }
```

---

## 7. Phase 4 — Telegram Bot

### `channels/telegram.py`

```python
"""
Telegram bot gateway for BBHunter AI.
Requires: pip install python-telegram-bot
"""
import os
import asyncio
import uuid
from telegram import Update
from telegram.ext import ApplicationBuilder, MessageHandler, CommandHandler, filters, ContextTypes
from agent.loop import run_agent

ALLOWED_USERS = []  # Fill with your Telegram user ID(s)

async def handle_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = str(update.effective_user.id)

    # Security: only allow configured users
    if ALLOWED_USERS and user_id not in ALLOWED_USERS:
        await update.message.reply_text("⛔ Unauthorized.")
        return

    user_input = update.message.text
    session_id = f"telegram_{user_id}"

    await update.message.reply_text("🤖 Processing...")

    try:
        response = run_agent(user_input, session_id, verbose=False)
        # Telegram has 4096 char limit — chunk if needed
        if len(response) > 4096:
            for i in range(0, len(response), 4096):
                await update.message.reply_text(response[i:i+4096])
        else:
            await update.message.reply_text(response)
    except Exception as e:
        await update.message.reply_text(f"❌ Error: {str(e)}")

async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "🎯 *BBHunter AI* ready!\n\n"
        "Send me a target domain or ask me anything about bug bounty hunting.\n\n"
        "Examples:\n"
        "• `Hunt example.com`\n"
        "• `Scan https://api.example.com`\n"
        "• `Generate XSS payloads`\n"
        "• `Show my last findings`",
        parse_mode="Markdown"
    )

def run_telegram_bot(token: str):
    app = ApplicationBuilder().token(token).build()
    app.add_handler(CommandHandler("start", start_command))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, handle_message))
    print("🤖 BBHunter Telegram bot started...")
    app.run_polling()
```

---

## 8. Phase 5 — Cron Scheduler

### `cron/scheduler.py`

```python
"""
Schedule recurring hunts using cron expressions.
Stores jobs in SQLite, runs in background thread.
"""
import json
import sqlite3
import os
import threading
import time
from datetime import datetime

DB_PATH = os.path.expanduser("~/.bbhunter/memory.db")

def init_cron_table():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS cron_jobs (
            id TEXT PRIMARY KEY,
            name TEXT,
            message TEXT,
            cron_expr TEXT,
            last_run TEXT,
            enabled INTEGER DEFAULT 1
        )
    """)
    conn.commit()
    conn.close()

def add_job(name: str, message: str, cron_expr: str):
    import uuid
    init_cron_table()
    job_id = str(uuid.uuid4())[:8]
    conn = sqlite3.connect(DB_PATH)
    conn.execute(
        "INSERT INTO cron_jobs (id, name, message, cron_expr) VALUES (?, ?, ?, ?)",
        (job_id, name, message, cron_expr)
    )
    conn.commit()
    conn.close()
    print(f"✅ Job '{name}' scheduled: {cron_expr}")
    return job_id

def list_jobs():
    init_cron_table()
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute("SELECT * FROM cron_jobs WHERE enabled=1").fetchall()
    conn.close()
    return rows
```

---

## 9. Phase 6 — Entry Point Refactor (`bbhunter.py`)

This is the key change. Modify the top of your existing `bbhunter.py` to detect agent mode vs legacy mode.

```python
#!/usr/bin/env python3
"""
BBHunter v2.0 — AI-Centered Bug Bounty Tool
Usage:
  python bbhunter.py              → AI Agent mode (interactive)
  python bbhunter.py --telegram   → Telegram bot mode
  python bbhunter.py recon -d ... → Legacy CLI mode (backward compatible)
"""
import sys
import os
import uuid

def main():
    args = sys.argv[1:]

    # ── Telegram bot mode ──────────────────────────────────────
    if args and args[0] == "--telegram":
        from config.config import load_config
        from channels.telegram import run_telegram_bot
        cfg = load_config()
        token = cfg.get("telegram", {}).get("token") or os.environ.get("TELEGRAM_BOT_TOKEN")
        if not token:
            print("❌ No Telegram token found. Set in ~/.bbhunter/config.json or TELEGRAM_BOT_TOKEN env var.")
            sys.exit(1)
        run_telegram_bot(token)

    # ── Agent mode: no args OR -i / --interactive ──────────────
    elif not args or args[0] in ("-i", "--interactive", "agent"):
        _run_interactive_agent()

    # ── Legacy CLI mode: known commands ───────────────────────
    else:
        _run_legacy_cli(args)


def _run_interactive_agent():
    """Spawn interactive AI agent in terminal."""
    from agent.loop import run_agent

    session_id = str(uuid.uuid4())[:8]

    print("""
  ██████╗ ██████╗ ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗
  ██╔══██╗██╔══██╗██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
  ██████╔╝██████╔╝███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
  ██╔══██╗██╔══██╗██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
  ██████╔╝██████╔╝██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
  ╚═════╝ ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝

  BBHunter AI v2.0  |  Session: {session_id}
  Type your target or question. 'exit' to quit, 'new' for a new session.
""".format(session_id=session_id))

    while True:
        try:
            user_input = input("\n🎯 You: ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\n\n👋 Happy hunting!")
            break

        if not user_input:
            continue
        if user_input.lower() == "exit":
            print("👋 Happy hunting!")
            break
        if user_input.lower() == "new":
            import uuid
            session_id = str(uuid.uuid4())[:8]
            print(f"🔄 New session: {session_id}")
            continue

        print()
        try:
            response = run_agent(user_input, session_id, verbose=True)
            print(f"\n🤖 BBHunter AI:\n{response}")
        except Exception as e:
            print(f"❌ Error: {e}")


def _run_legacy_cli(args):
    """Run original CLI commands for backward compatibility."""
    # Re-insert args and call original main logic
    # Your existing argparse/click code goes here unchanged
    from your_existing_cli_parser import legacy_main
    legacy_main(args)


if __name__ == "__main__":
    main()
```

---

## 10. System Prompt

The system prompt is the most important part — it defines how the AI hunts.

```
You are BBHunter AI — an expert bug bounty hunter with 10 years of experience.

## Identity
- You think like a real hacker: methodical, creative, persistent
- You know every trick: subdomain takeover, CORS misconfig, SSRF chains, JWT flaws
- You understand business impact and can write CVSS scores from memory

## Tools at your disposal
| Tool              | When to use                                      |
|-------------------|--------------------------------------------------|
| recon             | First step on any new domain                     |
| scan              | On each interesting subdomain                    |
| generate_payloads | When scan finds a vulnerability class            |
| write_report      | User confirms a finding or asks for report       |
| recall_memory     | User references past hunts or asks "what did I find on X" |

## Hunt Strategy
1. Start broad (recon the whole domain)
2. Focus on high-value subdomains: admin, api, dev, staging, internal
3. Scan each target methodically
4. Chain findings: e.g. CORS + XSS = credential theft
5. Always consider: what's the business impact?

## Response Format
- 🔍 When starting a scan
- ✅ When finding something benign
- ⚠️  For MEDIUM/LOW findings
- 🚨 For HIGH/CRITICAL findings
- 📄 When generating reports
- 💡 For recommendations

## Ethics
Always remind the user that scanning requires explicit written permission.
Never assist with unauthorized access or illegal activity.
```

---

## 11. Configuration

### `~/.bbhunter/config.json`

```json
{
  "providers": {
    "anthropic": {
      "api_key": "sk-ant-...",
      "model": "claude-3-5-haiku-20241022",
      "max_tokens": 4096
    },
    "openai": {
      "api_key": "sk-...",
      "model": "gpt-4o-mini"
    }
  },
  "agent": {
    "default_provider": "anthropic",
    "max_iterations": 20,
    "verbose": true
  },
  "telegram": {
    "token": "YOUR_BOT_TOKEN",
    "allowed_users": ["YOUR_USER_ID"]
  },
  "output_dir": "~/.bbhunter/outputs"
}
```

### `config/config.py`

```python
import json
import os

CONFIG_PATH = os.path.expanduser("~/.bbhunter/config.json")

def load_config() -> dict:
    if not os.path.exists(CONFIG_PATH):
        return {}
    with open(CONFIG_PATH) as f:
        return json.load(f)

def get_api_key(provider: str) -> str:
    cfg = load_config()
    key = cfg.get("providers", {}).get(provider, {}).get("api_key")
    if not key:
        env_map = {"anthropic": "ANTHROPIC_API_KEY", "openai": "OPENAI_API_KEY"}
        key = os.environ.get(env_map.get(provider, ""))
    return key or ""
```

---

## 12. Example Interactions

### Terminal

```
🎯 You: hunt example.com

🔧 [recon] {"domain": "example.com"}
   ✓ Result: {"subdomains": [{"fqdn": "admin.example.com", ...}, ...]}

🤖 BBHunter AI:
🔍 Recon complete on example.com — found 14 live subdomains.

Interesting targets:
• admin.example.com (200 OK, nginx)
• api.example.com (200 OK)
• dev.example.com (200 OK) ← staging/dev envs are gold

Running scans on the top 3...

🔧 [scan] {"url": "https://admin.example.com"}
   ✓ Result: {"findings": [{"severity": "HIGH", "type": "cors_misconfiguration"}, ...]}

🚨 CRITICAL findings on admin.example.com:
• CORS misconfiguration — wildcard origin with credentials allowed
• Missing HSTS header
• Exposed path: /actuator/env (Spring Boot — leaks env vars!)

Want me to generate CORS/XSS payloads or write the report?
```

### Telegram

```
You: /start
Bot: 🎯 BBHunter AI ready! Send me a target...

You: scan https://api.example.com
Bot: 🔍 Scanning api.example.com...
     ⚠️ 2 MEDIUM findings:
     • Missing Content-Security-Policy
     • Cookie without SameSite flag
     
     No CRITICAL issues found. Want payloads or a report?

You: show my last findings
Bot: 📋 Recent findings:
     • admin.example.com — CORS CRITICAL (2 days ago)
     • api.example.com — Missing headers MEDIUM (just now)
```

---

## 13. Migration Checklist

```
Phase 1 — Tool Registry
[ ] Create tools/registry.py        (TOOLS list with JSON schemas)
[ ] Create tools/executor.py        (dispatch LLM calls to modules)
[ ] Create tools/recon_tool.py      (wrap existing recon logic)
[ ] Create tools/scan_tool.py       (wrap existing scan logic)
[ ] Create tools/payload_tool.py    (wrap existing payload logic)
[ ] Create tools/report_tool.py     (wrap existing report logic)

Phase 2 — Agent Loop
[ ] Create agent/loop.py            (LLM ↔ tool iteration)
[ ] Create agent/context.py         (system prompt)
[ ] Create providers/anthropic.py   (Claude API with tool use)

Phase 3 — Memory
[ ] Create memory/db.py             (SQLite init, save, load, recall)
[ ] Test: session history persists across restarts

Phase 4 — Entry Point
[ ] Modify bbhunter.py              (detect agent vs legacy mode)
[ ] Test: python bbhunter.py        → spawns agent
[ ] Test: python bbhunter.py recon  → still works as before

Phase 5 — Telegram (optional)
[ ] pip install python-telegram-bot
[ ] Create channels/telegram.py
[ ] Test: python bbhunter.py --telegram

Phase 6 — Cron (optional)
[ ] Create cron/scheduler.py
[ ] Test: schedule a weekly scan
```

---

## 14. Roadmap Integration

Your existing `bbhunter_roadmap.md` features map perfectly to the AI architecture:

| Roadmap Feature | AI Integration |
|---|---|
| crt.sh integration | New `recon` tool parameter |
| Shodan API | New `shodan_search` tool |
| Nuclei template support | New `nuclei_scan` tool |
| WAF detection | Add to `scan` tool output |
| JS analysis | New `js_analyze` tool |
| CVE matching | Agent chains `scan` → CVE lookup |
| HTML reports | Add `report` tool output format |
| Distributed scanning | Sub-agents spawned by planner |

Each new capability = one new tool added to `tools/registry.py`. The AI agent automatically learns to use it from the description. No prompt changes needed.

---

## Summary

| What changes | What stays the same |
|---|---|
| `python bbhunter.py` → spawns AI agent | All CLI flags still work |
| LLM decides scan sequence | All module logic unchanged |
| Natural language input | JSON output formats preserved |
| Memory of past hunts | `bbhunter_output/` still written |
| Telegram/cron support | Pure stdlib for core modules |

**The biggest shift:** you stop writing `bbhunter.py recon -d example.com` and start writing `hunt example.com` — and the AI figures out the rest.
