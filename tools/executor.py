"""Dispatch LLM tool calls to BBHunter tool wrappers."""

import json

from memory.db import recall
from tools.payload_tool import run_payloads
from tools.recon_tool import run_recon
from tools.report_tool import run_report
from tools.scan_tool import run_scan

DISPATCH = {
    "recon": run_recon,
    "scan": run_scan,
    "generate_payloads": run_payloads,
    "write_report": run_report,
    "recall_memory": recall,
}


def execute_tool(tool_name: str, tool_input: dict) -> str:
    """Execute a tool and normalize the return value as JSON text."""
    if tool_name not in DISPATCH:
        return json.dumps({"error": f"Unknown tool: {tool_name}"})

    try:
        result = DISPATCH[tool_name](**tool_input)
    except TypeError as ex:
        return json.dumps({"error": f"Invalid args for {tool_name}: {ex}"})
    except Exception as ex:
        return json.dumps({"error": str(ex)})

    if isinstance(result, (dict, list)):
        return json.dumps(result, indent=2)
    return str(result)

