"""Tool schemas exposed to the LLM tool-calling API."""

TOOLS = [
    {
        "name": "recon",
        "description": "Enumerate subdomains for a target domain and identify live hosts.",
        "input_schema": {
            "type": "object",
            "properties": {
                "domain": {
                    "type": "string",
                    "description": "Target domain (example.com), no scheme.",
                },
                "threads": {
                    "type": "integer",
                    "description": "Thread count, default 50, max 200.",
                },
            },
            "required": ["domain"],
        },
    },
    {
        "name": "scan",
        "description": "Scan a URL for common vulnerabilities and misconfigurations.",
        "input_schema": {
            "type": "object",
            "properties": {
                "url": {
                    "type": "string",
                    "description": "Full URL (https://target.example).",
                }
            },
            "required": ["url"],
        },
    },
    {
        "name": "generate_payloads",
        "description": "Generate payloads for a vulnerability type.",
        "input_schema": {
            "type": "object",
            "properties": {
                "vuln_type": {
                    "type": "string",
                    "enum": [
                        "xss",
                        "sqli",
                        "ssrf",
                        "lfi",
                        "ssti",
                        "xxe",
                        "open_redirect",
                    ],
                },
                "category": {
                    "type": "string",
                    "enum": ["basic", "bypass", "blind", "all"],
                    "description": "Payload category. Defaults to all.",
                },
            },
            "required": ["vuln_type"],
        },
    },
    {
        "name": "write_report",
        "description": "Write a markdown bug bounty report from findings.",
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "vuln_type": {
                    "type": "string",
                    "enum": ["xss", "sqli", "ssrf", "lfi", "idor", "cors", "ssti", "xxe", "other"],
                },
                "severity": {
                    "type": "string",
                    "enum": ["critical", "high", "medium", "low"],
                },
                "summary": {"type": "string"},
                "findings": {"type": "array", "items": {"type": "object"}},
            },
            "required": ["target", "vuln_type", "severity", "summary"],
        },
    },
    {
        "name": "recall_memory",
        "description": "Recall past session messages and findings.",
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Query text like 'findings for example.com'.",
                }
            },
            "required": ["query"],
        },
    },
]

