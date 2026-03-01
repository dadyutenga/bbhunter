"""SQLite memory backend for BBHunter agent mode."""

import json
import os
import sqlite3
from datetime import datetime

DB_PATH = os.path.expanduser("~/.bbhunter/memory.db")


def get_conn():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_conn()
    conn.executescript(
        """
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
            is_json INTEGER DEFAULT 0,
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
        """
    )
    conn.commit()
    conn.close()


def _ensure_session(conn, session_id: str):
    row = conn.execute("SELECT id FROM sessions WHERE id = ?", (session_id,)).fetchone()
    if not row:
        conn.execute(
            "INSERT INTO sessions (id, created_at, target) VALUES (?, ?, ?)",
            (session_id, datetime.utcnow().isoformat(), ""),
        )


def save_message(session_id: str, role: str, content):
    init_db()
    conn = get_conn()
    _ensure_session(conn, session_id)

    is_json = 0
    value = content
    if not isinstance(content, str):
        is_json = 1
        value = json.dumps(content)

    conn.execute(
        "INSERT INTO messages (session_id, role, content, is_json, timestamp) VALUES (?, ?, ?, ?, ?)",
        (session_id, role, value, is_json, datetime.utcnow().isoformat()),
    )
    conn.commit()
    conn.close()


def load_history(session_id: str) -> list:
    init_db()
    conn = get_conn()
    rows = conn.execute(
        "SELECT role, content, is_json FROM messages WHERE session_id = ? ORDER BY id ASC",
        (session_id,),
    ).fetchall()
    conn.close()

    history = []
    for row in rows:
        content = row["content"]
        if row["is_json"]:
            try:
                content = json.loads(content)
            except Exception:
                pass
        history.append({"role": row["role"], "content": content})
    return history


def save_finding(
    session_id: str,
    target: str,
    severity: str,
    vuln_type: str,
    description: str,
):
    init_db()
    conn = get_conn()
    _ensure_session(conn, session_id)
    conn.execute(
        """
        INSERT INTO findings (session_id, target, severity, vuln_type, description, timestamp)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            session_id,
            target,
            severity,
            vuln_type,
            description,
            datetime.utcnow().isoformat(),
        ),
    )
    conn.commit()
    conn.close()


def recall(query: str) -> dict:
    """
    Query recent findings/sessions.
    If query contains a keyword, perform LIKE matching against target and description.
    """
    init_db()
    conn = get_conn()

    q = (query or "").strip()
    if q:
        like = f"%{q}%"
        findings = conn.execute(
            """
            SELECT * FROM findings
            WHERE target LIKE ? OR vuln_type LIKE ? OR description LIKE ?
            ORDER BY timestamp DESC
            LIMIT 20
            """,
            (like, like, like),
        ).fetchall()
        sessions = conn.execute(
            """
            SELECT * FROM sessions
            WHERE id LIKE ? OR target LIKE ?
            ORDER BY created_at DESC
            LIMIT 10
            """,
            (like, like),
        ).fetchall()
    else:
        findings = conn.execute(
            "SELECT * FROM findings ORDER BY timestamp DESC LIMIT 20"
        ).fetchall()
        sessions = conn.execute(
            "SELECT * FROM sessions ORDER BY created_at DESC LIMIT 10"
        ).fetchall()

    conn.close()
    return {
        "query": q,
        "recent_findings": [dict(f) for f in findings],
        "recent_sessions": [dict(s) for s in sessions],
    }

