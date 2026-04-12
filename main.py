import os
import re
import time
from typing import Dict

from dotenv import load_dotenv
import anthropic
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

load_dotenv()

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

FREE_ANALYSES_PER_DAY = int(os.getenv("FREE_ANALYSES_PER_DAY", "5"))
usage_store: Dict[str, Dict[str, int]] = {}


class AnalyzeInput(BaseModel):
    error: str
    logs: str = ""
    os: str = ""
    version: str = ""


BASE_RULES = """
You are a senior PostgreSQL production engineer responding during an active incident.

Your job is to give the fastest safe diagnosis.

Core principles:
- Be concise and practical
- Prefer standard PostgreSQL and Linux commands only
- Do not invent tools, utilities, or commands
- Use only evidence that appears in the pasted input
- If uncertain, say so clearly
- Prefer safer fixes before risky ones
- Keep each section short
- Use plain text only
- Do not use markdown headings
- Do not use code fences
- When mixing SQL and shell commands, label them clearly as "In psql:" and "In shell:"
- If a fix requires editing pg_hba.conf or postgresql.conf, label it as "In pg_hba.conf add:" or "In postgresql.conf set:"
- Do not present config lines as shell commands
- Evidence must be 1-2 short sentences maximum
- Risks must be short bullet-like lines, not a long paragraph
- Root cause should be short and direct
- Checks should contain only the most useful next checks
- Verification should be short and practical
- Prefer 2-4 lines per section when possible

Safety rules:
- Do not recommend aggressive actions early unless the evidence strongly supports them
- Treat restart, terminate, drop subscription, drop slot, chown -R, and broad config changes as last-resort actions unless clearly justified
- For connection issues without direct service logs, prefer "The most likely causes are..." wording
- For lock/deadlock issues, prefer application/query-order fixes before backend cancel/terminate
- For performance issues, prefer diagnosis before expensive or broad changes
- If a command is risky, place it after safer alternatives and reflect that risk in Risks
- Always return all required sections, even if some are brief

Formatting rules:
- You MUST follow the exact format strictly
- Each section MUST start with the exact label below
- Use the exact labels and keep the same order
- Do not rename sections
- Do not omit sections

Return EXACTLY in this format:

Severity:
Root cause:
Evidence:
Checks:
Fix commands:
Verification:
Risks:
"""

PG_HBA_GUIDANCE = """
Incident-specific guidance:
- This is a pg_hba / authentication / SSL matching problem
- Explain whether the problem is likely missing rule, wrong rule order, or SSL mismatch
- Prefer /32 over broad CIDRs unless the evidence suggests a range is needed
- Never suggest trust authentication for production
- When suggesting a pg_hba.conf change, present it as a config line, not as a shell command
- In Verification, prefer pg_hba_file_rules and one concrete log check if logs are relevant
"""

REPLICATION_GUIDANCE = """
Incident-specific guidance:
- This is a logical or physical replication problem
- Focus on the smallest safe fix first
- Prefer commands that confirm publication, subscription, slot, sender/receiver, and replay state
- Avoid speculative tuning advice unless strongly supported by the input
- Do not jump straight to dropping and recreating the subscription unless safer recovery steps fail
"""

REPLICA_IDENTITY_GUIDANCE = """
Incident-specific guidance:
- This is a replica identity / logical replication update-delete problem
- Focus on whether the table has a primary key or needs REPLICA IDENTITY FULL
- Prefer primary key or suitable unique index over REPLICA IDENTITY FULL
- Mention WAL overhead risk briefly if REPLICA IDENTITY FULL is suggested
"""

CONNECTION_GUIDANCE = """
Incident-specific guidance:
- This is a connection / reachability / startup problem
- If logs are limited, use "The most likely causes are..." instead of overcommitting
- Prefer checks for service status, listening socket, startup failure, authentication, TLS, or firewall only if supported by the input
- Do not recommend chown -R unless ownership/permission evidence is explicit
- Do not recommend listen_addresses changes unless there is evidence the server is listening only locally or not on the expected interface
"""

LOCKS_GUIDANCE = """
Incident-specific guidance:
- This is a locks / blocking / waiting problem
- Prefer commands for pg_stat_activity, blocking chains, wait events, and lock relationships
- Emphasize application/query ordering fixes before cancel/terminate suggestions
- If suggesting pg_cancel_backend, present it as a last resort after confirming the blocker
- Always include Risks for lock/deadlock cases
- When using cardinality(pg_blocking_pids(...)), call cardinality(...) directly
"""

PERFORMANCE_GUIDANCE = """
Incident-specific guidance:
- This is a performance / slow query / load problem
- Do not over-assert root cause from a timeout log alone
- Prefer wording like "The most likely causes are..." unless the plan/logs prove the cause
- Prefer EXPLAIN before EXPLAIN (ANALYZE, BUFFERS) on potentially expensive queries
- Avoid suggesting SELECT count(*) on a very large table unless it is clearly necessary
- Do not suggest SET statement_timeout = '0'; prefer a bounded session-only increase if needed
- Prefer diagnosis before config changes
- Avoid broad global timeout changes unless broader workload evidence supports them
"""

GENERIC_GUIDANCE = """
Incident-specific guidance:
- Keep output tight and operational
- Do not over-explain
- Only suggest commands that directly help narrow or fix the observed issue
"""


def get_anthropic_client():
    api_key = os.getenv("ANTHROPIC_API_KEY")
    if not api_key:
        raise RuntimeError("ANTHROPIC_API_KEY is not set")
    return anthropic.Anthropic(api_key=api_key)


def client_ip(request: Request) -> str:
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def get_usage(ip: str) -> Dict[str, int]:
    now = int(time.time())
    record = usage_store.get(ip)

    if not record or now >= record["reset_at"]:
        record = {"count": 0, "reset_at": now + 86400}
        usage_store[ip] = record

    return record


def detect_incident_type(error: str, logs: str) -> str:
    text = f"{error}\n{logs}".lower()

    if "no pg_hba.conf entry" in text or "pg_hba" in text:
        return "pg_hba"
    if "replica identity" in text:
        return "replica_identity"
    if (
        "logical replication" in text
        or "subscription" in text
        or "publication" in text
        or "replication slot" in text
        or "pg_stat_subscription" in text
    ):
        return "replication"
    if (
        "deadlock detected" in text
        or "could not obtain lock" in text
        or ("waiting for" in text and "lock" in text)
        or "blocked by" in text
        or "lock timeout" in text
    ):
        return "locks"
    if (
        "slow query" in text
        or "statement timeout" in text
        or "canceling statement due to statement timeout" in text
        or ("cpu" in text and "high" in text)
        or "load average" in text
        or "temporary file" in text
        or ("duration:" in text and "statement:" in text)
    ):
        return "performance"
    if (
        "connection refused" in text
        or "timeout expired" in text
        or "could not connect" in text
        or "the database system is starting up" in text
        or "remaining connection slots are reserved" in text
        or "too many connections" in text
    ):
        return "connection"

    return "generic"


def build_system_prompt(incident_type: str) -> str:
    mapping = {
        "pg_hba": PG_HBA_GUIDANCE,
        "replication": REPLICATION_GUIDANCE,
        "replica_identity": REPLICA_IDENTITY_GUIDANCE,
        "connection": CONNECTION_GUIDANCE,
        "locks": LOCKS_GUIDANCE,
        "performance": PERFORMANCE_GUIDANCE,
        "generic": GENERIC_GUIDANCE,
    }
    return BASE_RULES + "\n" + mapping.get(incident_type, GENERIC_GUIDANCE)


def parse_sections(text: str) -> Dict[str, str]:
    result = {
        "severity": "",
        "root_cause": "",
        "evidence": "",
        "checks": "",
        "fix_commands": "",
        "verification": "",
        "risks": "",
    }

    if not text:
        return result

    pattern = r"(Severity|Root cause|Evidence|Checks|Fix commands|Verification|Risks)\s*:?"
    parts = re.split(pattern, text)

    for i in range(1, len(parts), 2):
        key = parts[i].strip()
        value = parts[i + 1].strip() if i + 1 < len(parts) else ""

        if key == "Severity":
            result["severity"] = value
        elif key == "Root cause":
            result["root_cause"] = value
        elif key == "Evidence":
            result["evidence"] = value
        elif key == "Checks":
            result["checks"] = value
        elif key == "Fix commands":
            result["fix_commands"] = value
        elif key == "Verification":
            result["verification"] = value
        elif key == "Risks":
            result["risks"] = value

    return result


def shorten_evidence(text: str) -> str:
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    return "\n".join(lines[:2]) if lines else "Limited evidence was provided in the pasted error or logs."


def shorten_risks(text: str) -> str:
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    cleaned = []
    for line in lines[:4]:
        cleaned.append(line if line.startswith("-") else f"- {line}")
    return "\n".join(cleaned)


def trim_block(text: str, max_lines: int = 8) -> str:
    lines = [line.rstrip() for line in text.splitlines() if line.strip()]
    if len(lines) <= max_lines:
        return "\n".join(lines)

    trimmed = lines[:max_lines]
    last = trimmed[-1]
    if len(last) > 160:
        trimmed[-1] = last[:160].rsplit(" ", 1)[0] + "..."
    return "\n".join(trimmed)


def trim_root_cause(text: str) -> str:
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if not lines:
        return "A precise root cause could not be determined from the provided input."
    joined = " ".join(lines)
    sentences = re.split(r'(?<=[.!?])\s+', joined)
    return " ".join(sentences[:2]).strip()


def sanitize_aggressive_fixes(text: str, incident_type: str) -> str:
    if not text:
        return text

    patterns = [
        r"(?im)^.*chown\s+-R.*$",
        r"(?im)^.*DROP SUBSCRIPTION.*$",
        r"(?im)^.*pg_drop_replication_slot.*$",
        r"(?im)^.*pg_terminate_backend.*$",
    ]

    cleaned = text
    for pattern in patterns:
        cleaned = re.sub(pattern, "", cleaned)

    if incident_type == "connection":
        cleaned = re.sub(r"(?im)^.*listen_addresses\s*=.*$", "", cleaned)

    if incident_type == "performance":
        cleaned = re.sub(r"(?im)^.*SET\s+statement_timeout\s*=\s*'0'.*$", "", cleaned)
        cleaned = re.sub(r"(?im)^.*SELECT\s+count\(\*\)\s+FROM.*$", "", cleaned)

    return "\n".join(line for line in cleaned.splitlines() if line.strip())


def ensure_risks(incident_type: str, risks: str) -> str:
    text = (risks or "").strip()

    if text:
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        cleaned = []
        for line in lines[:4]:
            if not line.startswith("-"):
                line = "- " + line
            cleaned.append(line)

        if cleaned:
            return "\n".join(cleaned)

    if incident_type == "pg_hba":
        return (
            "- Allowing non-SSL may violate security policy\n"
            "- pg_hba rule order matters (first match wins)\n"
            "- Avoid using wide CIDR ranges in production"
        )

    if incident_type == "replication":
        return (
            "- Recreating subscriptions may trigger a full resync\n"
            "- Dropping slots too early can increase recovery time\n"
            "- Fix root cause before resuming replication"
        )

    if incident_type == "replica_identity":
        return (
            "- REPLICA IDENTITY FULL increases WAL volume\n"
            "- Adding a primary key may require locking\n"
            "- Existing duplicates can block PK creation"
        )

    if incident_type == "connection":
        return (
            "- Restarting may hide the root cause\n"
            "- Opening access too broadly increases exposure\n"
            "- Always verify service state before config changes"
        )

    if incident_type == "locks":
        return (
            "- Deadlocks will recur until query order is fixed\n"
            "- Canceling the wrong backend can abort useful work\n"
            "- Prefer application-level fixes first"
        )

    if incident_type == "performance":
        return (
            "- Index creation may impact performance temporarily\n"
            "- Increasing timeouts can hide real issues\n"
            "- Heavy EXPLAIN ANALYZE can impact production"
        )

    return (
        "- Review commands before running in production\n"
        "- Validate changes in staging when possible\n"
        "- Apply minimal changes first"
    )


def build_fallback_structured(result_text: str, incident_type: str) -> Dict[str, str]:
    titles = {
        "pg_hba": "Authentication / pg_hba issue detected.",
        "replication": "Replication issue detected.",
        "replica_identity": "Replica identity issue detected.",
        "connection": "Connection issue detected.",
        "locks": "Locking or deadlock issue detected.",
        "performance": "Performance or timeout issue detected.",
        "generic": "Incident detected, but the response format was incomplete.",
    }
    return {
        "severity": "Unknown",
        "root_cause": titles.get(incident_type, titles["generic"]),
        "evidence": "The AI returned a response, but it did not follow the expected section format.",
        "checks": "",
        "fix_commands": result_text.strip(),
        "verification": "",
        "risks": ensure_risks(incident_type, ""),
    }


def normalize_result(parsed: Dict[str, str], incident_type: str, raw_result: str) -> Dict[str, str]:
    if raw_result.strip() and not any(v.strip() for v in parsed.values()):
        safe = build_fallback_structured(raw_result, incident_type)
        if not safe["risks"].strip():
            safe["risks"] = "- Review commands before production use."
        return safe

    safe = dict(parsed)

    if not safe["severity"]:
        safe["severity"] = "Medium"

    if not safe["root_cause"]:
        safe["root_cause"] = trim_root_cause(raw_result) if raw_result.strip() else "A precise root cause could not be determined from the provided input."

    if not safe["evidence"]:
        safe["evidence"] = "Limited evidence was provided in the pasted error or logs."

    if not safe["checks"]:
        if incident_type == "pg_hba":
            safe["checks"] = (
                "In psql:\n"
                "SHOW hba_file;\n"
                "SHOW ssl;\n\n"
                "In shell:\n"
                "grep -n \"app\\|prod\\|10.1.2.3\" /var/lib/pgsql/*/data/pg_hba.conf"
            )
        elif incident_type == "replica_identity":
            safe["checks"] = (
                "In psql:\n"
                "\\d+ your_table\n"
                "SELECT relreplident FROM pg_class WHERE relname = 'your_table';"
            )
        elif incident_type == "replication":
            safe["checks"] = (
                "In psql:\n"
                "SELECT * FROM pg_stat_replication;\n"
                "SELECT * FROM pg_replication_slots;\n"
                "SELECT * FROM pg_stat_subscription;"
            )
        elif incident_type == "locks":
            safe["checks"] = (
                "In psql:\n"
                "SELECT pid, usename, wait_event_type, wait_event, state, query FROM pg_stat_activity WHERE state <> 'idle';"
            )
        elif incident_type == "performance":
            safe["checks"] = (
                "In psql:\n"
                "SHOW statement_timeout;\n"
                "EXPLAIN SELECT * FROM big_table ORDER BY created_at;\n"
                "SELECT indexname, indexdef FROM pg_indexes WHERE tablename = 'big_table';"
            )
        else:
            safe["checks"] = (
                "In shell:\n"
                "journalctl -u postgresql -n 100 --no-pager\n\n"
                "In psql:\n"
                "SELECT version();"
            )

    if not safe["fix_commands"]:
        safe["fix_commands"] = raw_result.strip() or "No safe fix command could be generated from the provided input alone."

    safe["fix_commands"] = sanitize_aggressive_fixes(safe["fix_commands"], incident_type)
    if not safe["fix_commands"].strip():
        safe["fix_commands"] = "No low-risk fix command could be generated from the provided input alone."

    if not safe["verification"]:
        safe["verification"] = "Retry the failing connection or query.\nRecheck PostgreSQL logs for new errors."

    safe["root_cause"] = trim_root_cause(safe["root_cause"])
    safe["evidence"] = shorten_evidence(safe["evidence"])
    safe["risks"] = ensure_risks(incident_type, safe.get("risks", ""))

    if not safe["risks"].strip():
        safe["risks"] = "- Review commands before production use."

    safe["checks"] = trim_block(safe["checks"], 8)
    safe["fix_commands"] = trim_block(safe["fix_commands"], 8)
    safe["verification"] = trim_block(safe["verification"], 6)

    return safe


def html_file_response(path: str) -> FileResponse:
    response = FileResponse(path)
    response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/")
def home():
    return html_file_response("index.html")


@app.get("/privacy")
def privacy():
    return html_file_response("privacy.html")


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/quota")
def quota(request: Request):
    ip = client_ip(request)
    record = get_usage(ip)
    remaining = max(FREE_ANALYSES_PER_DAY - record["count"], 0)
    return {
        "free_total": FREE_ANALYSES_PER_DAY,
        "used": record["count"],
        "remaining": remaining,
        "resets_in_seconds": max(record["reset_at"] - int(time.time()), 0),
    }


@app.post("/analyze")
def analyze(data: AnalyzeInput, request: Request):
    if not data.error.strip():
        return JSONResponse(status_code=400, content={"error": "Please paste a PostgreSQL error first."})

    ip = client_ip(request)
    record = get_usage(ip)
    remaining = max(FREE_ANALYSES_PER_DAY - record["count"], 0)

    if remaining <= 0:
        return JSONResponse(
            status_code=429,
            content={
                "error": "You used all free beta analyses for today.",
                "remaining": 0,
                "free_total": FREE_ANALYSES_PER_DAY,
            },
        )

    incident_type = detect_incident_type(data.error, data.logs)
    system_prompt = build_system_prompt(incident_type)

    prompt = f"""
Incident type hint:
{incident_type}

Error:
{data.error}

Logs:
{data.logs or "Not provided"}

Environment:
OS: {data.os or "Not provided"}
PostgreSQL version: {data.version or "Not provided"}
"""

    try:
        client = get_anthropic_client()
        response = client.messages.create(
            model="claude-sonnet-4-6",
            max_tokens=560,
            system=system_prompt,
            messages=[{"role": "user", "content": prompt}],
        )

        result_text = ""
        for block in response.content:
            if block.type == "text":
                result_text += block.text

        result_text = result_text.strip()
        parsed = parse_sections(result_text)
        structured = normalize_result(parsed, incident_type, result_text)

        record["count"] += 1
        remaining = max(FREE_ANALYSES_PER_DAY - record["count"], 0)

        return {
            "result": result_text,
            "structured": structured,
            "incident_type": incident_type,
            "remaining": remaining,
            "free_total": FREE_ANALYSES_PER_DAY,
        }

    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"error": f"The analysis service is temporarily unavailable: {str(e)}"},
        )