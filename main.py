from fastapi import FastAPI
from pydantic import BaseModel
import anthropic

app = FastAPI()

client = anthropic.Anthropic(
    api_key="NTHROPIC_API_KEY"
)

class AnalyzeInput(BaseModel):
    error: str
    logs: str = ""
    os: str = ""
    version: str = ""

SYSTEM_PROMPT = """
You are a senior PostgreSQL production engineer.

Analyze the incident like you are on-call.

Rules:
- Be practical, not theoretical
- Focus on the fastest safe resolution
- Use logs as evidence
- If unsure, say so clearly
- Do not use markdown headings
- Return plain text only

Return EXACTLY in this format:

Severity:
Root cause:
Evidence:
Immediate actions:
Commands:
Risks:
"""

@app.get("/")
def root():
    return {"status": "ok"}

@app.post("/analyze")
def analyze(data: AnalyzeInput):
    prompt = f"""
Error:
{data.error}

Logs:
{data.logs}

Environment:
OS: {data.os}
PostgreSQL version: {data.version}
"""

    response = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=900,
        system=SYSTEM_PROMPT,
        messages=[
            {"role": "user", "content": prompt}
        ]
    )

    result_text = ""
    for block in response.content:
        if block.type == "text":
            result_text += block.text

    return {"result": result_text}