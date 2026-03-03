#!/usr/bin/env python3
import json
import requests
import html
from pathlib import Path
from datetime import datetime

# ===== Configuration =====
LOG_FILE = Path("/home/host/Beehavior-inator/parsed/summary.jsonl")
STATE_FILE = Path("/home/host/Beehavior-inator/llm/honeypot_state.json")
LAST_GOOD_HTML = Path("/home/host/Beehavior-inator/site/report.html.bak")
OUTPUT_FILE = Path("/home/host/Beehavior-inator/site/report.html")
OLLAMA_CONNECT = "http://localhost:11434/api/generate"
MODEL = "qwen2.5"
MAX_EVENTS = 10


# ===== Log Reader =====
class LogReader:
    def __init__(self, path):
        self.path = path
        self.offset = 0
        self._load_state()

    def _load_state(self):
        if STATE_FILE.exists():
            try:
                self.offset = json.loads(STATE_FILE.read_text()).get("offset", 0)
            except:
                self.offset = 0

    def _save_state(self):
        STATE_FILE.write_text(json.dumps({"offset": self.offset}))

    def read_new(self):
        if not self.path.exists():
            return []

        events = []
        with open(self.path, "r", errors="ignore") as f:
            f.seek(self.offset)
            while len(events) < MAX_EVENTS:
                line = f.readline()
                if not line:
                    break
                try:
                    events.append(json.loads(line.strip()))
                except json.JSONDecodeError:
                    pass
                self.offset = f.tell()

        return events


# ===== LLM JSON ANALYSIS =====
def generate_analysis(events):

    safe_logs = html.escape(json.dumps(events, indent=2))

    prompt = f"""
You are a cybersecurity analyst.

Return ONLY valid JSON.
No markdown.
No commentary.

FORMAT:

{{
  "summary": "",
  "grouped_activity": [
    {{
      "ip": "",
      "description": "",
      "indicators": []
    }}
  ],
  "overall_explanation": ""
}}

Rules:
- Group by IP
- Identify scanning or bot patterns
- Keep concise
- Valid JSON only

Events:
{safe_logs}
"""

    try:
        response = requests.post(
            OLLAMA_CONNECT,
            json={
                "model": MODEL,
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": 0.2
                }
            },
            timeout=540
        )

        if response.status_code == 200:
            raw = response.json()["response"]
            print("----- LLM RAW OUTPUT -----")
            print(raw)
            print("--------------------------")

            return json.loads(raw)

    except Exception as e:
        print("LLM error:", e)

    return None


# ===== HTML RENDERING (STATIC TEMPLATE) =====
def render_dashboard(data):

    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

    grouped_html = ""
    for group in data.get("grouped_activity", []):
        indicators = "".join(
            f"<li>{html.escape(i)}</li>"
            for i in group.get("indicators", [])
        )

        grouped_html += f"""
        <div class="ip-block">
            <h3>{html.escape(group.get("ip", "Unknown"))}</h3>
            <p>{html.escape(group.get("description", ""))}</p>
            <ul>{indicators}</ul>
        </div>
        """

    html_page = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Honeypot Threat Dashboard</title>
<meta http-equiv="Content-Security-Policy"
content="default-src 'self'; script-src 'none'; object-src 'none'; base-uri 'self'; frame-ancestors 'none';">
<link rel="stylesheet" href="/style.css">
</head>
<body>
<div class="container">

<h1>Honeypot Threat Dashboard</h1>

<div class="section">
<strong>Timestamp:</strong> {timestamp}
</div>

<div class="section">
<strong>Summary:</strong>
<p>{html.escape(data.get("summary", ""))}</p>
</div>

<div class="section">
<strong>Grouped Activity:</strong>
{grouped_html}
</div>

<div class="section">
<strong>Overall Explanation:</strong>
<p>{html.escape(data.get("overall_explanation", ""))}</p>
</div>

</div>
</body>
</html>
"""

    return html_page


# ===== MAIN =====
def main():
    reader = LogReader(LOG_FILE)
    events = reader.read_new()

    if not events:
        print("No new events.")
        return

    print(f"Analyzing {len(events)} events...")

    analysis = generate_analysis(events)

    if not analysis:
        print("LLM failed — restoring backup.")
        if LAST_GOOD_HTML.exists():
            OUTPUT_FILE.write_text(LAST_GOOD_HTML.read_text())
        return

    final_html = render_dashboard(analysis)

    if OUTPUT_FILE.exists():
        LAST_GOOD_HTML.write_text(OUTPUT_FILE.read_text())

    OUTPUT_FILE.write_text(final_html)
    OUTPUT_FILE.chmod(0o644)

    reader._save_state()

    print("Dashboard updated successfully.")


if __name__ == "__main__":
    main()
