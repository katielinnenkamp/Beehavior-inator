#!/usr/bin/env python3
import json
import requests
import html
import re
from pathlib import Path

# ===== Configuration =====
LOG_FILE = Path("parsed/summary.jsonl")
STATE_FILE = Path("llm/honeypot_state.json")
LAST_GOOD_HTML = Path("site/report.html.bak")
OUTPUT_FILE = Path("site/report.html")
OLLAMA_CONNECT = "http://localhost:11434/api/generate"
MODEL = "qwen2.5"
MAX_EVENTS = 3

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
                    self.offset = f.tell()

                except json.JSONDecodeError:
                    self.offset = f.tell()
                    continue
        return events

#format, strips
def format_events(events):
    # Take the most recent MAX_EVENTS
    events = events[-MAX_EVENTS:]
    return "\n".join(json.dumps(e) for e in events)

#simple sanitization
def sanitize_logs(formatted_logs):
    return html.escape(formatted_logs)

def strip_scripts(html_content):
    html_content = re.sub(r"<script.*?>.*?</script>", "", html_content, flags=re.DOTALL | re.IGNORECASE)
    html_content = re.sub(r"on\w+\s*=", "", html_content, flags=re.IGNORECASE)
    return html_content

#ollama llm prompt, acts
def generate_html(events):
    formatted = format_events(events)
    safe_logs = sanitize_logs(formatted)
    
    prompt = f"""
You are a cybersecurity analyst.

Return ONLY valid JSON.
No markdown.
No explanation.
No commentary.

JSON FORMAT:

{{
  "timestamp_utc": "",
  "threat_level": "Low | Medium | High | Critical",
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
- Group events by source IP
- Identify scanning, credential stuffing, bots if present
- Keep explanations concise
- Ensure valid JSON only

Honeypot Events:
{safe_logs}
"""


    try:
        response = requests.post(
            OLLAMA_CONNECT,
            json={
                "model": MODEL,
                "prompt": prompt,
                "stream": False
            },
            timeout=540
        )
        if response.status_code == 200:
            if response.status_code == 200:
                raw = response.json()["response"]
                print("----- LLM RAW OUTPUT -----")
                print(raw)
                print("--------------------------")
            return raw
            #return response.json()["response"]
    except Exception as e:
        print("Ollama error:", e)
    return None

#main, takes log file, reads, prompts llm generates new html
def main():
    reader = LogReader(LOG_FILE)
    events = reader.read_new()

    #check for anything new
    if not events:
        print("No new events.")
        return

    print(f"Generating dashboard from {len(events)} new events...")
    htmlOut = generate_html(events)

    if htmlOut and "<html" in htmlOut.lower():
        htmlOut = strip_scripts(htmlOut)
        #sanitization
        csp = """<meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'none'; object-src 'none'; base-uri 'self'; frame-ancestors 'none';">"""
        htmlOut = htmlOut.replace("<head>", f"<head>{csp}")

        #backup
        if OUTPUT_FILE.exists():
            LAST_GOOD_HTML.write_text(OUTPUT_FILE.read_text())

        OUTPUT_FILE.write_text(htmlOut)
        reader._save_state()
        print("Dashboard updated.")
    else:
        print("LLM failed or returned invalid HTML.")
        if LAST_GOOD_HTML.exists():
            OUTPUT_FILE.write_text(LAST_GOOD_HTML.read_text())
            print("Restored last known good dashboard.")

if __name__ == "__main__":
    main()
