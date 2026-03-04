#!/usr/bin/env python3

import html
import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
import requests

#all paths, which woops
LOG_FILE = Path("/home/host/Beehavior-inator/parsed/summary.jsonl")
STATE_FILE = Path("/home/host/Beehavior-inator/llm/honeypot_state.json")
TEMPLATE_FILE = Path("/home/host/Beehavior-inator/llm/template.html")
OUTPUT_FILE = Path("/home/host/Beehavior-inator/site/report.html")
ARCHIVE_DIR = Path("/home/host/Beehavior-inator/site/archive")
OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "honeybot"
MAX_EVENTS = 3
LLM_TIMEOUT = 1800  #in seconds, adjust to longer as need be, same for max events

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
log = logging.getLogger(__name__)

#Handles open, read, and offset persistence for the JSONL event log
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

# Prompt is lean now — context, schema, and rules are baked into the honeybot Modelfile
_PROMPT_TEMPLATE = """\
Analyze the following honeypot events and respond per your instructions.

Events:
{events_json}
"""

def extract_and_fix_json(raw: str) -> dict:
    """Attempt to parse JSON, with a repair pass if it fails."""
    # strip markdown fencing just in case
    raw = re.sub(r"```json|```", "", raw).strip()

    try:
        return json.loads(raw)
    except json.JSONDecodeError as e:
        log.warning("Initial JSON parse failed (%s), attempting repair...", e)

    # replace the html_additions value with a json.dumps-safe version
    fixed = re.sub(
        r'("html_additions"\s*:\s*)"(.*?)"(\s*[},])',
        lambda m: m.group(1) + json.dumps(m.group(2)) + m.group(3),
        raw,
        flags=re.DOTALL
    )

    return json.loads(fixed)

def query_llm(events: list[dict]):
    """Send events to the local Ollama instance and parse the JSON response."""
    prompt = _PROMPT_TEMPLATE.format(events_json=json.dumps(events, indent=2))

    try:
        resp = requests.post(
            OLLAMA_URL,
            json={"model": MODEL, "prompt": prompt, "stream": False, "options": {"temperature": 0.4}},
            timeout=LLM_TIMEOUT,
        )
        resp.raise_for_status()
        raw = resp.json()["response"]
        log.debug("LLM raw output:\n%s", raw)
        return extract_and_fix_json(raw)

    except requests.RequestException as exc:
        log.error("LLM request failed: %s", exc)
    except (json.JSONDecodeError, KeyError) as exc:
        log.error("LLM response parse error: %s", exc)
        log.error("Raw output was:\n%s", raw if 'raw' in dir() else "unavailable")

    return None

#Help from claude to build out rendering ips
def _render_ip_blocks(grouped: list[dict]):
    blocks: list[str] = []
    for group in grouped:
        indicators_html = ""
        for item in group.get("indicators", []):
            if isinstance(item, dict):
                text = " &mdash; ".join(f"{html.escape(str(k))}: {html.escape(str(v))}" for k, v in item.items())
            else:
                text = html.escape(str(item))
            indicators_html += f"<li>{text}</li>"
        blocks.append(
            f'<div class="ip-block">'
            f'<div class="ip-addr">{html.escape(group.get("ip", "Unknown"))}</div>'
            f'<p class="ip-meta">'
            f'{html.escape(group.get("country_of_origin", ""))} &mdash; '
            f'{html.escape(group.get("time_occurred", ""))}'
            f'</p>'
            f'<p class="ip-desc">{html.escape(group.get("description", ""))}</p>'
            f'<ul class="indicators">{indicators_html}</ul>'
            f'</div>'
        )
    return "\n".join(blocks)

def render_report(analysis: dict):
    """Load the template and substitute all placeholders."""
    template = TEMPLATE_FILE.read_text(encoding="utf-8")

    replacements = {
        "{{TIMESTAMP}}":        datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        "{{SUMMARY}}":          html.escape(analysis.get("summary", "")),
        "{{GROUPED_ACTIVITY}}": _render_ip_blocks(analysis.get("grouped_activity", [])),
        "{{EXPANSION_NOTES}}":  html.escape(analysis.get("expansion_notes", "")),
        "{{HTML_ADDITIONS}}":   html.escape(analysis.get("html_additions", "")),
    }

    for placeholder, value in replacements.items():
        template = template.replace(placeholder, value)

    return template

def main() -> None:
    reader = LogReader(LOG_FILE)
    start_offset = reader.offset
    events = reader.read_new()

    if not events:
        log.info("No new events.")
        return

    log.info("Analysing %d event(s)...", len(events))

    analysis = query_llm(events)
    if not analysis:
        log.warning("LLM returned nothing — report not updated.")
        reader.offset = start_offset
        return

    # rotate archive slots 1-24, dropping oldest
    ARCHIVE_DIR.mkdir(parents=True, exist_ok=True)
    for i in range(23, 0, -1):
        src = ARCHIVE_DIR / f"report_{i:02d}.html"
        if src.exists():
            src.rename(ARCHIVE_DIR / f"report_{i+1:02d}.html")
    if OUTPUT_FILE.exists():
        OUTPUT_FILE.rename(ARCHIVE_DIR / "report_01.html")

    # atomic write: temp file + rename avoids corrupt half-written report
    tmp = OUTPUT_FILE.with_suffix(".tmp")
    try:
        tmp.write_text(render_report(analysis), encoding="utf-8")
        tmp.chmod(0o644)
        tmp.replace(OUTPUT_FILE)
    except Exception:
        tmp.unlink(missing_ok=True)
        reader.offset = start_offset
        raise

    reader._save_state()
    log.info("Dashboard updated successfully.")

if __name__ == "__main__":
    main()
