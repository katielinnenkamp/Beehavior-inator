#!/usr/bin/env python3
import json
import re
import sys
from pathlib import Path

# Matches the header line:
# 2026-02-09T09:24:46.600308 - From 127.0.0.1:49198:
RE_ENTRY = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T[0-9:.]+)\s+-\s+From\s+(?P<ip>[\d.]+):(?P<port>\d+):\s*$"
)

# Matches request line: GET /path HTTP/1.1
RE_REQ = re.compile(r"^(?P<meth>[A-Z]+)\s+(?P<path>\S+)\s+HTTP/\d\.\d\s*$")

def parse_log(text: str):
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        m = RE_ENTRY.match(lines[i].strip())
        if not m:
            i += 1
            continue

        evt = {
            "ts": m.group("ts"),
            "src_ip": m.group("ip"),
            "src_port": int(m.group("port")),
            "method": None,
            "path": None,
            "host": None,
            "user_agent": None,
            "referer": None,
            "content_type": None,
            "content_length": None,
        }

        i += 1
        # Request line
        if i < len(lines):
            rm = RE_REQ.match(lines[i].strip())
            if rm:
                evt["method"] = rm.group("meth")
                evt["path"] = rm.group("path")
        i += 1

        # Headers until blank line
        while i < len(lines) and lines[i].strip() != "":
            line = lines[i]
            if ":" in line:
                k, v = line.split(":", 1)
                k = k.strip().lower()
                v = v.strip()
                if k == "host":
                    evt["host"] = v
                elif k == "user-agent":
                    evt["user_agent"] = v[:200]
                elif k == "referer":
                    evt["referer"] = v[:300]
                elif k == "content-type":
                    evt["content_type"] = v[:100]
                elif k == "content-length":
                    try:
                        evt["content_length"] = int(v)
                    except ValueError:
                        pass
            i += 1

        # Skip blank line
        while i < len(lines) and lines[i].strip() == "":
            i += 1

        # Skip the "Sent:"
        if i < len(lines) and lines[i].strip().lower() == "sent:":
            i += 1
            while i < len(lines) and not RE_ENTRY.match(lines[i].strip()):
                i += 1

        yield evt

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 summarize_logs.py <logfile_or_logs_dir> [out.jsonl]")
        sys.exit(1)

    inp = Path(sys.argv[1])
    out = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("events.jsonl")

    # Gather log files
    files = []
    if inp.is_dir():
        files = sorted([p for p in inp.rglob("*") if p.is_file()])
    else:
        files = [inp]

    events = []
    for f in files:
        try:
            text = f.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        for evt in parse_log(text):
            # drop empty placeholders
            if evt["method"] and evt["path"]:
                events.append(evt)

    # Write JSONL
    with out.open("w", encoding="utf-8") as w:
        for evt in events:
            w.write(json.dumps(evt) + "\n")

    print(f"Wrote {len(events)} events to {out}")

if __name__ == "__main__":
    main()
