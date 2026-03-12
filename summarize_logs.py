#!/usr/bin/env python3
import json
import re
from pathlib import Path

# --- Absolute paths based on script location  ---
BASE_DIR = Path(__file__).resolve().parent
LOG_FILE = BASE_DIR / "logs" / "server-http-8080.log"
PARSED_DIR = BASE_DIR / "parsed"
OFFSET_FILE = PARSED_DIR / ".offset"
CARRY_FILE = PARSED_DIR / ".carry"
OUTPUT_FILE = PARSED_DIR / "summary.jsonl"

# 2026-02-09T09:24:46.600308 - From 127.0.0.1:49198:
RE_ENTRY = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T[0-9:.]+)\s+-\s+From\s+(?P<ip>[\d.]+):(?P<port>\d+):\s*$"
)
# GET /path HTTP/1.1
RE_REQ = re.compile(r"^(?P<meth>[A-Z]+)\s+(?P<path>\S+)\s+HTTP/\d\.\d\s*$")


def load_offset() -> int:
    try:
        if not OFFSET_FILE.exists():
            return 0
        s = OFFSET_FILE.read_text(encoding="utf-8", errors="ignore").strip()
        return int(s) if s else 0
    except Exception:
        return 0

def save_offset(offset: int) -> None:
    OFFSET_FILE.write_text(str(offset), encoding="utf-8")


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
            "method": None,
            "path": None,
            "host": None,
            "user_agent": None,
            "referer": None,
            "content_type": None,
            "content_length": None,
            "post_body": None,
            "cf_connecting_ip": None,
            "cf_country": None,
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
                elif k == "cf-connecting-ip":
                    evt["cf_connecting_ip"] = v
                    evt["src_ip"] = v
                elif k == "cf-ipcountry":
                    evt["cf_country"] = v
                elif k == "x-forwarded-for" and not evt["cf_connecting_ip"]:
                    evt["src_ip"] = v.split(",")[0].strip()
                elif k == "x-real-ip" and not evt["cf_connecting_ip"]:
                    evt["src_ip"] = v.strip()
            i += 1

        # Skip blank lines
        while i < len(lines) and lines[i].strip() == "":
            i += 1

        # Captures POST (for any payload)
        post_lines = []
        if i < len(lines) and lines[i].strip().lower() != "sent:":
            while i < len(lines) and lines[i].strip().lower() != "sent:" and not RE_ENTRY.match(lines[i].strip()):
                post_lines.append(lines[i])
                i += 1
        if post_lines and evt["method"] == "POST":
            evt["post_body"] = "\n".join(post_lines).strip()[:2000]

        # Now skips rest of request till next entry
        if i < len(lines) and lines[i].strip().lower() == "sent:":
            i += 1
            while i < len(lines) and not RE_ENTRY.match(lines[i].strip()):
                i += 1

        yield evt


def main():
    PARSED_DIR.mkdir(parents=True, exist_ok=True)

    if not LOG_FILE.exists():
        print(f"[parser] Log file not found: {LOG_FILE}")
        return

    last_offset = load_offset()

    # Read new bytes using byte offsets
    with LOG_FILE.open("rb") as f:
        f.seek(last_offset)
        new_bytes = f.read()
        end_pos = f.tell()

    if not new_bytes:
        return

    carry_bytes = b""
    if CARRY_FILE.exists():
        try:
            carry_bytes = CARRY_FILE.read_bytes()
        except Exception:
            carry_bytes = b""

    combined = carry_bytes + new_bytes

    last_nl = combined.rfind(b"\n")
    if last_nl == -1:
        CARRY_FILE.write_bytes(combined)
        return

    parse_bytes = combined[: last_nl + 1]
    remainder = combined[last_nl + 1:]
    CARRY_FILE.write_bytes(remainder)

    text = parse_bytes.decode("utf-8", errors="ignore")

    new_events = []
    for evt in parse_log(text):
        if evt["method"] and evt["path"]:
            new_events.append(evt)

    # Advance offset by the number of bytes we consumed from *new_bytes*
    consumed_from_new = max(0, len(parse_bytes) - len(carry_bytes))
    save_offset(last_offset + consumed_from_new)

    if not new_events:
        return

    with OUTPUT_FILE.open("a", encoding="utf-8") as w:
        for evt in new_events:
            w.write(json.dumps(evt) + "\n")

    print(f"[parser] appended {len(new_events)} events to {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
