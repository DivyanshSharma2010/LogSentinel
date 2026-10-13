import os
import re
from pygrok import Grok
from saving import save_as_json

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_PATH = os.path.join(BASE_DIR, "data", "OpenSSH_2k.log")

if not os.path.exists(LOG_PATH):
    raise SystemExit(f"FILE NOT FOUND: {LOG_PATH}")

count = 0
def SSH_parsing(log):

    BASE_PATTERN = (
        r"%{SYSLOGTIMESTAMP:date_timestamp} "
        r"%{HOSTNAME:hostname} "
        r"%{WORD:process}\[%{POSINT:pid}\]: "
        r"%{GREEDYDATA:message}"
    )
    
    grok = Grok(BASE_PATTERN)
    result = grok.match(log)

    ip_pattern = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
    ip_add = re.search(ip_pattern, result["message"])
    result["ip"] = ip_add.group() if ip_add else None
    
    if result is None:
        count += 1
        print(f"Error log: {log}")
        return {
            "parsed": False,
            "event_type": "unknown",
            "raw": log,
            "ip": None,
        }

parsed_logs = []
with open(LOG_PATH, encoding="utf-8", errors="replace") as f:
    for line_number, log in enumerate(f, start=1):
        x = SSH_parsing(log)
        parsed_logs.append(x)

save_as_json(parsed_logs, "SSH_parsedlogs")
