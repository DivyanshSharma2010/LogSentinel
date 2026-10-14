import os
import re
from pygrok import Grok
from saving import save_as_json

# Getting the relative path of Data
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_PATH = os.path.join(BASE_DIR, "data", "OpenSSH_2k.log")

if not os.path.exists(LOG_PATH):
    raise SystemExit(f"FILE NOT FOUND: {LOG_PATH}")

SYSLOG_HEADER_PATTERN = (
        r"%{SYSLOGTIMESTAMP:date_timestamp} "
        r"%{HOSTNAME:hostname} "
        r"%{WORD:process}\[%{POSINT:pid}\]: "
        r"%{GREEDYDATA:message}"
    )

GROK = Grok(SYSLOG_HEADER_PATTERN)
IP_PATTERN = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")

def parse_ssh_line(log):
    
    result = GROK.match(log)
    if result is None:
        return None
    
    ip_add = re.search(IP_PATTERN, result["message"])
    result["ip"] = ip_add.group() if ip_add else None
    
    if result is None:
        print(f"Error log: {log}")
        return {
            "parsed": False,
            "event_type": "unknown",
            "raw": log,
            "ip": None,
        }

    return {
        "parsed": True,
        "event_type": "unclassified",
        **result
    }

    
# Appending the Parsed Logs
parsed_logs = []
failed_count = 0 # Number of Failed Unparsed Logs 
with open(LOG_PATH, encoding="utf-8", errors="replace") as f:
    for line_number, log in enumerate(f, start=1):
        entry = parse_ssh_line(log)
        if entry is not None:
            parsed_logs.append(entry)
        else:
            failed_count += 1
            print(f"Unparsed line {line_number}: {log.strip()}")


save_as_json(parsed_logs, "SSH_parsedlogs")
print(failed_count)