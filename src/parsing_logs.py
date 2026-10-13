import os
import re
from pygrok import Grok
from collections import Counter

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_PATH = os.path.join(BASE_DIR, "data", "OpenSSH_2k.log")

if not os.path.exists(LOG_PATH):
    raise SystemExit(f"FILE NOT FOUND: {LOG_PATH}")


def SSH_parsing():
    test = "Dec 10 06:55:46 LabSZ sshd[24200]: reverse mapping checking getaddrinfo for ns.marryaldkfaczcz.com [173.234.31.186] failed - POSSIBLE BREAK-IN ATTEMPT!"

    pattern = r"%{SYSLOGTIMESTAMP:date_timestamp} %{HOSTNAME:hostname} %{WORD:process}\[%{POSINT:pid}\]: %{GREEDYDATA:message}"
    match = Grok(pattern)
    result = match.match(test)
    ip_pattern = re.compile(r"\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]")
    ip_add = re.search(ip_pattern, result["message"])
    result["ip"] = ip_add
    print(result)

        

with open(LOG_PATH, encoding="utf-8", errors="replace") as f:
    for line_number, line in enumerate(f, start=1):
        pass

SSH_parsing()
            