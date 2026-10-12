import os
import re
import pygrok
from collections import Counter

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_PATH = os.path.join(BASE_DIR, "data", "OpenSSH_2k.log")

if not os.path.exists(LOG_PATH):
    raise SystemExit(f"FILE NOT FOUND: {LOG_PATH}")


def SSH_parsing():
    test = "Dec 10 06:55:46 LabSZ sshd[24200]: reverse mapping checking getaddrinfo for ns.marryaldkfaczcz.com [173.234.31.186] failed - POSSIBLE BREAK-IN ATTEMPT!"

    HEADER = re.comple(
        r"^(?P<month>\w{3})\s+(?P<day>\w{2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
        r"(?P<host>\S+)\s+sshd\[(?P<pid>\d+)\]:\s+(?P<message>.*)$"
        )

    MESSAGE_PATTERNS = [
        ("ip_add", re.compile(r"\b\[\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\]\b"))
        ("user", re.compile(r"\buser=(\w+)\b"))
    ]
        

with open(LOG_PATH, encoding="utf-8", errors="replace") as f:
    for line_number, line in enumerate(f, start=1):
        pass


            