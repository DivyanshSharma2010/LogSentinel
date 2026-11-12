import re
from datetime import datetime

# --- SYSLOG HEADER PATTERN ---
# Shared by SSH logs and UFW firewall logs, since both ride on the same
# syslog format, e.g: "Dec 10 06:55:46 LabSZ sshd[24200]: Failed password..."

SYSLOG_REGEX = re.compile(
    r"^(?P<date_timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<hostname>\S+)\s+"
    r"(?P<process>\w+)(?:\[(?P<pid>\d+)\])?:\s*"
    r"(?P<message>.*)$"
)


def parse_syslog_header(log):
    """Pulls the timestamp, hostname, process and message out of a syslog line.
    Returns None if the line doesn't look like syslog at all."""

    match = SYSLOG_REGEX.match(log)
    if match is None:
        return None
    return match.groupdict()


def normalize_timestamp(raw_ts, fmt="%b %d %H:%M:%S", default_year=2026):
    """Adds a default year to a syslog timestamp and normalizes it to YYYY-MM-DD HH:MM:SS"""
    try:
        clean_ts = " ".join(raw_ts.split())
        dt = datetime.strptime(f"{default_year} {clean_ts}", f"%Y {fmt}")
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        return raw_ts