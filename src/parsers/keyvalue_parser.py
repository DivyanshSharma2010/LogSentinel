import re

# "2026-10-02 09:14:22 ERROR 192.168.1.15 user=alice action=login status=failed attempts=2"

KV_HEADER_REGEX = re.compile(
    r"^(?P<date_timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<level>[A-Z]+)\s+"
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+"
    r"(?P<rest>.*)$"
)

# Matches both "key=value" and "key:value" pairs inside the rest of the line
KV_PAIR_REGEX = re.compile(r"([A-Za-z_]+)\s*[:=]\s*(\S+)")

def parse_keyvalue_line(log):
    """Parses a generic key=value application log line.
    Returns None if the line doesn't match this format."""

    match = KV_HEADER_REGEX.match(log)
    if match is None:
        return None

    header = match.groupdict()
    kv_pairs = dict(KV_PAIR_REGEX.findall(header["rest"]))

    username = kv_pairs.get("user") or kv_pairs.get("username")
    action = kv_pairs.get("action")
    status = kv_pairs.get("status")

    if action and status:
        event_type = f"{action}_{status}"
    elif action:
        event_type = action
    else:
        event_type = header["level"].lower()

    return {
        "parsed": True,
        "log_type": "app_keyvalue",
        "event_type": event_type,
        "date_timestamp": header["date_timestamp"],
        "process": "app",
        "ip": header["ip"],
        "username": username,
    }