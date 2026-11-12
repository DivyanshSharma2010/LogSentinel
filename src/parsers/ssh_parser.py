import re
from parsers.common import parse_syslog_header, normalize_timestamp

IP_PATTERN = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")

USER_PATTERN_SSH = re.compile(
    r"(?:"
    r"(?:invalid|authenticating)\s+user(?:=|\s+)|"
    r"(?:failed|accepted)\s+\S+\s+for\s+(?:invalid\s+user\s+)?|"
    r"(?:session\s+(?:opened|closed)\s+\S+\s+for\s+)"
    r")"
    r"(?!unknown\b|invalid\b)"
    r"(?P<username>[A-Za-z0-9_.\-\$]+)",
    re.IGNORECASE
)


def parse_ssh_line(log):
    """Parses an SSH/auth syslog line. Returns None if the line isn't SSH,
    including when it's actually a UFW firewall line on the same syslog format."""

    header = parse_syslog_header(log)
    if header is None:
        return None

    msg = header.get("message", "")

    # UFW firewall lines use this same syslog format, let firewall_parser handle those
    if "[UFW" in msg:
        return None

    msg_lower = msg.lower()

    ip_match = IP_PATTERN.search(msg)
    extracted_ip = ip_match.group() if ip_match else None

    username_match = USER_PATTERN_SSH.search(msg)
    extracted_username = username_match.group("username") if username_match else None

    if "failed password" in msg_lower:
        event_type = "failed_login"
    elif "invalid user" in msg_lower:
        event_type = "invalid_user"
    elif "authentication failure" in msg_lower:
        event_type = "authentication_failure"
    elif "possible break-in attempt" in msg_lower:
        event_type = "possible break-in attempt"
    elif "accepted password" in msg_lower or "accepted publickey" in msg_lower:
        event_type = "accepted_login"
    else:
        event_type = "unclassified"

    return {
        "parsed": True,
        "log_type": "ssh",
        "event_type": event_type,
        "date_timestamp": normalize_timestamp(header.get("date_timestamp")),
        "hostname": header.get("hostname"),
        "process": header.get("process"),
        "pid": header.get("pid"),
        "message": msg,
        "ip": extracted_ip,
        "username": extracted_username,
    }