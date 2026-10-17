import re
from pygrok import Grok
from datetime import datetime

SYSLOG_HEADER_PATTERN = (
    r"%{SYSLOGTIMESTAMP:date_timestamp} "
    r"%{HOSTNAME:hostname} "
    r"%{WORD:process}(?:\[%{POSINT:pid}\])?: "
    r"%{GREEDYDATA:message}"
)

APACHE_HEADER_PATTERN = (
    r"%{IPORHOST:clientip} "
    r"%{USER:ident} "
    r"%{USER:auth} "
    r"\[%{HTTPDATE:timestamp}\] "
    r"\"(?:%{WORD:verb} %{NOTSPACE:request}(?: HTTP/%{NUMBER:httpversion})?|%{DATA:rawrequest})\" "
    r"%{NUMBER:response} "
    r"(?:%{NUMBER:bytes}|-)"
    r"(?: %{QS:referrer} %{QS:agent})?"
)

SYSLOG_GROK = Grok(SYSLOG_HEADER_PATTERN)
APACHE_GROK = Grok(APACHE_HEADER_PATTERN)

IP_PATTERN = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
UFW_KV_PATTERN = re.compile(r"(\b[A-Za-z_]+)=([^\s]+)")

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


# --- TIMESTAMP NORMALIZATION ---
def normalize_timestamp(raw_ts, fmt="%b %d %H:%M:%S", default_year=2026):
    """Adds a default year to syslog timestamp and normalizes to YYYY-MM-DD HH:MM:SS"""
    try:
        clean_ts = " ".join(raw_ts.split())
        dt = datetime.strptime(f"{default_year} {clean_ts}", f"%Y {fmt}")
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        return raw_ts


def normalize_apache_timestamp(raw_ts):
    """Converts '15/Oct/2026:20:15:02 +0000' -> '2026-10-15 20:15:02'"""
    try:
        clean_ts = raw_ts.split()[0]
        dt = datetime.strptime(clean_ts, "%d/%b/%Y:%H:%M:%S")
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        return raw_ts


# --- LOG PARSERS ---
def parse_ssh_line(log):
    result = SYSLOG_GROK.match(log)
    if result is None:
        return None

    result["date_timestamp"] = normalize_timestamp(result["date_timestamp"])
    msg = result.get("message", "")
    msg_lower = msg.lower()

    # Check if it's a UFW Firewall log inside Syslog
    if "[UFW" in msg:
        kv_pairs = dict(UFW_KV_PATTERN.findall(msg))
        return {
            "parsed": True,
            "log_type": "firewall",
            "event_type": "ufw_block" if "BLOCK" in msg else "ufw_allow",
            "date_timestamp": result["date_timestamp"],
            "process": result.get("process", "kernel"),
            "ip": kv_pairs.get("SRC"),
            "dst_port": kv_pairs.get("DPT"),
            "proto": kv_pairs.get("PROTO"),
            "hostname": result.get("hostname"),
        }

    # Otherwise handle it as SSH / Auth Log
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
        "ip": extracted_ip,
        "username": extracted_username,
        **result,
    }


def parse_web_access_line(log):
    result = APACHE_GROK.match(log)
    if result is None:
        return None

    status = int(result.get("response", 0))
    request_path = result.get("request") or result.get("rawrequest") or ""

    if status in (401, 403):
        event_type = "web_auth_failure"
    elif "../" in request_path or "UNION SELECT" in request_path.upper():
        event_type = "web_attack_payload"
    else:
        event_type = "web_access"

    return {
        "parsed": True,
        "log_type": "web_access",
        "event_type": event_type,
        "date_timestamp": normalize_apache_timestamp(result.get("timestamp")),
        "process": "http_server",
        "ip": result.get("clientip"),
        "http_method": result.get("verb"),
        "request_url": request_path,
        "status_code": status,
        "user_agent": result.get("agent"),
    }


def parse_log_line(log):
    for parser in (parse_ssh_line, parse_web_access_line):
        entry = parser(log)
        if entry is not None:
            return entry
    return None