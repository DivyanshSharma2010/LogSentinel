import re
from datetime import datetime

# --- WEB ACCESS PATTERN ---
# Example line: '91.99.72.15 - - [22/Jan/2019:04:05:25 +0330] "GET /index.html HTTP/1.1" 200 1024 "-" "Mozilla/5.0"'

WEB_ACCESS_REGEX = re.compile(
    r'^(?P<clientip>\S+)\s+\S+\s+\S+\s+'
    r'\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?:(?P<verb>[A-Z]+)\s+(?P<request>\S+)(?:\s+HTTP/(?P<httpversion>[\d.]+))?|(?P<rawrequest>[^"]*))"\s+'
    r'(?P<response>\d+)\s+'
    r'(?P<bytes>\d+|-)'
    r'(?:\s+"(?P<referrer>[^"]*)"\s+"(?P<agent>[^"]*)")?'
)


def parse_web_header(log):
    """Pulls the IP, timestamp, request and status out of a web access line.
    Returns None if the line doesn't look like a web access log at all."""

    match = WEB_ACCESS_REGEX.match(log)
    if match is None:
        return None
    return match.groupdict()


def normalize_apache_timestamp(raw_ts):
    """Converts '15/Oct/2026:20:15:02 +0000' -> '2026-10-15 20:15:02'"""
    try:
        clean_ts = raw_ts.split()[0]
        dt = datetime.strptime(clean_ts, "%d/%b/%Y:%H:%M:%S")
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        return raw_ts


def parse_web_access_line(log):
    """Parses a web (Apache/Nginx style) access log line."""

    result = parse_web_header(log)
    if result is None:
        return None

    request_path = result.get("request") or result.get("rawrequest") or ""
    request_lower = request_path.lower()
    status = int(result.get("response") or 0)

    # Critical Payloads
    if any(cmd in request_lower for cmd in [";ls", "|cat", "&&", "/bin/sh", "cmd.exe"]):
        event_type = "web_cmd_injection"
    elif any(sql in request_lower for sql in ["union select", "or 1=1", "information_schema", "sleep("]):
        event_type = "web_sql_injection"
    elif any(pt in request_lower for pt in ["../", "..%2f", "/etc/passwd", "boot.ini"]):
        event_type = "web_path_traversal"
    elif any(xss in request_lower for xss in ["<script", "%3cscript", "javascript:", "onerror="]):
        event_type = "web_xss_attempt"

    # Scanners & Probes
    elif any(probe in request_lower for probe in [".env", ".git", "wp-admin", "phpmyadmin", "config", ".bak"]):
        event_type = "web_sensitive_probe"

    # Status Code Behaviors
    elif status >= 500:
        event_type = "web_server_error"
    elif status in (401, 403):
        event_type = "web_auth_failure"
    elif status == 404:
        event_type = "web_not_found"

    # Safe / Noise Traffic
    elif request_lower == "/site/ping" or (result.get("verb") == "HEAD" and request_lower == "/"):
        event_type = "web_health_check"
    elif "/login" in request_lower or "/customer/register" in request_lower or "/signin" in request_lower:
        event_type = "web_account_endpoint"
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