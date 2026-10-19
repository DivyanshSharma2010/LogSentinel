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
        dst_port = kv_pairs.get("DPT")
        proto = kv_pairs.get("PROTO")

        event_type = "ufw_block"
        if "ALLOW" in msg:
            event_type = "ufw_allow"
        elif proto == "2" or kv_pairs.get("DST") == "224.0.0.1":
            event_type = "ufw_block_multicast"
        elif dst_port == "443" and ("ACK FIN" in msg or "RST" in msg):
            event_type = "ufw_block_https_noise"
        elif proto == "UDP" and dst_port and dst_port.isdigit() and 33434 <= int(dst_port) <= 33534:
            event_type = "ufw_block_traceroute"
        elif dst_port in {"5060", "389"}:
            event_type = "ufw_block_voip_ldap"
        elif dst_port in {"22", "3389", "5900", "21", "2121"}:
            event_type = "ufw_block_remote_admin"
        elif dst_port in {"1433", "3306", "5432", "6379", "27017", "11211"}:
            event_type = "ufw_block_database"
        elif dst_port in {"23", "2323"}:
            event_type = "ufw_block_telnet_iot"
        elif dst_port in {"2375", "2376", "6443", "9200"}:
            event_type = "ufw_block_critical_api"
        
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

    request_path = result.get("request") or result.get("rawrequest") or ""
    request_lower = request_path.lower()
    status = int(result.get("response", 0))

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


def parse_log_line(log):
    for parser in (parse_ssh_line, parse_web_access_line):
        entry = parser(log)
        if entry is not None:
            return entry
    return None