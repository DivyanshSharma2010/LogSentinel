import os
import re
from pygrok import Grok
from datetime import datetime
from db import insert_events

# Getting the relative path of Data
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_PATH = os.path.join(BASE_DIR, "data", "OpenSSH_2k.log")
SOURCE_FILE = os.path.relpath(LOG_PATH, BASE_DIR)

if not os.path.exists(LOG_PATH):
    raise SystemExit(f"FILE NOT FOUND: {LOG_PATH}")

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

def normalize_timestamp(raw_ts, fmt = "%b %d %H:%M:%S", default_year = 2026):
    try: 
        clean_ts = " ".join(raw_ts.split())
        dt = datetime.strptime(f"{default_year} {clean_ts}", f"%Y {fmt}")
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        return raw_ts

def normalize_apache_timestamp(raw_ts):
    # Converts "15/Oct/2026:20:15:02 +0000" -> "2026-10-15 20:15:02"
    try:
        clean_ts = raw_ts.split()[0] # Strip timezone offset like +0000
        dt = datetime.strptime(clean_ts, "%d/%b/%Y:%H:%M:%S")
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        return raw_ts

def parse_ssh_line(log):
    
    result = SYSLOG_GROK.match(log)
    if result is None:
        return None

    result["date_timestamp"] = normalize_timestamp(result["date_timestamp"]) # Adding year to timestamp
    msg = result.get("message","")

    # To Check if it's a UFW Firewall log inside Syslog
    if "[UFW" in msg:
        kv_pairs = dict(UFW_KV_PATTERN.findall(msg))
        return {
            "parsed": True,
            "log_type": "firewall",
            "event_type": "ufw_block" if r"\bBLOCK" in msg else "usf_allow",
            "date_timestamp": result["date_timestamp"],
            "process": result.get("process", "kernel"),
            "ip": kv_pairs.get("SRC"),
            "dst_port": kv_pairs.get("DPT"),
            "proto": kv_pairs.get("PROTO"),
            "hostname": result.get("hostname"),
        }

    # Otherwise handle it as SSH / Auth Log
    ip_add = re.search(IP_PATTERN, msg)
    result["ip"] = ip_add.group() if ip_add else None

    if "Failed password" in msg:
        event_type = "failed_login"
    elif "Invalid user" in msg:
        event_type = "invalid_user"
    elif "Accepted password" in msg or "Accepted publickey" in msg:
        event_type = "accepted_login"
    else:
        event_type = "unclassified"

    return {
        "parsed": True,
        "log_type": "ssh",
        "event_type": event_type,
        "ip": ip_add,
        **result,
    }

def parse_web_access_line(log):
    test1 = '5.127.220.71 - - [26/Jan/2019:20:29:12 +0330] "GET /favicon.ico HTTP/1.1" 200 0 "-" "MobileSafari/604.1 CFNetwork/976 Darwin/18.2.0" "-"'
    test2 = '5.127.220.71 - - [26/Jan/2019:20:29:13 +0330] "GET /apple-touch-icon-120x120.png HTTP/1.1" 404 32420 "-" "MobileSafari/604.1 CFNetwork/976 Darwin/18.2.0" "-"'

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

if __name__ == "__main__":  

    LOG_DIR = os.path.join(BASE_DIR, "data")

    total_parsed = 0
    total_failed_count = 0 # Number of Failed Unparsed Logs

    for filename in os.listdir(LOG_DIR):

        file_path = os.path.join(LOG_DIR, filename)

        if not os.path.isfile(file_path):
            continue

        file_source = os.path.relpath(file_path, BASE_DIR)
        print(f"\nProcessing file: {filename}...")

        file_parsed_logs = [] # Specific to this instance of file
        file_failed_count = 0 # Specific to this instance of file
        file_parsed_count = 0

        with open(file_path, encoding="utf-8", errors="replace") as f:
            for line_number, log in enumerate(f, start=1):

                # To check and skip empty lines at the start of file
                if not log.strip():
                    continue

                # To check and skip empty lines or NUL corruption at the start of file
                if not log.replace('\x00', '').strip():
                    continue

                entry = parse_log_line(log)
                if entry is not None:
                    entry["line_number"] = line_number
                    entry["raw_line"] = log.rstrip('\n')
                    file_parsed_logs.append(entry)
                    file_parsed_count += 1
                else:
                    file_failed_count += 1
                    print(f"The unparsed log is {repr(log)} and its line number is {line_number}")

                if len(file_parsed_logs) >= 10000:
                        insert_events(file_parsed_logs, source_file=file_source)
                        file_parsed_logs.clear() # Instantly frees RAM
                        print(f"Processed {line_number} lines...")

        # Insert events for THIS specific file before moving to the next
        if file_parsed_logs:
            insert_events(file_parsed_logs, source_file=file_source)
            file_parsed_logs.clear()
                    
        print(f"Finished {filename} - Parsed: {file_parsed_count} | Unparsed: {file_failed_count}")
                
        total_parsed += file_parsed_count
        total_failed_count += file_failed_count
        
    print(f"\nALL FILES COMPLETE. Total Parsed: {total_parsed} | Total Unparsed: {total_failed_count}")