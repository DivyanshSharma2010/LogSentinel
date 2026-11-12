import os
from config import *
from db import insert_events
from parser_function import parse_log_line
from datetime import datetime
import json

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_DIR = os.path.join(BASE_DIR, "data")

FAILED_IP_COUNT = {}
ip_count = 0

FAILURE_EVENTS = {
    "failed_login",
    "invalid_user",
    "authentication_failure",
    "possible break-in attempt",
}

def calculate_risk_score(dict_1):
    """Scores a parsed log entry. Returns (score, reasons) where reasons
    is a list of short tags explaining what added to the score."""

    global FAILED_IP_COUNT
    global ip_count

    if dict_1 is None:
        return 0, []

    score = 0
    reasons = []
    log_type = dict_1.get("log_type")
    event_type = dict_1.get("event_type", "unclassified").lower()
    ip = dict_1.get("ip")

    # Global Rules 
    if dict_1.get("username", None) in HIGH_RISK_USER:
        score += HIGH_RISK_USER_BONUS
        reasons.append("high_risk_username")

    if event_type in FAILURE_EVENTS and ip is not None:
        FAILED_IP_COUNT[ip] = FAILED_IP_COUNT.get(ip, 0) + 1

        if FAILED_IP_COUNT[ip] >= BRUTE_FORCE_LIMIT:
            score += BRUTE_FORCE_BONUS
            reasons.append("brute_force_pattern")

    for key, weight in EVENTS_WEIGHT.items():
        if key.lower() in event_type:
            score += weight
            if weight > 0:
                reasons.append(f"event_type:{key}")
            break

    ts_str = dict_1.get("date_timestamp", "")
    try:
        hour = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S").hour
        if hour >= OFF_HOURS_START and hour <= OFF_HOURS_END:
            score += OFF_HOURS_BONUS 
            reasons.append("off_hours_activity")
    except ValueError:
        pass

    # web_access logs
    if dict_1.get("log_type") == "web_access":

        if "user_agent" in dict_1:
            raw_agent = dict_1.get("user_agent", "")
        elif "details" in dict_1:
            details = dict_1["details"]

            if isinstance(details, str):
                details = json.loads(details)
            raw_agent = details.get("user_agent", "")
        else:
            raw_agent = ""

        user_agent = raw_agent.replace('"', '').lower()

        if user_agent == "-" or user_agent == "":
            score += 15
            reasons.append("missing_user_agent")
        elif any(bad_agent in user_agent for bad_agent in HIGH_RISK_AGENTS):
            score += HIGH_RISK_AGENTS_BONUS
            reasons.append("high_risk_user_agent")

    return min(score, 100), reasons

if __name__ == "__main__":

    logs = []
    sample_log_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs_clean.txt")
    with open(sample_log_path, encoding='utf-8', errors='replace') as f:
        for log in f:
            log = log.strip()
            if log:  # skip empty lines
                logs.append(log)
        

    for log in logs:
        dict_1 = parse_log_line(log)
        score, reasons = calculate_risk_score(dict_1)
        user = dict_1.get('username')
        display_user = user if user else "N/A"        

        print(f"Event: {dict_1.get('event_type', ''):<22} | User: {display_user:<10} | Score: {score}")