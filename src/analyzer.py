import os
from config import EVENTS_WEIGHT, RISK_THRESHOLD, HIGH_RISK_USER, HIGH_RISK_USER_BONUS, BRUTE_FORCE_LIMIT, BRUTE_FORCE_BONUS, OFF_HOURS_BONUS
from db import insert_events
from parser_function import parse_log_line
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_DIR = os.path.join(BASE_DIR, "data")

def calculate_risk_score(dict_1):

    if dict_1 is None:
        return 0
    
    score = 0

    if dict_1.get("username") in HIGH_RISK_USER:
        score += HIGH_RISK_USER_BONUS

    ts_str = dict_1.get("date_timestamp", "")
    try:
        hour = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S").hour
        if 0 <= hour < 6:
            score += OFF_HOURS_BONUS 
    except ValueError:
        pass

    event_type = dict_1.get("event_type", 0).lower()
    for key, weight in EVENTS_WEIGHT.items():
        if key.lower() in event_type:
            score += weight
            break


    return score

if __name__ == "__main__":

    logs = [
    "Dec 10 02:55:46 LabSZ sshd[24200]: reverse mapping checking getaddrinfo for ns.marryaldkfaczcz.com [173.234.31.186] failed - POSSIBLE BREAK-IN ATTEMPT!",
    "Dec 10 06:55:46 LabSZ sshd[24200]: Invalid user admin from 173.234.31.186",
    "Dec 10 04:55:46 LabSZ sshd[24200]: input_userauth_request: invalid user webmaster [preauth]",
    "Dec 10 06:55:46 LabSZ sshd[24200]: pam_unix(sshd:auth): check pass; user unknown",
    "Dec 10 06:55:46 LabSZ sshd[24200]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=173.234.31.186 ",
    "Dec 10 06:55:48 LabSZ sshd[24200]: Failed password for invalid user webmaster from 173.234.31.186 port 38926 ssh2",
    ]

    for log in logs:
        dict_1 = parse_log_line(log)
        score = calculate_risk_score(dict_1)
        print(f"Event: {dict_1['event_type']:<22} | User: {str(dict_1['username']):<10} | Score: {score}")
        