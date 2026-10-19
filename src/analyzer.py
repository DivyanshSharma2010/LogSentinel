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

    global FAILED_IP_COUNT
    global ip_count

    if dict_1 is None:
        return 0
    
    score = 0
    log_type = dict_1.get("log_type")
    event_type = dict_1.get("event_type", 0).lower()
    ip = dict_1.get("ip")

    # Global Rules 
    if dict_1.get("username", None) in HIGH_RISK_USER:
        score += HIGH_RISK_USER_BONUS

    if event_type in FAILURE_EVENTS and ip is not None:
        FAILED_IP_COUNT[ip] = FAILED_IP_COUNT.get(ip, 0) + 1

        if FAILED_IP_COUNT[ip] >= BRUTE_FORCE_LIMIT:
            score += BRUTE_FORCE_BONUS

    for key, weight in EVENTS_WEIGHT.items():
        if key.lower() in event_type:
            score += weight
            break

    ts_str = dict_1.get("date_timestamp", "")
    try:
        hour = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S").hour
        if hour >= OFF_HOURS_START and hour <= OFF_HOURS_END:
            score += OFF_HOURS_BONUS 
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
        print(f"DEBUG - CLEANED AGENT: {user_agent}")

        if user_agent == "-" or user_agent == "":
            score += 15
        elif any(bad_agent in user_agent for bad_agent in HIGH_RISK_AGENTS):
            score += HIGH_RISK_AGENTS_BONUS
        
    
    return min(score, 100)

if __name__ == "__main__":

#     logs = [
#     'Dec 10 02:55:46 LabSZ sshd[24200]: reverse mapping checking getaddrinfo for ns.marryaldkfaczcz.com [173.234.31.186] failed - POSSIBLE BREAK-IN ATTEMPT!',
#     'Dec 10 06:55:46 LabSZ sshd[24200]: Invalid user admin from 173.234.31.186',
#     'Dec 10 04:55:46 LabSZ sshd[24200]: input_userauth_request: invalid user webmaster [preauth]',
#     'Dec 10 06:55:46 LabSZ sshd[24200]: pam_unix(sshd:auth): check pass; user unknown',
#     'Dec 10 06:55:46 LabSZ sshd[24200]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=173.234.31.186 ',
#     'Dec 10 06:55:48 LabSZ sshd[24200]: Failed password for invalid user webmaster from 173.234.31.186 port 38926 ssh2',
#     'Dec 10 06:55:46 LabSZ sshd[24200]: Invalid user admin from 173.234.31.186',
#     'Aug 10 17:53:47 kauai kernel: [492520.519106] [UFW ALLOW] IN= OUT=eno1 SRC=123.21.32.5 DST=123.21.32.107 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=50294 DF PROTO=TCP SPT=10348 DPT=11211 WINDOW=29200 RES=0x00 SYN URGP=0',
#     'Aug 10 17:53:47 kauai kernel: [492520.522346] [UFW ALLOW] IN= OUT=eno1 SRC=123.21.32.5 DST=123.21.32.117 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=39441 DF PROTO=TCP SPT=54690 DPT=11211 WINDOW=29200 RES=0x00 SYN URGP=0 ',
#     'Aug 10 17:53:47 kauai kernel: [492520.519500] [UFW ALLOW] IN= OUT=eno1 SRC=123.21.32.5 DST=123.21.32.6 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=16025 DF PROTO=TCP SPT=59794 DPT=3306 WINDOW=29200 RES=0x00 SYN URGP=0',
#     'Aug 10 17:53:47 kauai kernel: [492520.522346] [UFW ALLOW] IN= OUT=eno1 SRC=123.21.32.5 DST=123.21.32.117 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=39441 DF PROTO=TCP SPT=54690 DPT=11211 WINDOW=29200 RES=0x00 SYN URGP=0 ',
#     'Aug 10 17:53:47 kauai kernel: [492520.521576] [UFW ALLOW] IN= OUT=eno1 SRC=123.21.32.5 DST=123.21.32.6 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=39825 DF PROTO=TCP SPT=59796 DPT=3306 WINDOW=29200 RES=0x00 SYN URGP=0',
#     'Aug 10 17:53:47 kauai kernel: [492520.521966] [UFW ALLOW] IN= OUT=eno1 SRC=123.21.32.5 DST=123.21.32.107 LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID=36688 DF PROTO=TCP SPT=10354 DPT=11211 WINDOW=29200 RES=0x00 SYN URGP=0',
#     '91.99.72.15 - - [22/Jan/2019:04:05:25 +0330] "GET /product/4151/257/%D8%B3%DB%8C%D9%86%DA%A9-%D8%B8%D8%B1%D9%81%D8%B4%D9%88%DB%8C%DB%8C-%D8%B1%D9%88%DA%A9%D8%A7%D8%B1-%D8%A7%D8%B3%D8%AA%DB%8C%D9%84-%D8%A7%D9%84%D8%A8%D8%B1%D8%B2-%D9%85%D8%AF%D9%84-%D8%B7%D8%B1%D8%AD-%D9%BE%D8%B1%D9%88%D8%A7%D9%86%D9%87-220-50 HTTP/1.1" 200 42741 "-" "Mozilla/5.0 (Windows NT 6.2; Win64; x64; rv:16.0)Gecko/16.0 Firefox/16.0" "-"',
#     '91.99.72.15 - - [22/Jan/2019:04:05:26 +0330] "GET /product/29445/58879/%D9%85%D8%A7%D8%B4%DB%8C%D9%86-%D8%A7%D8%B5%D9%84%D8%A7%D8%AD-%D8%A8%D8%AF%D9%86-%D8%A8%D8%B1%D8%A7%D9%88%D9%86-%D9%85%D8%AF%D9%84-BG5010 HTTP/1.1" 200 42036 "-" "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_7_3) AppleWebKit/534.55.3 (KHTML, like Gecko) Version/5.1.3 Safari/534.53.10" "-"',
#     '54.36.148.40 - - [22/Jan/2019:04:05:26 +0330] "GET /blog/tag/%D9%81%D8%B5%D9%84-%D9%BE%D8%A7%DB%8C%DB%8C%D8%B2/ HTTP/1.1" 200 19580 "-" "Mozilla/5.0 (compatible; AhrefsBot/6.1; +[http://ahrefs.com/robot/](http://ahrefs.com/robot/))" "-"',
#     '54.36.148.38 - - [22/Jan/2019:04:05:26 +0330] "GET /blog/digital-supplies/cell-phone/page/92/ HTTP/1.1" 200 21342 "-" "Mozilla/5.0 (compatible; AhrefsBot/6.1; +[http://ahrefs.com/robot/](http://ahrefs.com/robot/))" "-"',
#     '66.249.66.194 - - [22/Jan/2019:04:05:27 +0330] "GET /m/filter/p18%2Cv1%7C%D8%B3%D9%81%DB%8C%D8%AF%2Cb215%2Cb88 HTTP/1.1" 302 0 "-" "Mozilla/5.0 (compatible; Googlebot/2.1; +[http://www.google.com/bot.html](http://www.google.com/bot.html))" "-"',
#     '91.99.72.15 - - [22/Jan/2019:04:05:27 +0330] "GET /product/12923?model=21506 HTTP/1.1" 200 40325 "-" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/53.0.2785.92 Safari/537.36" "-"',
#     '5.211.97.39 - - [22/Jan/2019:04:05:27 +0330] "GET /m/browse/appliances/%D9%84%D9%88%D8%A7%D8%B2%D9%85-%D9%85%D9%86%D8%B2%D9%84 HTTP/1.1" 200 16640 "[https://www.zanbil.ir/m/browse/home-appliances/%D9%84%D9%88%D8%A7%D8%B2%D9%85-%D8%AE%D8%A7%D9%86%DA%AF%DB%8C](https://www.zanbil.ir/m/browse/home-appliances/%D9%84%D9%88%D8%A7%D8%B2%D9%85-%D8%AE%D8%A7%D9%86%DA%AF%DB%8C)" "Mozilla/5.0 (iPhone; CPU iPhone OS 10_3_2 like Mac OS X) AppleWebKit/603.2.4 (KHTML, like Gecko) Version/10.0 Mobile/14F89 Safari/602.1" "-"',
#     '192.168.1.100 - - [22/Jan/2019:04:05:28 +0330] "GET /admin.php?id=1 UNION SELECT 1,2,3 HTTP/1.1" 403 456 "-" "sqlmap/1.5.8#dev (http://sqlmap.org)" "-"'
# ]
    logs = []
    with open("src\\logs_clean.txt", encoding='utf-8', errors='replace') as f:
        for log in f:
            log = log.strip()
            if log:  # skip empty lines
                logs.append(log)
        

    for log in logs:
        dict_1 = parse_log_line(log)
        score = calculate_risk_score(dict_1)
        user = dict_1.get('username')
        display_user = user if user else "N/A"        

        print(f"Event: {dict_1.get('event_type', ''):<22} | User: {display_user:<10} | Score: {score}")