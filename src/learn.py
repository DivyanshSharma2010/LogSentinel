import re

# logs = [
#     "2026-10-02 09:14:22 ERROR 192.168.1.15 user=alice action=login status=failed attempts=2 ip=10.20.30.40",

#     "2026-10-02 09:15:07 INFO 10.0.0.23 user=bob action=download file=report_final.pdf size=4821 status=success",

#     "2026-10-02 09:17:43 WARN 172.16.5.12 username:carol action=login status=failed attempts=4 error=invalid_pass",

#     "2026-10-02 09:19:51 CRITICAL 203.0.113.42 user:admin action=file_access path=/var/log/auth.log status=denied attempts=7",

#     "2026-10-02 09:21:16 INFO 192.168.10.8 user=dave action=upload file=backup_2026.zip size=1048576 status=success",

#     "2026-10-02 09:24:38 ERROR 10.10.5.77 username=eve action=api_request endpoint=/api/v2/users status=500 response_time=842ms",

#     "2026-10-02 09:27:04 WARN 192.168.2.44 user=frank action=login status=failed attempts=3 error=account_locked",

#     "2026-10-02 09:29:55 CRITICAL 198.51.100.24 user=unknown action=brute_force attempts=175 blocked=yes source_port=443"
# ]
    
# # Level 2
# pattern = re.compile(r"(\d{4}\-\d{2}\-\d{2}) (\d{2}:\d{2}:\d{2}) (\w+) (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) user(?:name)?=(\w+) action=(\w+)")
# pattern_level = re.compile(r"\b(ERROR|INFO|WARN|CRITICAL)\b")
# pattern_username = re.compile(r"user(?:name)?(?:=|:)(\w+)")

# for log in logs:
#     match_level = pattern_level.search(log)
#     match_username = pattern_username.search(log)

#     if match_username:
#         print(match_username.group())
#     else:
#         print("No match found")

# from collections import Counter

# ips = ["203.0.113.7", "198.51.100.4", "203.0.113.7", "203.0.113.7"]
# counts = Counter(ips)

# print(counts["203.0.113.7"])

# from pygrok import Grok
# import csv

# logs = [
#     "Dec 10 07:28:19 LabSZ sshd[24259]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=112.95.230.3  user=root",
#     "Dec 10 07:28:19 LabSZ sshd[24259]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=112.95.230.3  user=root",
#     "Dec 10 07:29:10 LabSZ sshd[24260]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=188.10.10.5  user=admin"
# ]

# pattern = r"%{SYSLOGTIMESTAMP:timestamp} %{WORD:serverhost} %{WORD:app}\[%{NUMBER:processid}\]: %{GREEDYDATA:waste}: %{DATA:result}; %{GREEDYDATA:system_message}\s+ user=%{WORD:user}"

# grok = Grok(pattern)

# parsed_logs = []

# for log in logs:
#     match = grok.match(log)
#     if match:
#         parsed_logs.append(match)
#     else:
#         print("No matches")

# if parsed_logs:
#     # Get the headers dynamically from the first match keys
#     headers = parsed_logs[0].keys()
    
#     with open('security_logs.csv', 'w', newline='') as csvfile:
#         writer = csv.DictWriter(csvfile, fieldnames=headers)
        
#         writer.writeheader()  # Writes: timestamp, server_host, app...
#         writer.writerows(parsed_logs)  # Writes the data
        
#     print("Success! Saved to security_logs.csv")

# from pygrok import Grok

# def with_return(x):
#     return {"value": x}

# def without_return(x):
#     y = {"value": x}      # built, but never handed back

# print(with_return(5))
# print(without_return(5))

# from datetime import datetime

# raw_ts = "Dec 10 06:55:46"
# print(raw_ts.split())
# default_yr = "2026"
# clean_ts = " ".join(raw_ts.split())
# full_ts = default_yr + clean_ts

# raw_log_date = "2026-10-15 20:45:00"

# date_obj = datetime.strptime(raw_log_date, "%Y-%m-%d %H:%M:%S")
# print(type(date_obj))  
# print(date_obj.year) 

# now = datetime.now()
# friendly_text = now.strftime("%A, %B %d, %Y")
# print(friendly_text)

import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_DIR = os.path.join(BASE_DIR, "data")
for filename in os.listdir(LOG_DIR):
    file_path = os.path.join(LOG_DIR, filename)
    source_name = os.path.relpath(file_path, BASE_DIR)
    print(source_name)
    print(file_path)