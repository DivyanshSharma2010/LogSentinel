import re

logs = [
    "2026-10-02 09:14:22 ERROR 192.168.1.15 user=alice action=login status=failed attempts=2 ip=10.20.30.40",

    "2026-10-02 09:15:07 INFO 10.0.0.23 user=bob action=download file=report_final.pdf size=4821 status=success",

    "2026-10-02 09:17:43 WARN 172.16.5.12 username:carol action=login status=failed attempts=4 error=invalid_pass",

    "2026-10-02 09:19:51 CRITICAL 203.0.113.42 user:admin action=file_access path=/var/log/auth.log status=denied attempts=7",

    "2026-10-02 09:21:16 INFO 192.168.10.8 user=dave action=upload file=backup_2026.zip size=1048576 status=success",

    "2026-10-02 09:24:38 ERROR 10.10.5.77 username=eve action=api_request endpoint=/api/v2/users status=500 response_time=842ms",

    "2026-10-02 09:27:04 WARN 192.168.2.44 user=frank action=login status=failed attempts=3 error=account_locked",

    "2026-10-02 09:29:55 CRITICAL 198.51.100.24 user=unknown action=brute_force attempts=175 blocked=yes source_port=443"
]
    
# Level 2
pattern = re.compile(r"(\d{4}\-\d{2}\-\d{2}) (\d{2}:\d{2}:\d{2}) (\w+) (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) user(?:name)?=(\w+) action=(\w+)")
pattern_level = re.compile(r"\b(ERROR|INFO|WARN|CRITICAL)\b")
pattern_username = re.compile(r"user(?:name)?(?:=|:)(\w+)")

for log in logs:
    match_level = pattern_level.search(log)
    match_username = pattern_username.search(log)

    if match_username:
        print(match_username.group())
    else:
        print("No match found")

