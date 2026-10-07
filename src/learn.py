import re

logs = [
    "2026-10-01 08:15:23 CRITICAL 192.168.1.10 user=alice action=login status=success attempts=1",
    "2026-10-01 08:16:02 WARN 10.0.0.45 user=bob action=login status=failed attempts=3 error=invalid_pass",
    "2026-10-01 08:17:45 ERROR 172.16.254.1 user=admin action=file_access path=/etc/passwd status=denied",
    "2026-10-01 08:19:10 INFO 192.168.1.22 user=carol action=download file=report.pdf size=2048",
    "2026-10-01 08:21:33 CRITICAL 203.0.113.77 user=unknown action=brute_force attempts=250 blocked=yes",
]

# pattern = re.compile(r"(\d{4}\-\d{2}\-\d{2}) (\d{2}:\d{2}:\d{2}) (\w+) (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) user(?:name)?=(\w+) ")

# Task 1: Extract all key=value pairs as dict
pattern_kvpair = re.compile(r"(\w+)=(\w+)")
pattern_level = re.compile(r"\s(INFO|WARN|ERROR|CRITICAL)\s")

for log in logs:
    match = pattern_kvpair.findall(log)
    dict_ = dict(match)
    
    level_match = pattern_level.search(log)
    level = level_match.group(1) if level_match else None

    print(f"Level: {level}")
    print(f"Action: {dict_.get("action", "N/A")}")
    print(f"Error: {dict_.get("Error", "N/A")}")

    if level in ["CRITICAL", "ERROR"]:
        print(f"  ⚠️  ALERT - User: {dict_.get('user')}, Action: {dict_.get('action')}")

    print()
    