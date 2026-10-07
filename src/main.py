import re

log1 = "2026-10-01 08:15:23 INFO 192.168.1.10 user=alice login success"
log2 = "2026-10-01 08:16:02 WARN 10.0.0.45 user=bob login failed"
log3 = "2026-10-01 08:17:45 ERROR 172.16.254.1 user=admin file_access denied"

pattern = re.compile(r"(\d{4}\-\d{2}\-\d{2}) (\d{2}:\d{2}:\d{2}) (\w+) (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) user=(\w+) (.*)")

for log in [log1, log2, log3]:
    match = pattern.search(log)
    if match:
        print(match.groups())

