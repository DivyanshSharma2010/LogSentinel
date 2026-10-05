import re

log_line = "re whitespace CAPITAL 234543"

pattern = re.compile(r"^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})\s+(\w+)\s+(.+)$")

with open("server.log", "w") as file:
    for line in file:
        line = line.strip()
        match = pattern.match(line)
        if match:
            timestamp, severity, message = match.groups()
            print(f"[{timestamp}] {severity}: {message}")
