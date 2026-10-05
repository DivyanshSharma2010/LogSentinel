import re

log_line = "Switching to port 340 from PORT 230"
pattern = re.compile(r"port", re.IGNORECASE)
match = re.findall(pattern, log_line)

if match:
    print(match[1])
else:
    print("No match found")

