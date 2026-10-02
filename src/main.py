import re

log_line = "main@myaddress.coms"
pattern = r"^[a-zA-Z0-9\.\-_]+@{1}[a-zA-Z0-9]+\.{1}[a-zA-Z]{2,3}"
match = re.search(pattern, log_line)
if match:
    print("Accepted")
    print(match)
else:
    print("Rejected")

print("hello, testing 1, 2, 3")