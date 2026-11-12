from parsers.ssh_parser import parse_ssh_line
from parsers.firewall_parser import parse_firewall_line
from parsers.web_parser import parse_web_access_line

def parse_log_line(log):
    """Tries each log type's parser in turn and returns the first match."""

    for parser in (parse_ssh_line, parse_firewall_line, parse_web_access_line):
        entry = parser(log)
        if entry is not None:
            return entry
    return None