import re
from parsers.common import parse_syslog_header, normalize_timestamp

UFW_KV_PATTERN = re.compile(r"(\b[A-Za-z_]+)=([^\s]+)")

def parse_firewall_line(log):
    """Parses a UFW firewall line. Returns None if the line isn't a UFW log."""

    header = parse_syslog_header(log)
    if header is None:
        return None

    msg = header.get("message", "")

    if "[UFW" not in msg:
        return None

    kv_pairs = dict(UFW_KV_PATTERN.findall(msg))
    dst_port = kv_pairs.get("DPT")
    proto = kv_pairs.get("PROTO")

    event_type = "ufw_block"
    if "ALLOW" in msg:
        event_type = "ufw_allow"
    elif proto == "2" or kv_pairs.get("DST") == "224.0.0.1":
        event_type = "ufw_block_multicast"
    elif dst_port == "443" and ("ACK FIN" in msg or "RST" in msg):
        event_type = "ufw_block_https_noise"
    elif proto == "UDP" and dst_port and dst_port.isdigit() and 33434 <= int(dst_port) <= 33534:
        event_type = "ufw_block_traceroute"
    elif dst_port in {"5060", "389"}:
        event_type = "ufw_block_voip_ldap"
    elif dst_port in {"22", "3389", "5900", "21", "2121"}:
        event_type = "ufw_block_remote_admin"
    elif dst_port in {"1433", "3306", "5432", "6379", "27017", "11211"}:
        event_type = "ufw_block_database"
    elif dst_port in {"23", "2323"}:
        event_type = "ufw_block_telnet_iot"
    elif dst_port in {"2375", "2376", "6443", "9200"}:
        event_type = "ufw_block_critical_api"

    return {
        "parsed": True,
        "log_type": "firewall",
        "event_type": "ufw_block" if "BLOCK" in msg else "ufw_allow",
        "date_timestamp": normalize_timestamp(header.get("date_timestamp")),
        "process": header.get("process", "kernel"),
        "ip": kv_pairs.get("SRC"),
        "dst_port": kv_pairs.get("DPT"),
        "proto": kv_pairs.get("PROTO"),
        "hostname": header.get("hostname"),
    }