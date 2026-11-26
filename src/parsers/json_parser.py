import json

def parse_json_line(log):
    """Parses a single-line JSON log, e.g:
    {"timestamp":"2026-10-02 09:14:22","level":"ERROR","user":"alice","action":"login","status":"failed","ip":"10.0.0.5"}
    Returns None if the line isn't a JSON object."""

    log = log.strip()
    if not log.startswith("{"):
        return None

    try:
        data = json.loads(log)
    except (json.JSONDecodeError, ValueError):
        return None

    if not isinstance(data, dict):
        return None

    level = str(data.get("level", "")).lower()
    action = data.get("action")
    status = data.get("status")

    if action and status:
        event_type = f"{action}_{status}"
    elif action:
        event_type = str(action)
    elif level:
        event_type = level
    else:
        event_type = "unclassified"

    return {
        "parsed": True,
        "log_type": "json_app",
        "event_type": event_type,
        "date_timestamp": data.get("timestamp") or data.get("time"),
        "process": data.get("service") or data.get("app"),
        "ip": data.get("ip"),
        "username": data.get("user") or data.get("username"),
    }