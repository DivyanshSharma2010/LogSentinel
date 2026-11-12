import os
import hashlib
import mysql.connector
from dotenv import load_dotenv
from config import RISK_THRESHOLD
import json

COLUMN_KEY = {"parsed", "line_number", "event_type", "date_timestamp", "process", "ip", "username", "raw_line", "log_type", "risk_score", "reasons"}

INSERT_EVENT = """
    INSERT INTO events
        (line_number, event_type, event_time, log_type, process, ip, username, details, raw_line, source_file, risk_score, is_quarantined)
    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    ON DUPLICATE KEY UPDATE id = id
"""

INSERT_QUARANTINE = """
    INSERT INTO quarantine
        (log_hash, log_line, event_time, risk_score, trigger_reasons, threat_type, user_name, ip_address)
    VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
    ON DUPLICATE KEY UPDATE id = id
"""

load_dotenv(override=True)

def get_connection():
    return mysql.connector.connect(
        host=os.getenv("DB_HOST"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        database=os.getenv("DB_NAME"),
    )

def row_from_entry(entry, source_file):
    details = {k:v for k,v in entry.items() if k not in COLUMN_KEY}
    risk_score = entry.get("risk_score", 0)
    return (
        entry.get("line_number"), 
        entry.get("event_type","unclassified"), 
        entry.get("date_timestamp"), 
        entry.get("log_type", "unkown"), 
        entry.get("process"), 
        entry.get("ip"), 
        entry.get("username"),
        json.dumps(details),
        entry.get("raw_line"), 
        source_file,
        risk_score,
        1 if risk_score >= RISK_THRESHOLD else 0,
    )
    
def insert_events(entries, source_file):

    rows = []
    for e in entries:
        row = row_from_entry(e, source_file)
        rows.append(row)

    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.executemany(INSERT_EVENT, rows)
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        cursor.close()
        conn.close()

def insert_quarantine(entries):
    """Inserts high-risk log entries into the quarantine table.
    Each entry must already have 'risk_score' and 'reasons' set on it."""

    if not entries:
        return

    rows = []
    for e in entries:
        raw_line = e.get("raw_line", "")
        log_hash = hashlib.sha256(raw_line.encode("utf-8")).hexdigest()
        reasons_text = ", ".join(e.get("reasons", []))

        rows.append((
            log_hash,
            raw_line,
            e.get("date_timestamp"),
            e.get("risk_score", 0),
            reasons_text,
            e.get("event_type"),
            e.get("username"),
            e.get("ip"),
        ))

    conn = get_connection()
    cursor = conn.cursor()

    try:
        cursor.executemany(INSERT_QUARANTINE, rows)
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        cursor.close()
        conn.close()