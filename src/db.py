import os
import mysql.connector
from dotenv import load_dotenv
import json

COLUMN_KEY = {"parsed", "event_type", "date_timestamp", "process", "ip", "raw_line", "log_type"}

INSERT_EVENT = """
    INSERT INTO events
        (line_number, event_type, timestamp_raw, log_type, process, ip, details, raw_line, source_file)
    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
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
    return (
        entry["line_number"], None, entry["date_timestamp"], "ssh", entry["process"], entry["ip"], json.dumps(details), entry["raw_line"], source_file
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
    
