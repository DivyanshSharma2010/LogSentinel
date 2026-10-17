import os
import mysql.connector
from dotenv import load_dotenv
import json

COLUMN_KEY = {"parsed", "line_number", "event_type", "date_timestamp", "process", "ip", "username", "raw_line", "log_type"}

INSERT_EVENT = """
    INSERT INTO events
        (line_number, event_type, event_time, log_type, process, ip, username, details, raw_line, source_file)
    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
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
        # entry["line_number"], None, entry["date_timestamp"], "ssh", entry["process"], entry["ip"], json.dumps(details), entry["raw_line"], source_file
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
    
# def call_parsed_logs(entries):
#     conn = get_connection()
#     cursor = conn.cursor()

#     sql_query = """SELECT id, log_type, event_time, ip, event_type, details, raw_line, process 
#     FROM events WHERE is_analyzed = 0 ORDER BY id ASC LIMIT 500;"""

#     try:
#         logs = cursor.execute(sql_query)