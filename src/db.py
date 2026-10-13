import os
import mysql.connector
from dotenv import load_dotenv

load_dotenv(override=True)

def get_connection():
    return mysql.connector.connect(
        host=os.getenv("DB_HOST"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        database=os.getenv("DB_NAME"),
    )

conn = get_connection()
cursor = conn.cursor()

cursor.execute("""
    CREATE TABLE IF NOT EXISTS events (
    id         BIGINT AUTO_INCREMENT PRIMARY KEY,
    log_type   VARCHAR(20) NOT NULL,
    event_time DATETIME NULL,
    ip         VARCHAR(45),
    username   VARCHAR(255),
    event_type VARCHAR(32),
    details    JSON,
    raw_line   TEXT,
    INDEX idx_ip_time (ip, event_time),
    INDEX idx_type_event (log_type, event_type)
);
""")


conn.commit()
cursor.close()
conn.close()
