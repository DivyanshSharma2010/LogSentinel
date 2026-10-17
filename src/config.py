import os 
from dotenv import load_dotenv

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join("BASE_DIR", ".env"))

DB_CONFIG = {
    "host": os.getenv("DB_HOST", "localhost"),
    "port": int(os.getenv("DB_PORT", "3306")),
    "user": os.getenv("DB_USER"),
    "password": os.getenv("DB_PASSWORD"),
    "database": os.getenv("DB_DATABASE"),
}

RISK_THRESHOLD = 70

EVENTS_WEIGHT = {
    "accepted_login": 0,
    "session_opened": 0,
    "failed_login": 10,
    "connection_closed": 15,
    "received_disconnect": 15,
    "authentication_failure": 35,
    "invalid_user": 40,
    "unusual_hour": 40,
    "maximum authentication attempts exceeded": 60,
    "possible break-in attempt": 60,
    "root login refused": 60,
    "did not receive identification string": 30
}

# High Risk User
HIGH_RISK_USER = ["root", "admin", "mysql", "oracle", "ubuntu", "test", "guest", "postgres"]
HIGH_RISK_USER_BONUS = 25

# Brute-force repetition settings
BRUTE_FORCE_LIMIT = 5
BRUTE_FORCE_BONUS = 30

# OFF Hours
OFF_HOURS_BONUS = 25