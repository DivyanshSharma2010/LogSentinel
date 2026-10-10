import os 
from dotenv import load_dotenv

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
load_dotenv(os.path.join("BASE_DIR", ".env"))

DB_CONFIG = {
    "host": os.getenv("DB_HOST", "localhost"),
    "PORT": int(os.getenv("DB_PORT", "3306")),
    "user": os.getenv("DB_USER"),
    "password": os.getenv("DB_PASSWORD"),
    "database": os.getenv("DB_DATABASE"),
}

LOG_FILE_PATH = os.getenv("LOG_FILE_PATH", "sample_logs.txt")
RISK_THRESHOLD = int(os.getenv("RISK_THRESHOLD", 50))
