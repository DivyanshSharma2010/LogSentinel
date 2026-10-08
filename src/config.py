import os 
from dotenv import load_dotenv

load_dotenv()

DB_HOST = os.getenv("DB_HOST")
DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")
DB_NAME = os.getenv("DB_NAME")
DB_PORT = os.getenv("DB_PORT", 3306)

LOG_FILE_PATH = os.getenv("LOG_FILE_PATH", "sample_logs.txt")
RISK_THRESHOLD = int(os.getenv("RISK_THRESHOLD", 50))

