from config import EVENTS_WEIGHT, RISK_THRESHOLD, HIGH_RISK_USER, HIGH_RISK_USER_BONUS, BRUTE_FORCE_LIMIT, BRUTE_FORCE_BONUS
from db import insert_events
import os

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_PATH = os.path.join(BASE_DIR, "data", "OpenSSH_2k.log")
SOURCE_FILE = os.path.relpath(LOG_PATH, BASE_DIR)

initial_score = 0

def calculate_risk_score(event, user, failed_attempts):
    global initial_score
    score = initial_score

    score += EVENTS_WEIGHT.get(event, 0)

    if user in HIGH_RISK_USER:
        score += HIGH_RISK_USER_BONUS

    # Check for brute-force attempts
    if failed_attempts >= BRUTE_FORCE_LIMIT:
        score += BRUTE_FORCE_BONUS

    if score > 100:
        score = 100

    if score >= RISK_THRESHOLD:
        print(f"Risk score {score} exceeds threshold {RISK_THRESHOLD}.")
    else:
        print(f"Risk score {score} is below threshold {RISK_THRESHOLD}.")

    return score

