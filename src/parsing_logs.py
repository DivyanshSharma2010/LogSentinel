import os
from db import insert_events, insert_quarantine
from analyzer import calculate_risk_score
from parser_function import parse_log_line
from config import RISK_THRESHOLD

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_DIR = os.path.join(BASE_DIR, "data")

if not os.path.exists(LOG_DIR):
    raise SystemExit(f"DATA DIRECTORY NOT FOUND: {LOG_DIR}")

if __name__ == "__main__":
    total_parsed = 0
    total_failed_count = 0 

    for filename in os.listdir(LOG_DIR):
        file_path = os.path.join(LOG_DIR, filename)

        if not os.path.isfile(file_path):
            continue

        file_source = os.path.relpath(file_path, BASE_DIR)
        print(f"\nProcessing file: {filename}...")

        file_parsed_logs = []      # Every parsed log, goes to the main events table
        file_quarantine_logs = []  # Only high-risk logs, goes to the quarantine table
        file_failed_count = 0  # Specific to this instance of file
        file_parsed_count = 0

        with open(file_path, encoding="utf-8", errors="replace") as f:
            for line_number, log in enumerate(f, start=1):

                # Skip empty lines or NUL corruption
                if not log.replace('\x00', '').strip():
                    continue

                entry = parse_log_line(log)
                if entry is not None:
                    entry["line_number"] = line_number
                    entry["raw_line"] = log.rstrip('\n')

                    # Score the entry and remember why it scored that way
                    score, reasons = calculate_risk_score(entry)
                    entry["risk_score"] = score
                    entry["reasons"] = reasons

                    file_parsed_logs.append(entry)
                    file_parsed_count += 1

                    # High risk logs also go to quarantine
                    if score >= RISK_THRESHOLD:
                        file_quarantine_logs.append(entry)
                else:
                    file_failed_count += 1
                    preview = repr(log[:200])
                    if len(log) > 200:
                        preview += f" ...(truncated, full line is {len(log)} characters)"
                    print(f"Unparsed log in {filename} at line {line_number}: {preview}")

                if len(file_parsed_logs) >= 10000:
                    insert_events(file_parsed_logs, source_file=file_source)
                    file_parsed_logs.clear()  # Instantly frees RAM
                    print(f"Processed {line_number} lines...")

                if len(file_quarantine_logs) >= 10000:
                    insert_quarantine(file_quarantine_logs)
                    file_quarantine_logs.clear()

        # Insert remaining events for THIS specific file before moving to the next
        if file_parsed_logs:
            insert_events(file_parsed_logs, source_file=file_source)
            file_parsed_logs.clear()

        if file_quarantine_logs:
            insert_quarantine(file_quarantine_logs)
            file_quarantine_logs.clear()