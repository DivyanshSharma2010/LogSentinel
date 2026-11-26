import os
import csv
from db import insert_events, insert_quarantine
from analyzer import calculate_risk_score
from parser_function import parse_log_line
from config import RISK_THRESHOLD

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_DIR = os.path.join(BASE_DIR, "data")

def read_lines_from_file(file_path):
    """Reads a file and yields (line_number, raw_text) pairs.
    Works for plain text log files, and for CSV files where each row
    holds one raw log line, or several columns that together make up
    one raw log line."""

    _, ext = os.path.splitext(file_path)

    if ext.lower() == ".csv":
        with open(file_path, encoding="utf-8", errors="replace", newline="") as f:
            reader = csv.reader(f)
            for line_number, row in enumerate(reader, start=1):
                if not row:
                    continue
                # One column = that column IS the raw log line.
                # Several columns = join them back into one line with a space.
                raw_text = row[0] if len(row) == 1 else " ".join(row)
                yield line_number, raw_text
    else:
        with open(file_path, encoding="utf-8", errors="replace") as f:
            for line_number, raw_text in enumerate(f, start=1):
                yield line_number, raw_text.rstrip("\n")


def process_file(file_path, file_source):
    """Parses, scores and saves every log line in one file.
    Returns (parsed_count, failed_count)."""

    file_parsed_logs = []      # Every parsed log, goes to the main events table
    file_quarantine_logs = []  # Only high-risk logs, goes to the quarantine table
    file_failed_count = 0
    file_parsed_count = 0

    for line_number, raw_text in read_lines_from_file(file_path):

        # Skip empty lines or NUL corruption
        if not raw_text.replace('\x00', '').strip():
            continue

        entry = parse_log_line(raw_text)
        if entry is not None:
            entry["line_number"] = line_number
            entry["raw_line"] = raw_text

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
            preview = repr(raw_text[:200])
            if len(raw_text) > 200:
                preview += f" ...(truncated, full line is {len(raw_text)} characters)"
            print(f"Unparsed log in {os.path.basename(file_path)} at line {line_number}: {preview}")

        if len(file_parsed_logs) >= 10000:
            insert_events(file_parsed_logs, source_file=file_source)
            file_parsed_logs.clear()  # Instantly frees RAM
            print(f"Processed {line_number} lines...")

        if len(file_quarantine_logs) >= 10000:
            insert_quarantine(file_quarantine_logs)
            file_quarantine_logs.clear()

    # Insert whatever is left over for this file
    if file_parsed_logs:
        insert_events(file_parsed_logs, source_file=file_source)
        file_parsed_logs.clear()

    if file_quarantine_logs:
        insert_quarantine(file_quarantine_logs)
        file_quarantine_logs.clear()

    return file_parsed_count, file_failed_count


def process_all_logs():
    """Processes every file inside the data/ folder, one at a time."""

    if not os.path.exists(LOG_DIR):
        raise SystemExit(f"DATA DIRECTORY NOT FOUND: {LOG_DIR}")

    total_parsed = 0
    total_failed_count = 0

    for filename in os.listdir(LOG_DIR):
        file_path = os.path.join(LOG_DIR, filename)

        if not os.path.isfile(file_path):
            continue

        file_source = os.path.relpath(file_path, BASE_DIR)
        print(f"\nProcessing file: {filename}...")

        file_parsed_count, file_failed_count = process_file(file_path, file_source)

        print(f"Finished {filename} - Parsed: {file_parsed_count} | Unparsed: {file_failed_count}")

        total_parsed += file_parsed_count
        total_failed_count += file_failed_count

    print(f"\nALL FILES COMPLETE. Total Parsed: {total_parsed} | Total Unparsed: {total_failed_count}")


if __name__ == "__main__":
    process_all_logs()