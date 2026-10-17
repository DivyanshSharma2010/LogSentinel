import os
from db import insert_events
from analyzer import calculate_risk_score
from parser_function import parse_log_line

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

        file_parsed_logs = []  # Specific to this instance of file
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
                    
                    # NOTE: Once your analyzer is ready, you can score the entry right here!
                    # entry["risk_score"] = calculate_risk_score(entry)
                    
                    file_parsed_logs.append(entry)
                    file_parsed_count += 1
                else:
                    file_failed_count += 1
                    print(f"The unparsed log is {repr(log)} and its line number is {line_number}")

                if len(file_parsed_logs) >= 10000:
                    insert_events(file_parsed_logs, source_file=file_source)
                    file_parsed_logs.clear()  # Instantly frees RAM
                    print(f"Processed {line_number} lines...")

        # Insert remaining events for THIS specific file before moving to the next
        if file_parsed_logs:
            insert_events(file_parsed_logs, source_file=file_source)
            file_parsed_logs.clear()

        print(f"Finished {filename} - Parsed: {file_parsed_count} | Unparsed: {file_failed_count}")

        total_parsed += file_parsed_count
        total_failed_count += file_failed_count

    print(f"\nALL FILES COMPLETE. Total Parsed: {total_parsed} | Total Unparsed: {total_failed_count}")