from parsing_logs import process_all_logs

# This is the entry point for LogSentinel.
# It reads every log file inside the data/ folder, parses each line,
# scores it for risk, and saves it to the database (and to quarantine if it's high risk).

if __name__ == "__main__":
    process_all_logs()  