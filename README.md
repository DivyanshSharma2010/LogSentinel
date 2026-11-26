# LogSentinel

Threat Detection System based on reading, parsing and evaluating log lines from SSH Logs, UFW Logs, Web Access Logs, Json app Logs and Key=value app Logs 

## What it does

- Parses any file in the data/ folder of the format csv or plain text
- Support 5 logs types SSH/auth syslog, UFW firewall syslog, Apache/Nginx-style web access logs single-line JSON app logs, and generic key=value app logs.
- Saved every parsed line to events table in mysql database.
- Every log which excceds the risk threshold(>= 70) goes in the quarantine table.
- Parses logs in batches so that even when parsing millions of logs the memory never runs out.

## Prerequisites

- Python 3.9+
- A running MySQL server (local or remote) you have credentials for

## Setup

1. **Clone the repo**
   ```bash
   git clone https://github.com/DivyanshSharma2010/LogSentinel.git
   cd LogSentinel
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Create the database and tables**
   ```bash
   mysql -u root -p < src/schema.sql
   ```
   This creates a `LogSentinel` database with two tables: `events` (every parsed log line) and `quarantine` (high-risk lines only).

44. **Configure your environment**

   Copy the example env file and fill in your own MySQL credentials:

   **macOS/Linux:**
   ```bash
   cp .env.example .env
   ```

   **Windows (Command Prompt):**
   ```cmd
   copy .env.example .env
   ```

5. **Add your log files**

   # copy your .log / .txt / .csv files into data/ which is already created in the project
   ```

6. **Run it**

   From the project root:
   ```bash
   python src/main.py
   ```

   You'll see per-file progress and a final summary of parsed vs. unparsed lines. Anything scoring 70+ (configurable via `RISK_THRESHOLD` in `src/config.py`) ends up in the `quarantine` table for review.

## Configuration

All tunable behavior lives in `src/config.py`:

| Setting  |  Purpose |
| `RISK_THRESHOLD` | Score at which an entry is also copied to `quarantine` |
| `EVENTS_WEIGHT` | Points added per event type (SQL injection, failed login, etc.) |
| `HIGH_RISK_USER` / `HIGH_RISK_USER_BONUS` | Flags logins from accounts like `root`, `admin` |
| `HIGH_RISK_AGENTS` / `HIGH_RISK_AGENTS_BONUS` | Flags scanner/tool user agents (sqlmap, nikto, nmap, etc.) |
| `BRUTE_FORCE_LIMIT` / `BRUTE_FORCE_BONUS` | Repeated-failure threshold per IP, within a single run |
| `OFF_HOURS_START` / `OFF_HOURS_END` / `OFF_HOURS_BONUS` | Flags activity outside normal hours |

## Project structure

LogSentinel/
├── .env.example
├── .gitignore
├── README.md
├── requirements.txt
├── data/                        # you create this; holds the log files to process
│   └── .gitkeep                 # optional, keeps the empty folder tracked by git
└── src/
    ├── __init__.py
    ├── main.py                  # entry point — calls process_all_logs()
    ├── parsing_logs.py          # orchestrates reading, parsing, scoring, saving
    ├── parser_function.py       # dispatcher — tries each parser in turn
    ├── analyzer.py              # risk-scoring logic
    ├── config.py                # all tunables + DB connection settings
    ├── db.py                    # MySQL insert logic (events + quarantine)
    ├── threat_analysis.py       # get_connection() stub (not wired into main flow)
    ├── scratch.py               # personal test file (not part of the pipeline)
    ├── schema.sql               # creates the LogSentinel database + tables
    └── parsers/
        ├── __init__.py
        ├── common.py            # shared syslog regex + timestamp normalizer
        ├── ssh_parser.py        # SSH/auth log parser
        ├── firewall_parser.py   # UFW firewall log parser
        ├── web_parser.py        # Apache/Nginx access log parser
        ├── json_parser.py       # single-line JSON app log parser
        └── keyvalue_parser.py   # key=value app log parser

## Troubleshooting

**Windows: `'mysql' is not recognized as an internal or external command`**

This means MySQL is installed, but its `bin` folder isn't in your Windows PATH, so the terminal can't find the `mysql` command. Two options:

1. **One-off fix** — run the command using the full path to `mysql.exe` instead of just `mysql`. It's usually somewhere like: C:\Program Files\MySQL\MySQL Server <version>\bin\mysql.exe

Example:
```powershell
"C:\Program Files\MySQL\MySQL Server 8.0\bin\mysql.exe" -u root -p < src/schema.sql
```

2. **Permanent fix** — add that `bin` folder to your PATH environment variable:
- Search "Edit the system environment variables" in the Start menu
- Environment Variables → select `Path` under System variables → Edit → New → paste the `bin` folder path → OK
- Close and reopen your terminal, then `mysql` will work normally from anywhere.

If `mysql.exe` doesn't exist anywhere on your machine at all, you likely only installed MySQL Workbench (a GUI) and not MySQL Server itself — install MySQL Server from [dev.mysql.com](https://dev.mysql.com/downloads/mysql/), or just load `src/schema.sql` through MySQL Workbench's "Run SQL Script" option instead of the command line.

## License

This project is licensed under the [MIT License](LICENSE).