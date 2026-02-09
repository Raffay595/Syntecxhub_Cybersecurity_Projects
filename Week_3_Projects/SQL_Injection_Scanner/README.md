# SQL Injection Scanner

An ethical, lightweight **SQL Injection vulnerability scanner** built in Python.  
This tool tests web input parameters using common SQL injection payloads and detects **error-based SQL injection indicators** in server responses.

---

## Features

- Error-based SQL injection detection
- Safe, predefined SQL payloads
- Detection via common SQL error patterns
- Built-in rate limiting
- Concurrent scanning with thread pools
- Thread-safe logging with timestamps
- Safety check to block unauthorized targets

---

## How It Works

1. Sends crafted SQL payloads to input parameters
2. Analyzes HTTP responses for SQL error messages
3. Flags parameters that appear vulnerable
4. Logs confirmed findings to a file
5. Does **not exploit** vulnerabilities

---

## Legal & Ethical Notice

This tool must only be used on **authorized targets**.

Allowed examples:
- `http://localhost`
- `http://127.0.0.1`
- DVWA (Damn Vulnerable Web Application)

Unauthorized scanning of real websites is illegal and unethical.

---

## Requirements

- Python 3.8+
- requests library

---


## Configuration

Edit inside the script:

TARGET_URL = "http://localhost/dvwa/vulnerabilities/sqli/"
PARAMETERS = ["id"]
MAX_THREADS = 5
RATE_LIMIT = 0.5

### Output

-Console
-Displays vulnerable parameters
-Shows payload and error indicator
-Log File
-scan_log.txt

Includes timestamped vulnerability findings
