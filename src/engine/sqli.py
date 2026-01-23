import argparse
import requests
import urllib.parse
import time
import signal
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

STOP_EVENT = threading.Event()

DB_ERRORS = {
    "MySQL/MariaDB": [
        "mysql", "mysqli", "mariadb",
        "you have an error in your sql syntax"
    ],
    "PostgreSQL": [
        "postgresql", "pg_query",
        "syntax error at or near"
    ],
    "MSSQL": [
        "sql server",
        "unclosed quotation mark",
        "incorrect syntax near"
    ],
    "Oracle": ["ora-"],
    "SQLite": ["sqlite", "sqliteexception"]
}

def handle_sigint(signum, frame):
    STOP_EVENT.set()
    print("\n[INFO] interrupt received, stopping scan...")

def detect_dbms(text):
    t = text.lower()
    for db, sigs in DB_ERRORS.items():
        for s in sigs:
            if s in t:
                return db
    return None

def similarity(a, b):
    length = min(len(a), len(b))
    if length == 0:
        return 1.0
    matches = sum(1 for i in range(length) if a[i] == b[i])
    return matches / length

def injection_variants(value, payload):
    return [f"{value}{payload}", payload]

def send_request(session, method, url, params=None, data=None):
    start = time.time()
    r = session.request(
        method,
        url,
        params=params,
        data=data,
        allow_redirects=True,
        timeout=20
    )
    elapsed = time.time() - start
    return r, elapsed

def resolve_redirects(session, method, url, params=None, data=None):
    r, _ = send_request(session, method, url, params=params, data=data)

    if r.history:
        print("[INFO] redirects:")
        for h in r.history:
            loc = h.headers.get("Location", "")
            print(f"  {h.status_code} -> {loc}")
        print(f"[INFO] final_url={r.url}")

    return r

def scan_param(
    session,
    method,
    base_url,
    param,
    value,
    payloads,
    params,
    data,
    baseline_text,
    baseline_time,
    baseline_status,
    time_threshold
):
    for payload in payloads:
        if STOP_EVENT.is_set():
            return None

        for injected_value in injection_variants(value, payload):
            if STOP_EVENT.is_set():
                return None

            if method == "GET":
                test_params = params.copy()
                test_params[param] = injected_value
                r, delay = send_request(session, "GET", base_url, params=test_params)
            else:
                test_data = data.copy()
                test_data[param] = injected_value
                r, delay = send_request(session, "POST", base_url, data=test_data)

            print(
                f"[{method}] param={param} "
                f"payload={payload!r} "
                f"status={r.status_code} "
                f"len={len(r.text)} "
                f"time={delay:.2f}s"
            )

            if r.status_code in (403, 406, 429):
                print("[INFO] response suggests filtering or WAF")

            db = detect_dbms(r.text)
            if db:
                return {
                    "type": "Error-based",
                    "db": db,
                    "param": param,
                    "payload": payload
                }

            if baseline_status < 500 and r.status_code >= 500:
                return {
                    "type": "HTTP Error-based (implied)",
                    "db": "Unknown",
                    "param": param,
                    "payload": payload,
                    "status": r.status_code
                }

            sim = similarity(r.text, baseline_text)
            if sim < 0.95:
                return {
                    "type": "Boolean-based",
                    "db": "Unknown",
                    "param": param,
                    "payload": payload,
                    "similarity": round(sim, 3)
                }

            if delay - baseline_time >= time_threshold:
                return {
                    "type": "Time-based",
                    "db": "Unknown",
                    "param": param,
                    "payload": payload,
                    "delay": round(delay, 2)
                }

    return None

def main():
    signal.signal(signal.SIGINT, handle_sigint)

    parser = argparse.ArgumentParser(
        description="Extensible SQL injection scanner (payload-driven)",
        epilog="""
Examples:

GET:
  python3 sqli.py \\
    -u "http://testphp.vulnweb.com/listproducts.php?cat=1" \\
    -w sqli_payloads/sqli_payloads.txt 

POST:
  python3 sqli.py \\
    -u "http://testphp.vulnweb.com/login.php" \\
    -X POST \\
    -d "username=admin&password=admin" \\
    -w sqli_payloads/sqli_payloads.txt 
""",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument("-u", "--url", required=True)
    parser.add_argument("-w", "--wordlist", required=True)
    parser.add_argument("-X", "--method", default="GET", choices=["GET", "POST"])
    parser.add_argument("-d", "--data")
    parser.add_argument("--threads", type=int, default=5)
    parser.add_argument("--time-threshold", type=int, default=4)

    args = parser.parse_args()

    with open(args.wordlist) as f:
        payloads = [l.strip() for l in f if l.strip()]

    parsed = urllib.parse.urlparse(args.url)
    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    params = dict(urllib.parse.parse_qsl(parsed.query))
    data = dict(urllib.parse.parse_qsl(args.data)) if args.data else {}

    session = requests.Session()

    # Baseline
    if args.method == "GET":
        baseline_resp = resolve_redirects(session, "GET", base_url, params=params)
    else:
        baseline_resp = resolve_redirects(session, "POST", base_url, data=data)

    baseline_text = baseline_resp.text
    baseline_time = baseline_resp.elapsed.total_seconds()
    baseline_status = baseline_resp.status_code

    final_parsed = urllib.parse.urlparse(baseline_resp.url)
    base_url = f"{final_parsed.scheme}://{final_parsed.netloc}{final_parsed.path}"
    final_params = dict(urllib.parse.parse_qsl(final_parsed.query))

    if args.method == "GET" and final_params != params:
        print("[WARNING] parameters changed after redirect")
        print(f"  before: {list(params.keys())}")
        print(f"  after : {list(final_params.keys())}")
        params = final_params or params

    targets = params if args.method == "GET" else data

    print(f"[INFO] target={base_url}")
    print(f"[INFO] method={args.method}")
    print(f"[INFO] params={list(targets.keys())}")
    print(f"[INFO] baseline_status={baseline_status}")
    print(f"[INFO] baseline_time={baseline_time:.2f}s")

    try:
        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            futures = [
                executor.submit(
                    scan_param,
                    session,
                    args.method,
                    base_url,
                    param,
                    value,
                    payloads,
                    params,
                    data,
                    baseline_text,
                    baseline_time,
                    baseline_status,
                    args.time_threshold
                )
                for param, value in targets.items()
            ]

            for future in as_completed(futures):
                if STOP_EVENT.is_set():
                    executor.shutdown(wait=False, cancel_futures=True)
                    return

                result = future.result()
                if result:
                    print("\n[VULNERABLE]")
                    for k, v in result.items():
                        print(f"{k}: {v}")
                    STOP_EVENT.set()
                    executor.shutdown(wait=False, cancel_futures=True)
                    return

    except KeyboardInterrupt:
        STOP_EVENT.set()
        print("\n[INFO] scan interrupted by user")

    print("\n[INFO] scan complete")

if __name__ == "__main__":
    main()

