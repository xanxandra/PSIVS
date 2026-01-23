import argparse
import requests
import urllib.parse
import time
import signal
import threading
import html
from concurrent.futures import ThreadPoolExecutor, as_completed

STOP_EVENT = threading.Event()

XSS_CONTEXT_HINTS = {
    "script": ["<script", "javascript:"],
    "attr": ["onerror=", "onload=", "onclick="],
    "html": ["<", ">", "\"", "'"]
}

def handle_sigint(signum, frame):
    STOP_EVENT.set()
    print("\n[INFO] interrupt received, stopping scan...")

def similarity(a, b):
    length = min(len(a), len(b))
    if length == 0:
        return 1.0
    matches = sum(1 for i in range(length) if a[i] == b[i])
    return matches / length

def injection_variants(value, payload):
    return [
        f"{value}{payload}",
        payload
    ]

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

def detect_xss(payload, response_text):
    if payload in response_text:
        return "Reflected (raw)"

    escaped = html.escape(payload)
    if escaped in response_text:
        return "Reflected (HTML-escaped)"

    lower = response_text.lower()
    for ctx, hints in XSS_CONTEXT_HINTS.items():
        for h in hints:
            if h in lower:
                return f"Possible XSS context: {ctx}"

    return None

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
    baseline_status
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

            result = detect_xss(payload, r.text)
            if result:
                return {
                    "type": "XSS",
                    "subtype": result,
                    "param": param,
                    "payload": payload
                }

            # DOM/content changes can hint injection points
            sim = similarity(r.text, baseline_text)
            if sim < 0.90:
                return {
                    "type": "Possible XSS (content diff)",
                    "param": param,
                    "payload": payload,
                    "similarity": round(sim, 3)
                }

            # Error-based XSS hints
            if baseline_status < 500 and r.status_code >= 500:
                return {
                    "type": "Server-side error (possible injection)",
                    "param": param,
                    "payload": payload,
                    "status": r.status_code
                }

    return None

def main():
    signal.signal(signal.SIGINT, handle_sigint)

    parser = argparse.ArgumentParser(
        description="Payload-driven XSS scanner",
        epilog="""
Examples:

GET:
  python3 xss.py \\
    -u "http://testphp.vulnweb.com/search.php?test=abc" \\
    -w xss_payloads/xss_payloads.txt 

POST:
  python3 xss.py \\
    -u "http://testphp.vulnweb.com/guestbook.php" \\
    -X POST \\
    -d "name=test&comment=test" \\
    -w xss_payloads/xss_payloads.txt 
""",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument("-u", "--url", required=True)
    parser.add_argument("-w", "--wordlist", required=True)
    parser.add_argument("-X", "--method", default="GET", choices=["GET", "POST"])
    parser.add_argument("-d", "--data")
    parser.add_argument("--threads", type=int, default=5)

    args = parser.parse_args()

    with open(args.wordlist) as f:
        payloads = [l.strip() for l in f if l.strip()]

    parsed = urllib.parse.urlparse(args.url)
    base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
    params = dict(urllib.parse.parse_qsl(parsed.query))
    data = dict(urllib.parse.parse_qsl(args.data)) if args.data else {}

    session = requests.Session()

    # Baseline request
    if args.method == "GET":
        baseline_resp, _ = send_request(session, "GET", base_url, params=params)
    else:
        baseline_resp, _ = send_request(session, "POST", base_url, data=data)

    baseline_text = baseline_resp.text
    baseline_status = baseline_resp.status_code

    targets = params if args.method == "GET" else data

    print(f"[INFO] target={base_url}")
    print(f"[INFO] method={args.method}")
    print(f"[INFO] params={list(targets.keys())}")
    print(f"[INFO] baseline_status={baseline_status}")

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
                    baseline_status
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

