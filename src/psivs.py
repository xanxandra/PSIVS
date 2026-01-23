import argparse
import subprocess
import sys
import tempfile
import os
import webbrowser
import re
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse, parse_qs
from report import generate_html_report
from urllib.parse import urlparse

REPORT_DIR = Path("reports")
REPORT_DIR.mkdir(exist_ok=True)
BASE_DIR = Path(__file__).parent.resolve()
ENGINE_DIR = BASE_DIR / "engine"
WORDLIST_DIR = BASE_DIR / "wordlists"

def print_banner():
    print("Crawling target and testing discovered endpoints for injection vulnerabilities ... \n")

def run_katana(target):
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        output_file = tmp.name

    cmd = [
        "katana",
        "-u", target,
        "-silent",
        "-o", output_file
    ]

    subprocess.run(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    with open(output_file) as f:
        urls = [line.strip() for line in f if line.strip()]

    os.unlink(output_file)
    return urls

def filter_injectable_urls(urls):
    injectable = []

    for url in urls:
        parsed = urlparse(url)
        if parse_qs(parsed.query):
            injectable.append(url)

    return injectable

def parse_finding(output, url, vuln_type):
    param = None

    for line in output.splitlines():
        if line.lower().startswith("param:"):
            param = line.split(":", 1)[1].strip()

    if not param:
        return None

    return {
        "type": vuln_type,
        "url": url,
        "param": param,
        "suggestion": f"guides/{vuln_type.lower()}_guide.html"
    }

def run_scanner(scanner, urls, wordlist, vuln_type, findings):
    for url in urls:
        cmd = [
            sys.executable,
            str(scanner),
            "-u", url,
            "-w", str(wordlist)
        ]

        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        if "[VULNERABLE]" in result.stdout:
            print(result.stdout, end="")

            finding = parse_finding(result.stdout, url, vuln_type)
            if finding:
                findings.append(finding)

def url_to_filename(url):
    parsed = urlparse(url)

    # take hostname if it exists, fallback to path
    base = parsed.netloc or parsed.path

    # replace anything not filename-safe with hyphens
    safe = re.sub(r"[^a-zA-Z0-9.-]", "-", base)

    # collapse multiple hyphens
    safe = re.sub(r"-+", "-", safe).strip("-")

    return f"{safe}-findings.html"

def build_report_path(target_url):
    reports_dir = Path("reports")
    reports_dir.mkdir(exist_ok=True)

    base = url_to_filename(target_url).replace(".html", "")
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")

    return reports_dir / f"{base}-{timestamp}.html"

def main():
    parser = argparse.ArgumentParser(
        description="PSIVS (PUP Services Injection Vulnerability Scanner",
        epilog="""
Examples:

SQLi and XSS scan:
  python3 psivs.py \\
    -u http://testphp.vulnweb.com \\
    --sqli --xss

SQL injection only:
  python3 psivs.py \\
    -u http://example.com \\
    --sqli

XSS only:
  python3 psivs.py \\
    -u http://example.com \\
    --xss
""",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    parser.add_argument(
        "-u", "--url",
        required=True,
        help="base target URL (e.g. https://example.com)"
    )

    parser.add_argument("--sqli", action="store_true", help="enable SQL injection scanning")
    parser.add_argument("--xss", action="store_true", help="enable XSS scanning")

    parser.add_argument(
        "--sqli-wordlist",
        default=WORDLIST_DIR / "sqli_payloads.txt"
    )

    parser.add_argument(
        "--xss-wordlist",
        default=WORDLIST_DIR / "xss_payloads.txt"
    )
    parser.add_argument(
    "--no-open",
    action="store_true",
    help="do not automatically open the HTML report"
    )
    parser.add_argument(
    "--output",
    default=None,
    help="output HTML report file"
    )

    args = parser.parse_args()

    if not args.output:
        args.output = url_to_filename(args.url)

    if not args.sqli and not args.xss:
        parser.error("at least one scanner must be enabled (--sqli / --xss)")

    print_banner()

    urls = run_katana(args.url)
    targets = filter_injectable_urls(urls)

    if not targets:
        return

    findings = []

    try:
        if args.sqli:
            run_scanner(
                ENGINE_DIR/"sqli.py",
                targets,
                args.sqli_wordlist,
                "SQLI",
                findings
            )

        if args.xss:
            run_scanner(
                ENGINE_DIR/"xss.py",
                targets,
                args.xss_wordlist,
                "XSS",
                findings
            )

    except KeyboardInterrupt:
        pass

    if findings:
        report_path = build_report_path(args.url)
        generate_html_report(findings, report_path)
        print(f"[+] Report written to {report_path.resolve()}")

        if not args.no_open:
            try:
                webbrowser.open(report_path.resolve().as_uri())
                print("[+] Opening report in browser")
            except Exception:
                print("[!] Failed to open browser automatically")
                print(f"    Open manually: {report_path}")

    else:
        print("[+] No injection vulnerabilities found")

if __name__ == "__main__":
    main()

