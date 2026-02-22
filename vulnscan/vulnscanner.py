#!/usr/bin/env python3

import sys
import time
import itertools
from dotenv import load_dotenv
load_dotenv()

from scanner.network import scan_target
from api.Api import query_nvd
from api.exploitdb import search_exploit_by_cve
from output.formatter import print_results


# =========================
# ANSI COLORS
# =========================
RED = "\033[91m"
GREEN = "\033[92m"
CYAN = "\033[96m"
YELLOW = "\033[93m"
RESET = "\033[0m"
BOLD_ANSI = "\033[1m"


def type_writer(text, delay=0.02):
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(delay)
    print()


def loading_animation(text, duration=3):
    spinner = itertools.cycle(["|", "/", "-", "\\"])
    end_time = time.time() + duration
    while time.time() < end_time:
        sys.stdout.write(f"\r{CYAN}{text} {next(spinner)}{RESET}")
        sys.stdout.flush()
        time.sleep(0.1)
    print(f"\r{GREEN}{text} ✔{RESET}")


def show_banner():
    logo = f"""
{RED}{BOLD_ANSI}
██╗   ██╗██╗   ██╗██╗     ███╗   ██╗███████╗ ██████╗ █████╗ ███╗   ██╗
██║   ██║██║   ██║██║     ████╗  ██║██╔════╝██╔════╝██╔══██╗████╗  ██║
██║   ██║██║   ██║██║     ██╔██╗ ██║███████╗██║     ███████║██╔██╗ ██║
╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║╚════██║██║     ██╔══██║██║╚██╗██║
 ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║███████║╚██████╗██║  ██║██║ ╚████║
  ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
{RESET}
{GREEN}            >> API-Driven Vulnerability Intelligence Engine <<
{RESET}
"""
    print(logo)


def kali_startup():
    type_writer(f"{CYAN}Initializing VulnScan Engine...{RESET}")
    time.sleep(0.5)
    loading_animation("Loading CVE Database")
    loading_animation("Connecting to NVD API")
    loading_animation("Connecting to Exploit-DB")
    loading_animation("Preparing Scan Modules")
    print(f"\n{GREEN}[+] System Ready. Happy Hunting 😈{RESET}\n")


def get_severity_from_score(score):
    """Convert CVSS score to severity level (for CVSS v2 compatibility)"""
    try:
        score = float(score)
        if score == 0:
            return "NONE"
        elif score < 3.9:
            return "LOW"
        elif score < 6.9:
            return "MEDIUM"
        elif score < 8.9:
            return "HIGH"
        else:
            return "CRITICAL"
    except (ValueError, TypeError):
        return "Unknown"


# Common CWE ID to readable name mapping
CWE_NAMES = {
    "CWE-20": "Improper Input Validation",
    "CWE-22": "Path Traversal",
    "CWE-77": "Command Injection",
    "CWE-78": "OS Command Injection",
    "CWE-79": "Cross-site Scripting (XSS)",
    "CWE-89": "SQL Injection",
    "CWE-94": "Code Injection",
    "CWE-119": "Buffer Overflow",
    "CWE-120": "Buffer Copy without Size Check",
    "CWE-125": "Out-of-bounds Read",
    "CWE-190": "Integer Overflow",
    "CWE-200": "Information Exposure",
    "CWE-264": "Permissions / Privileges / Access Control",
    "CWE-269": "Improper Privilege Management",
    "CWE-276": "Incorrect Default Permissions",
    "CWE-287": "Improper Authentication",
    "CWE-295": "Improper Certificate Validation",
    "CWE-310": "Cryptographic Issues",
    "CWE-312": "Cleartext Storage of Sensitive Info",
    "CWE-352": "Cross-Site Request Forgery (CSRF)",
    "CWE-362": "Race Condition",
    "CWE-399": "Resource Management Errors",
    "CWE-400": "Uncontrolled Resource Consumption",
    "CWE-416": "Use After Free",
    "CWE-434": "Unrestricted File Upload",
    "CWE-476": "NULL Pointer Dereference",
    "CWE-502": "Deserialization of Untrusted Data",
    "CWE-522": "Insufficiently Protected Credentials",
    "CWE-601": "Open Redirect",
    "CWE-611": "XML External Entity (XXE)",
    "CWE-667": "Improper Locking",
    "CWE-732": "Incorrect Permission Assignment",
    "CWE-787": "Out-of-bounds Write",
    "CWE-798": "Hard-coded Credentials",
    "CWE-863": "Incorrect Authorization",
    "CWE-918": "Server-Side Request Forgery (SSRF)",
}


def resolve_cwe(weaknesses):
    """Extract the most specific CWE from weaknesses list, skipping NVD placeholders."""
    generic_values = {"NVD-CWE-Other", "NVD-CWE-noinfo"}
    best_cwe = None
    fallback_cwe = None

    for weakness in weaknesses:
        for desc in weakness.get("description", []):
            value = desc.get("value", "")
            if value in generic_values:
                fallback_cwe = fallback_cwe or value
            elif value.startswith("CWE-"):
                best_cwe = value
                break
        if best_cwe:
            break

    cwe_id = best_cwe or fallback_cwe or "Unknown"

    # Resolve to a readable name
    if cwe_id in CWE_NAMES:
        return f"{cwe_id} ({CWE_NAMES[cwe_id]})"
    elif cwe_id == "NVD-CWE-Other":
        return "Other (Unclassified)"
    elif cwe_id == "NVD-CWE-noinfo":
        return "No CWE Info Available"
    return cwe_id


def parse_cve(cve_item):
    cve = cve_item["cve"]

    cve_id = cve["id"]
    description = cve["descriptions"][0]["value"]

    weaknesses = cve.get("weaknesses", [])
    cwe = resolve_cwe(weaknesses)

    severity = "Unknown"
    score = "N/A"

    metrics = cve.get("metrics", {})
    
    # Try different CVSS metric versions (V31, V30, V2)
    if "cvssMetricV31" in metrics:
        cvss = metrics["cvssMetricV31"][0]["cvssData"]
        score = cvss["baseScore"]
        severity = cvss["baseSeverity"]
    elif "cvssMetricV30" in metrics:
        cvss = metrics["cvssMetricV30"][0]["cvssData"]
        score = cvss["baseScore"]
        severity = cvss["baseSeverity"]
    elif "cvssMetricV2" in metrics:
        cvss = metrics["cvssMetricV2"][0]["cvssData"]
        score = cvss["baseScore"]
        # CVSS V2 doesn't have baseSeverity, we'll derive it from score
        severity = get_severity_from_score(score)

    published = cve.get("published", "N/A")
    last_modified = cve.get("lastModified", "N/A")

    references = []
    for ref in cve.get("references", []):
        references.append(ref.get("url"))

    return {
        "cve_id": cve_id,
        "description": description,
        "cwe": cwe,
        "cvss_score": score,
        "severity": severity,
        "published": published,
        "last_modified": last_modified,
        "references": references
    }


def preventive_measures(cwe):
    cwe = cwe.lower()

    if "sql" in cwe:
        return "Use parameterized queries and input validation"
    if "xss" in cwe:
        return "Sanitize user input and use output encoding"
    if "path traversal" in cwe:
        return "Normalize file paths and patch software"
    if "buffer overflow" in cwe:
        return "Use safe libraries and enable ASLR/DEP"
    if "authentication" in cwe:
        return "Implement MFA and strong password policies"

    return "Apply vendor patches and upgrade software"


def run_scan(target, ports, num_cves, output_mode):
    """Execute the scan with the given parameters."""
    print(f"\n{CYAN}[*] Scanning target: {BOLD_ANSI}{target}{RESET}")
    print(f"{CYAN}[*] Ports: {ports}{RESET}")
    print(f"{CYAN}[*] Max CVEs per port: {num_cves}{RESET}")
    print(f"{CYAN}[*] Output mode: {output_mode}{RESET}\n")

    loading_animation("Scanning ports", duration=2)

    results = scan_target(target, ports)

    total_open = sum(len(h["open_ports"]) for h in results["hosts"])
    if total_open == 0:
        print(f"{YELLOW}[!] No open ports found on {target}{RESET}")
        print(f"{YELLOW}    Tip: Make sure the target is up and try different ports.{RESET}\n")
        return

    loading_animation("Querying NVD for vulnerabilities", duration=2)

    for host in results["hosts"]:
        for port in host["open_ports"]:
            meta = port.get("meta")
            if not meta:
                continue

            raw_vulns = query_nvd(
                cpe=meta.get("cpe"),
                keyword=meta.get("keyword"),
                limit=max(20, num_cves)
            )

            enriched_vulns = []

            for v in raw_vulns:
                parsed = parse_cve(v)
                parsed["mitigation"] = preventive_measures(parsed["cwe"])

                exploits = search_exploit_by_cve(parsed["cve_id"])
                parsed["exploits"] = exploits
                parsed["exploit_available"] = bool(exploits)

                enriched_vulns.append(parsed)

            enriched_vulns.sort(
                key=lambda v: float(v["cvss_score"]) if v["cvss_score"] != "N/A" else -1,
                reverse=True
            )

            port["vulnerabilities"] = enriched_vulns[:num_cves]

    print_results(results, output_mode)


def show_help():
    """Display available commands."""
    print(f"""
  {BOLD_ANSI}Available Commands:{RESET}
  ─────────────────────────────────────────────────────
  {GREEN}scan{RESET}          Start a new vulnerability scan
  {GREEN}set{RESET}           Set a scan option  (e.g. set target 10.0.0.1)
  {GREEN}options{RESET}       Show current scan configuration
  {GREEN}help{RESET}          Show this help menu
  {GREEN}clear{RESET}         Clear the screen
  {GREEN}exit{RESET}          Exit VulnScan
  ─────────────────────────────────────────────────────

  {BOLD_ANSI}Set Options:{RESET}
  ─────────────────────────────────────────────────────
  {YELLOW}set target{RESET}    <ip/hostname/CIDR>     Target to scan
  {YELLOW}set ports{RESET}     <port1,port2 | common>  Ports to scan
  {YELLOW}set cves{RESET}      <number>                Max CVEs per port
  {YELLOW}set output{RESET}    <text | json>           Output format
  ─────────────────────────────────────────────────────
""")


def show_options(config):
    """Display current scan configuration."""
    target_val = config["target"] or f"{RED}(not set){RESET}"
    print(f"""
  {BOLD_ANSI}Current Configuration:{RESET}
  ─────────────────────────────────────────────────────
  {CYAN}TARGET{RESET}     =>  {target_val}
  {CYAN}PORTS{RESET}      =>  {config['ports']}
  {CYAN}MAX CVEs{RESET}   =>  {config['num_cves']}
  {CYAN}OUTPUT{RESET}     =>  {config['output']}
  ─────────────────────────────────────────────────────
""")


def interactive_cli():
    """Main interactive CLI loop — like Metasploit / sqlmap."""
    config = {
        "target": None,
        "ports": "common",
        "num_cves": 10,
        "output": "text",
    }

    PROMPT = f"{RED}vulnscan{RESET} > "

    show_help()

    while True:
        try:
            raw = input(PROMPT).strip()
        except (KeyboardInterrupt, EOFError):
            print(f"\n{GREEN}[+] Exiting VulnScan. Stay safe! 👋{RESET}\n")
            break

        if not raw:
            continue

        parts = raw.split()
        cmd = parts[0].lower()

        # ── exit ──
        if cmd in ("exit", "quit", "q"):
            print(f"\n{GREEN}[+] Exiting VulnScan. Stay safe! 👋{RESET}\n")
            break

        # ── help ──
        elif cmd in ("help", "h", "?"):
            show_help()

        # ── clear ──
        elif cmd == "clear":
            print("\033c", end="")
            show_banner()

        # ── options ──
        elif cmd in ("options", "show", "config"):
            show_options(config)

        # ── set ──
        elif cmd == "set":
            if len(parts) < 3:
                print(f"  {YELLOW}Usage: set <option> <value>{RESET}")
                print(f"  {YELLOW}Options: target, ports, cves, output{RESET}")
                continue

            option = parts[1].lower()
            value = " ".join(parts[2:])

            if option == "target":
                config["target"] = value
                print(f"  {GREEN}TARGET => {value}{RESET}")

            elif option in ("ports", "port"):
                config["ports"] = value
                print(f"  {GREEN}PORTS => {value}{RESET}")

            elif option in ("cves", "num-cves", "num_cves", "n"):
                try:
                    config["num_cves"] = int(value)
                    print(f"  {GREEN}MAX CVEs => {value}{RESET}")
                except ValueError:
                    print(f"  {RED}[!] Invalid number: {value}{RESET}")

            elif option == "output":
                if value in ("text", "json"):
                    config["output"] = value
                    print(f"  {GREEN}OUTPUT => {value}{RESET}")
                else:
                    print(f"  {RED}[!] Output must be 'text' or 'json'{RESET}")

            else:
                print(f"  {RED}[!] Unknown option: {option}{RESET}")
                print(f"  {YELLOW}Options: target, ports, cves, output{RESET}")

        # ── scan ──
        elif cmd in ("scan", "run", "start"):
            if not config["target"]:
                print(f"  {RED}[!] Target not set. Use: set target <ip/hostname>{RESET}")
                continue

            run_scan(
                target=config["target"],
                ports=config["ports"],
                num_cves=config["num_cves"],
                output_mode=config["output"],
            )

        # ── unknown ──
        else:
            print(f"  {RED}[!] Unknown command: {cmd}{RESET}")
            print(f"  {YELLOW}Type 'help' for available commands{RESET}")


def main():
    show_banner()
    kali_startup()
    interactive_cli()


if __name__ == "__main__":
    main()