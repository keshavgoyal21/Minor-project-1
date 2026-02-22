import json
import textwrap

# ANSI Colors
RED     = "\033[91m"
YELLOW  = "\033[93m"
GREEN   = "\033[92m"
CYAN    = "\033[96m"
BOLD    = "\033[1m"
DIM     = "\033[2m"
RESET   = "\033[0m"

SEV_COLOR = {
    "CRITICAL": RED, "HIGH": RED, "MEDIUM": YELLOW,
    "LOW": GREEN, "NONE": DIM, "Unknown": DIM,
}

W = 70  # max width


def _sev(s):
    return f"{SEV_COLOR.get(s, DIM)}{s}{RESET}"


def _wrap(text, width=60, pad=8):
    return ("\n" + " " * pad).join(textwrap.wrap(text, width))


def print_vuln_table(vulns):
    hdr = f"{'No':<4} {'CVE ID':<16} {'Severity':<10} {'Score':<6} {'Exploit':<8} {'Type'}"
    print(f"\n      {BOLD}{hdr}{RESET}")
    print(f"      {'─' * W}")

    for i, v in enumerate(vulns, 1):
        ex = f"{RED}YES{RESET}" if v.get("exploit_available") else "NO"
        sv = _sev(v["severity"])
        # pad extra for hidden ANSI chars
        cwe = v["cwe"][:30]
        print(f"      {i:<4} {v['cve_id']:<16} {sv:<19} {str(v['cvss_score']):<6} {ex:<17} {cwe}")

    print(f"      {'─' * W}")


def print_detailed_vulns(vulns):
    print(f"\n      {BOLD}{CYAN}Detailed Vulnerability Intelligence{RESET}")

    for i, v in enumerate(vulns, 1):
        print(f"\n      {BOLD}{'═' * W}{RESET}")
        print(f"      {BOLD}[{i}] {v['cve_id']}{RESET}")
        print(f"      {'─' * W}")
        print(f"      Severity      : {_sev(v['severity'])}")
        print(f"      CVSS Score    : {BOLD}{v['cvss_score']}{RESET}")
        print(f"      CWE Type      : {v['cwe']}")
        print(f"      Published     : {v.get('published', 'N/A')}")
        print(f"      Last Modified : {v.get('last_modified', 'N/A')}")

        if v.get("mitigation"):
            print(f"      Mitigation    : {CYAN}{v['mitigation']}{RESET}")

        print(f"\n      {BOLD}Description:{RESET}")
        print(f"      {_wrap(v['description'])}")

        if v.get("exploit_available"):
            print(f"\n      {RED}{BOLD}⚠  Exploit Available{RESET}")
            for exp in v["exploits"]:
                print(f"         → {exp['exploit_url']}")
        else:
            print(f"\n      {GREEN}✓  No known exploits{RESET}")

    print(f"\n      {'═' * W}")


def print_results(data, mode):
    if mode == "json":
        print(json.dumps(data, indent=2))
        return

    print(f"\n{'═' * W}")
    print(f"{BOLD}  SCAN RESULTS{RESET}")
    print(f"{'═' * W}")
    print(f"  Target : {data.get('target', 'N/A')}")
    print(f"  Time   : {data.get('scan_time', 'N/A')}")

    for host in data["hosts"]:
        print(f"\n  {BOLD}Host: {host['ip']}{RESET}")
        print(f"  {'─' * (W - 2)}")

        if not host["open_ports"]:
            print(f"  {DIM}No open ports found{RESET}")
            continue

        for port in host["open_ports"]:
            print(f"\n  {GREEN}{BOLD}[+] Port {port['port']}{RESET} — {BOLD}OPEN{RESET}")

            info = []
            if port.get("service"):
                info.append(f"Service : {port['service']}")
            if port.get("version"):
                info.append(f"Version : {port['version']}")

            meta = port.get("meta")
            if meta:
                if meta.get("vendor"):
                    info.append(f"Vendor  : {meta['vendor']}")
                if meta.get("product"):
                    info.append(f"Product : {meta['product']}")
                if meta.get("cpe"):
                    info.append(f"CPE     : {meta['cpe']}")

            for line in info:
                print(f"      {line}")

            vulns = port.get("vulnerabilities")
            if not vulns:
                print(f"      {DIM}No known CVEs found{RESET}")
                continue

            print(f"      {BOLD}Found {len(vulns)} CVE(s){RESET}")
            print_vuln_table(vulns)
            print_detailed_vulns(vulns)

    print(f"\n{'═' * W}")
    print(f"  {DIM}Scan complete.{RESET}")
    print(f"{'═' * W}\n")
