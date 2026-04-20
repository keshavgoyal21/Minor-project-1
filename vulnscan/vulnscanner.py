#!/usr/bin/env python3

import sys
import os
import time
import itertools
try:
    from dotenv import load_dotenv
    # Load .env from the same directory as this script
    _env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
    load_dotenv(_env_path)
except ImportError:
    pass  # .env loading optional — set env vars manually if python-dotenv is missing

from scanner.network import scan_target
from scanner.behavior import build_host_profile, generate_findings, generate_nvd_keywords, detect_anomalies
from scanner.packets import analyze_pcap, SCAPY_AVAILABLE
from scanner.monitor import monitor_target
from scanner.ai_agent import (
    GEMINI_AVAILABLE, analyze_vulnerabilities,
    analyze_network_behavior, assess_zero_day_risk,
    _refresh_availability,
)
from api.Api import query_nvd
from api.exploitdb import search_exploit_by_cve
from output.formatter import print_results, print_monitor_report


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
    loading_animation("Loading Behavior Engine")
    if SCAPY_AVAILABLE:
        loading_animation("Packet Analyzer Ready (Scapy)")
    else:
        print(f"  {YELLOW}[~] Scapy not installed — packet analysis disabled{RESET}")
    # Re-check Gemini availability (load_dotenv may have run after initial import)
    _refresh_availability()
    from scanner.ai_agent import GEMINI_AVAILABLE as _ai_ready
    if _ai_ready:
        loading_animation("AI Security Agent Ready (Gemini)")
    else:
        print(f"  {YELLOW}[~] Gemini AI not configured — set GEMINI_API_KEY in .env{RESET}")
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


def _enrich_cves_from_keywords(keywords, num_cves):
    """Query NVD for each keyword, parse CVEs, enrich with exploits.

    Returns a list of enriched CVE dicts.  Adds a 1-second delay between
    NVD calls to respect rate limits.
    """
    seen_ids = set()
    enriched = []

    for kw in keywords:
        raw_vulns = query_nvd(keyword=kw, limit=max(5, num_cves))
        for v in raw_vulns:
            parsed = parse_cve(v)
            if parsed["cve_id"] in seen_ids:
                continue
            seen_ids.add(parsed["cve_id"])

            parsed["mitigation"] = preventive_measures(parsed["cwe"])
            exploits = search_exploit_by_cve(parsed["cve_id"])
            parsed["exploits"] = exploits
            parsed["exploit_available"] = bool(exploits)
            parsed["source_keyword"] = kw
            enriched.append(parsed)

        # Respect NVD rate limits
        time.sleep(1)

    # Sort by CVSS score descending
    enriched.sort(
        key=lambda v: float(v["cvss_score"]) if v["cvss_score"] != "N/A" else -1,
        reverse=True,
    )
    return enriched[:num_cves]


def run_behavior_analysis(scan_results, pcap_path=None, num_cves=5, skip_cve_enrichment=False):
    """Build behavior profiles, run packet analysis, and optionally enrich with CVEs.

    Parameters
    ----------
    scan_results : dict
        The results dict from ``scan_target()``.
    pcap_path : str | None
        Optional path to a ``.pcap`` file for packet-pattern analysis.
    num_cves : int
        Max behavior-driven CVEs to return per source.
    skip_cve_enrichment : bool
        If True, skip NVD keyword lookups (AI handles intelligence instead).

    Returns
    -------
    dict  with keys: host_profiles, packet_analysis
    """
    behavior_results = {
        "host_profiles": [],
        "packet_analysis": None,
    }

    # ── Per-host behavior profiling ──────────────────────────────────
    for host in scan_results.get("hosts", []):
        profile = build_host_profile(host)
        findings = generate_findings(profile)
        keywords = generate_nvd_keywords(profile, findings)
        anomalies = detect_anomalies(host)

        # Behavior-driven CVE enrichment (skipped when AI handles intelligence)
        behavior_cves = []
        if not skip_cve_enrichment and keywords:
            behavior_cves = _enrich_cves_from_keywords(keywords, num_cves)

        behavior_results["host_profiles"].append({
            "ip": profile["ip"],
            "risk_score": profile["risk_score"],
            "risk_level": profile["risk_level"],
            "profile": profile,
            "findings": findings,
            "anomalies": anomalies,
            "nvd_keywords": keywords,
            "behavior_cves": behavior_cves,
        })

    # ── Packet analysis (optional) ───────────────────────────────────
    if pcap_path:
        if not SCAPY_AVAILABLE:
            print(f"  {YELLOW}[!] Scapy is not installed — skipping pcap analysis.{RESET}")
            print(f"  {YELLOW}    Install with: pip install scapy{RESET}")
        elif not os.path.isfile(pcap_path):
            print(f"  {YELLOW}[!] PCAP file not found: {pcap_path}{RESET}")
        else:
            loading_animation("Analyzing packet capture", duration=2)
            pkt_result = analyze_pcap(pcap_path)

            if pkt_result:
                # Collect NVD keywords from all detected patterns
                pattern_keywords = []
                for pat in pkt_result.get("patterns", []):
                    pattern_keywords.extend(pat.get("nvd_keywords", []))

                # De-duplicate
                seen = set()
                unique_kw = []
                for kw in pattern_keywords:
                    if kw.lower() not in seen:
                        seen.add(kw.lower())
                        unique_kw.append(kw)
                unique_kw = unique_kw[:5]

                # Enrich with CVEs (skipped when AI handles intelligence)
                pattern_cves = []
                if not skip_cve_enrichment and unique_kw:
                    pattern_cves = _enrich_cves_from_keywords(unique_kw, num_cves)

                pkt_result["pattern_keywords"] = unique_kw
                pkt_result["pattern_cves"] = pattern_cves
                behavior_results["packet_analysis"] = pkt_result

    return behavior_results


def run_scan(target, ports, num_cves, output_mode, pcap_path=None, ai_enabled=True, monitor_duration=0):
    """Execute the scan with the given parameters."""
    print(f"\n{CYAN}[*] Scanning target: {BOLD_ANSI}{target}{RESET}")
    print(f"{CYAN}[*] Ports: {ports}{RESET}")
    print(f"{CYAN}[*] Max CVEs per port: {num_cves}{RESET}")
    print(f"{CYAN}[*] Output mode: {output_mode}{RESET}")
    if pcap_path:
        print(f"{CYAN}[*] PCAP file: {pcap_path}{RESET}")
    ai_active = ai_enabled and GEMINI_AVAILABLE
    print(f"{CYAN}[*] AI Agent: {'enabled' if ai_active else 'disabled'}{RESET}")
    if monitor_duration > 0:
        print(f"{CYAN}[*] Active monitoring: {monitor_duration}s{RESET}")
    print()

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

    # ── Behavior analysis ────────────────────────────────────────────
    loading_animation("Running behavior analysis", duration=2)
    behavior_results = run_behavior_analysis(
        results, pcap_path=pcap_path, num_cves=num_cves,
        skip_cve_enrichment=ai_active,
    )
    results["behavior_results"] = behavior_results

    # ── Active monitoring (if configured) ────────────────────────────
    monitoring_data = None
    if monitor_duration > 0:
        open_ports = []
        for host in results["hosts"]:
            for p in host["open_ports"]:
                open_ports.append(p["port"])
        if open_ports:
            target_ip = results["hosts"][0]["ip"]
            print(f"\n  {CYAN}[*] Starting active monitoring for {monitor_duration}s...{RESET}")
            print(f"  {CYAN}    Probing {len(open_ports)} ports every 5 seconds{RESET}")
            monitoring_data = monitor_target(target_ip, open_ports, duration=monitor_duration)
            results["monitoring"] = monitoring_data
            print(f"  {GREEN}[+] Monitoring complete: {monitoring_data['total_rounds']} rounds, "
                  f"{len(monitoring_data['anomalies'])} anomalies detected{RESET}")

    # ── AI Security Agent ────────────────────────────────────────────
    results["ai_analysis"] = None
    if ai_active:
        loading_animation("AI Agent analyzing scan data", duration=2)
        ai_analysis = {}

        try:
            # 1. Vulnerability intelligence (with monitoring data)
            print(f"  {CYAN}[AI] Analyzing vulnerabilities...{RESET}")
            vuln_intel = analyze_vulnerabilities(results, behavior_results, monitoring_data)
            if vuln_intel:
                ai_analysis["vulnerability_intel"] = vuln_intel

                # Inject AI mitigations into CVE entries
                cve_mitigations = vuln_intel.get("cve_mitigations", {})
                if cve_mitigations:
                    for host in results["hosts"]:
                        for port in host["open_ports"]:
                            for vuln in port.get("vulnerabilities", []):
                                ai_mit = cve_mitigations.get(vuln["cve_id"])
                                if ai_mit:
                                    vuln["mitigation"] = ai_mit
                                    vuln["ai_mitigation"] = True

            # 2. Network behavior analysis
            print(f"  {CYAN}[AI] Analyzing network behavior...{RESET}")
            pkt_data = behavior_results.get("packet_analysis")
            behavior_intel = analyze_network_behavior(behavior_results, pkt_data)
            if behavior_intel:
                ai_analysis["behavior_intel"] = behavior_intel

            # 3. Zero-day risk assessment (per host)
            print(f"  {CYAN}[AI] Assessing zero-day risks...{RESET}")
            zeroday_results = []
            for hp in behavior_results.get("host_profiles", []):
                profile = hp.get("profile", {})
                findings = hp.get("findings", [])
                pkt_patterns = []
                if pkt_data:
                    pkt_patterns = pkt_data.get("patterns", [])
                zd = assess_zero_day_risk(profile, findings, pkt_patterns)
                if zd:
                    zd["ip"] = hp["ip"]
                    zeroday_results.append(zd)
            if zeroday_results:
                ai_analysis["zero_day_assessment"] = zeroday_results

            if ai_analysis:
                results["ai_analysis"] = ai_analysis
                print(f"  {GREEN}[AI] Analysis complete ✔{RESET}")
            else:
                print(f"  {YELLOW}[AI] No analysis results returned{RESET}")

        except Exception as e:
            print(f"  {YELLOW}[AI] Analysis failed: {e}{RESET}")
            print(f"  {YELLOW}      Scan results are still valid.{RESET}")

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
  {YELLOW}set pcap{RESET}      <file path>             PCAP for packet analysis
  {YELLOW}set ai{RESET}        <on | off>              Toggle AI agent
  {YELLOW}set monitor{RESET}   <seconds>               Active monitoring duration
  ─────────────────────────────────────────────────────
""")


def show_options(config):
    """Display current scan configuration."""
    target_val = config["target"] or f"{RED}(not set){RESET}"
    pcap_val = config["pcap"] or f"{YELLOW}(none){RESET}"
    scapy_status = f"{GREEN}available{RESET}" if SCAPY_AVAILABLE else f"{YELLOW}not installed{RESET}"
    ai_toggle = f"{GREEN}on{RESET}" if config["ai"] else f"{YELLOW}off{RESET}"
    gemini_status = f"{GREEN}available{RESET}" if GEMINI_AVAILABLE else f"{YELLOW}no API key{RESET}"
    monitor_val = f"{config['monitor']}s" if config['monitor'] > 0 else f"{YELLOW}(off){RESET}"
    print(f"""
  {BOLD_ANSI}Current Configuration:{RESET}
  ─────────────────────────────────────────────────────
  {CYAN}TARGET{RESET}     =>  {target_val}
  {CYAN}PORTS{RESET}      =>  {config['ports']}
  {CYAN}MAX CVEs{RESET}   =>  {config['num_cves']}
  {CYAN}OUTPUT{RESET}     =>  {config['output']}
  {CYAN}PCAP{RESET}       =>  {pcap_val}
  {CYAN}SCAPY{RESET}      =>  {scapy_status}
  {CYAN}AI AGENT{RESET}   =>  {ai_toggle}
  {CYAN}GEMINI{RESET}     =>  {gemini_status}
  {CYAN}MONITOR{RESET}    =>  {monitor_val}
  ─────────────────────────────────────────────────────
""")


def interactive_cli():
    """Main interactive CLI loop — like Metasploit / sqlmap."""
    config = {
        "target": None,
        "ports": "common",
        "num_cves": 5,
        "output": "text",
        "pcap": None,
        "ai": True,
        "monitor": 0,
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
                print(f"  {YELLOW}Options: target, ports, cves, output, pcap, ai, monitor{RESET}")
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

            elif option == "pcap":
                if os.path.isfile(value):
                    config["pcap"] = value
                    print(f"  {GREEN}PCAP => {value}{RESET}")
                else:
                    # Store it anyway — we'll warn at scan time
                    config["pcap"] = value
                    print(f"  {YELLOW}[~] PCAP => {value}  (file not found — will recheck at scan time){RESET}")

            elif option == "ai":
                if value.lower() in ("on", "true", "1", "yes"):
                    config["ai"] = True
                    print(f"  {GREEN}AI AGENT => on{RESET}")
                elif value.lower() in ("off", "false", "0", "no"):
                    config["ai"] = False
                    print(f"  {YELLOW}AI AGENT => off{RESET}")
                else:
                    print(f"  {RED}[!] AI must be 'on' or 'off'{RESET}")

            elif option == "monitor":
                try:
                    secs = int(value)
                    if secs < 0:
                        raise ValueError
                    config["monitor"] = secs
                    if secs > 0:
                        print(f"  {GREEN}MONITOR => {secs}s (active probing after scan){RESET}")
                    else:
                        print(f"  {YELLOW}MONITOR => off{RESET}")
                except ValueError:
                    print(f"  {RED}[!] Monitor must be a positive number of seconds{RESET}")

            else:
                print(f"  {RED}[!] Unknown option: {option}{RESET}")
                print(f"  {YELLOW}Options: target, ports, cves, output, pcap, ai, monitor{RESET}")

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
                pcap_path=config["pcap"],
                ai_enabled=config["ai"],
                monitor_duration=config["monitor"],
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