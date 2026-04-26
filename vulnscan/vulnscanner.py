#!/usr/bin/env python3

import sys
import os
import time
import itertools
import importlib.util

dotenv_spec = importlib.util.find_spec("dotenv")
if dotenv_spec is not None:
    dotenv = importlib.import_module("dotenv")
    load_dotenv = getattr(dotenv, "load_dotenv", None)
    if callable(load_dotenv):
        # Load .env from the same directory as this script
        _env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
        load_dotenv(_env_path)

from scanner.network import scan_target
from scanner.behavior import build_host_profile, generate_findings, generate_nvd_keywords, detect_anomalies
from scanner.packets import analyze_pcap, SCAPY_AVAILABLE
from scanner.monitor import monitor_target
import scanner.ai_agent as ai_agent
from scanner.ai_agent import (
    analyze_vulnerabilities,
    analyze_network_behavior,
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

MAX_AI_CALLS = 2
AI_CALL_DELAY = 2
_QUERY_CACHE = {}


def type_writer(text, delay=0.02):
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(delay)
    print()


def loading_animation(text, duration=3, enabled=True):
    if not enabled or not getattr(sys.stdout, "isatty", lambda: False)():
        return
    spinner = itertools.cycle(["|", "/", "-", "\\"])
    end_time = time.time() + duration
    while time.time() < end_time:
        sys.stdout.write(f"\r{CYAN}{text} {next(spinner)}{RESET}")
        sys.stdout.flush()
        time.sleep(0.1)
    print(f"\r{GREEN}{text} [OK]{RESET}")


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


def _enrich_cves_from_keywords(keywords, num_cves, stop_requested=None):
    """Query NVD for each keyword, parse CVEs, enrich with exploits.

    Returns a list of enriched CVE dicts.  Uses caching and early stop.
    """
    seen_ids = set()
    enriched = []

    for kw in keywords:
        if stop_requested and callable(stop_requested) and stop_requested():
            break

        raw_vulns = query_nvd(keyword=kw, limit=max(5, num_cves), stop_requested=stop_requested)
        for v in raw_vulns:
            if stop_requested and callable(stop_requested) and stop_requested():
                break

            parsed = parse_cve(v)
            if parsed["cve_id"] in seen_ids:
                continue
            seen_ids.add(parsed["cve_id"])

            parsed["mitigation"] = preventive_measures(parsed["cwe"])
            exploits = search_exploit_by_cve(parsed["cve_id"], stop_requested=stop_requested)
            parsed["exploits"] = exploits
            parsed["exploit_available"] = bool(exploits)
            parsed["source_keyword"] = kw
            enriched.append(parsed)

        time.sleep(0.5)

    enriched.sort(
        key=lambda v: float(v["cvss_score"]) if v["cvss_score"] != "N/A" else -1,
        reverse=True,
    )
    return enriched[:num_cves]


def run_behavior_analysis(scan_results, pcap_path=None, num_cves=5, skip_cve_enrichment=False, stop_requested=None):
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
            behavior_cves = _enrich_cves_from_keywords(keywords, num_cves, stop_requested=stop_requested)

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
        if stop_requested and callable(stop_requested) and stop_requested():
            return behavior_results
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
                    pattern_cves = _enrich_cves_from_keywords(unique_kw, num_cves, stop_requested=stop_requested)

                pkt_result["pattern_keywords"] = unique_kw
                pkt_result["pattern_cves"] = pattern_cves
                behavior_results["packet_analysis"] = pkt_result

    return behavior_results


def run_scan(target, ports, num_cves, output_mode, pcap_path=None, ai_enabled=True, monitor_duration=0, stop_requested=None, pretty_output=True, step_callback=None):
    """Execute the scan with the given parameters."""
    quiet = output_mode == "json"
    def _log(message="", *args, **kwargs):
        if quiet:
            return
        print(message, *args, **kwargs)

    def _send_step(step, status):
        if callable(step_callback):
            try:
                step_callback({"step": step, "status": status})
            except Exception:
                pass

    def _normalize_text(value):
        if value is None:
            return ""
        if isinstance(value, (list, tuple)):
            return " ".join(str(v) for v in value if v is not None)
        return str(value)

    def _build_ai_analysis_items(ai_results):
        items = []
        if not isinstance(ai_results, dict):
            return items

        vuln_intel = ai_results.get("vulnerability_intel", {}) or {}
        for chain in vuln_intel.get("exploit_chains", []):
            items.append({
                "severity": chain.get("severity", "MEDIUM") or "MEDIUM",
                "finding": chain.get("chain_name", "Exploit chain analysis"),
                "reason": _normalize_text(chain.get("explanation", "")),
                "recommendation": _normalize_text(chain.get("steps", [])),
            })

        for action in vuln_intel.get("priority_actions", []):
            items.append({
                "severity": "ACTION",
                "finding": _normalize_text(action),
                "reason": "",
                "recommendation": "",
            })

        behavior_intel = ai_results.get("behavior_intel") or {}
        if behavior_intel:
            items.append({
                "severity": "INFO",
                "finding": _normalize_text(behavior_intel.get("anomaly_assessment") or behavior_intel.get("summary") or "Behavior intelligence available."),
                "reason": _normalize_text(behavior_intel.get("ids_ips_detection") or behavior_intel.get("firewall_detection") or behavior_intel.get("honeypot_indicators") or ""),
                "recommendation": _normalize_text(behavior_intel.get("recommended_actions") or behavior_intel.get("suggestions") or ""),
            })

        for zd in ai_results.get("zero_day_assessment", []) or []:
            items.append({
                "severity": zd.get("risk_level", "INFO") or "INFO",
                "finding": _normalize_text(zd.get("assessment_summary") or zd.get("summary") or "Zero-day risk assessment"),
                "reason": _normalize_text(zd.get("suspicious_indicators") or zd.get("potential_attack_vectors") or ""),
                "recommendation": _normalize_text(zd.get("recommended_monitoring") or zd.get("recommended_actions") or ""),
            })

        return items

    def _build_ai_mitigation(ai_results):
        mitigation = {"summary": "", "steps": []}
        if not isinstance(ai_results, dict):
            return mitigation

        vuln_intel = ai_results.get("vulnerability_intel", {}) or {}
        mitigation["summary"] = _normalize_text(vuln_intel.get("overall_risk_summary") or "Use standard hardening, patch exposed services, and validate network access controls.")

        cve_mitigations = vuln_intel.get("cve_mitigations", {}) or {}
        if isinstance(cve_mitigations, dict) and cve_mitigations:
            mitigation["steps"] = [f"{cve}: {text}" for cve, text in cve_mitigations.items() if text]
        elif vuln_intel.get("priority_actions"):
            mitigation["steps"] = [str(item) for item in vuln_intel.get("priority_actions", []) if item]
        else:
            mitigation["steps"] = ["Patch vulnerable services, restrict exposed ports, and harden network access controls."]

        return mitigation

    _log(f"\n{CYAN}[*] Scanning target: {BOLD_ANSI}{target}{RESET}")
    _log(f"{CYAN}[*] Ports: {ports}{RESET}")
    _log(f"{CYAN}[*] Max CVEs per port: {num_cves}{RESET}")
    _log(f"{CYAN}[*] Output mode: {output_mode}{RESET}")
    if pcap_path:
        _log(f"{CYAN}[*] PCAP file: {pcap_path}{RESET}")
    ai_active = ai_enabled and ai_agent.GEMINI_AVAILABLE
    _log(f"{CYAN}[*] AI Agent: {'enabled' if ai_active else 'disabled'}{RESET}")
    if monitor_duration > 0:
        _log(f"{CYAN}[*] Active monitoring: {monitor_duration}s{RESET}")
    if not quiet:
        _log()

    _send_step("Scanning ports", "running")
    loading_animation("Scanning ports", duration=2, enabled=not quiet)

    results = scan_target(target, ports, stop_requested=stop_requested)
    _send_step("Scanning ports", "done")

    total_open = sum(len(h["open_ports"]) for h in results["hosts"])
    if total_open == 0:
        _log(f"{YELLOW}[!] No open ports found on {target}{RESET}")
        _log(f"{YELLOW}    Tip: Make sure the target is up and try different ports.{RESET}\n")
        _send_step("Querying NVD", "done")
        return results

    _send_step("Querying NVD", "running")
    loading_animation("Querying NVD for vulnerabilities", duration=2, enabled=not quiet)

    for host in results["hosts"]:
        for port in host["open_ports"]:
            meta = port.get("meta")
            if not meta:
                continue

            raw_vulns = query_nvd(
                cpe=meta.get("cpe"),
                keyword=meta.get("keyword"),
                limit=max(20, num_cves),
                stop_requested=stop_requested,
            )

            enriched_vulns = []

            for v in raw_vulns:
                if stop_requested and callable(stop_requested) and stop_requested():
                    break
                parsed = parse_cve(v)
                parsed["mitigation"] = preventive_measures(parsed["cwe"])
                exploits = search_exploit_by_cve(parsed["cve_id"], stop_requested=stop_requested)
                parsed["exploits"] = exploits
                parsed["exploit_available"] = bool(exploits)
                enriched_vulns.append(parsed)

            enriched_vulns.sort(
                key=lambda v: float(v["cvss_score"]) if v["cvss_score"] != "N/A" else -1,
                reverse=True
            )

            port["vulnerabilities"] = enriched_vulns[:num_cves]

    _send_step("Querying NVD", "done")

    # ── Behavior analysis ────────────────────────────────────────────
    _send_step("Behavior analysis", "running")
    loading_animation("Running behavior analysis", duration=2, enabled=not quiet)
    behavior_results = run_behavior_analysis(
        results, pcap_path=pcap_path, num_cves=num_cves,
        skip_cve_enrichment=ai_active,
        stop_requested=stop_requested,
    )
    results["behavior_results"] = behavior_results
    _send_step("Behavior analysis", "done")

    # ── Active monitoring (if configured) ────────────────────────────
    monitoring_data = None
    if monitor_duration > 0:
        open_ports = []
        for host in results["hosts"]:
            for p in host["open_ports"]:
                open_ports.append(p["port"])
        if open_ports:
            target_ip = results["hosts"][0]["ip"]
            _log(f"\n  {CYAN}[*] Starting active monitoring for {monitor_duration}s...{RESET}")
            _log(f"  {CYAN}    Probing {len(open_ports)} ports every 5 seconds{RESET}")
            monitoring_data = monitor_target(target_ip, open_ports, duration=monitor_duration, stop_requested=stop_requested)
    # ── Local Fallback Generators ────────────────────────────────────
    def _build_local_fallback_intel(scan_results):
        cve_mits = {}
        chains = []
        actions = [
            "Apply vendor patches to all identified vulnerable services immediately.",
            "Restrict network access to critical ports using a firewall.",
            "Implement strict access controls and monitor anomalous traffic."
        ]
        
        for host in scan_results.get("hosts", []):
            for port in host.get("open_ports", []):
                for v in port.get("vulnerabilities", []):
                    cve_mits[v["cve_id"]] = v.get("mitigation", "Update to the latest version and apply vendor patches.")
                    
                    try:
                        score = float(v.get("cvss_score", 0))
                    except ValueError:
                        score = 0.0
                        
                    if score >= 7.0:
                        chains.append({
                            "chain_name": f"Potential exploit of {v['cve_id']}",
                            "severity": v.get("severity", "HIGH"),
                            "likelihood": "MEDIUM",
                            "steps": [
                                f"Attacker identifies exposed port {port['port']} ({port.get('service', 'unknown')})",
                                f"Attacker exploits {v['cve_id']} leveraging {v.get('cwe', 'Unknown Weakness')}",
                                "Attacker gains unauthorized access, extracts data, or causes denial of service"
                            ],
                            "explanation": v.get("description", "Vulnerability exploitation.")[:250] + "..."
                        })
        
        return {
            "overall_risk_summary": "Local analysis indicates exposed services with known vulnerabilities. Immediate patching and network restriction is recommended. (Generated via Local Fallback Engine)",
            "cve_mitigations": cve_mits,
            "exploit_chains": chains[:5],
            "priority_actions": actions
        }

    def _build_local_behavior_intel():
        return {
            "anomaly_assessment": "Local behavior analysis detects typical port exposure patterns with no critical anomalies. (Generated via Local Fallback Engine)",
            "firewall_detection": {
                "detected": False,
                "confidence": 50,
                "evidence": ["No packet filtering or stateful inspection blocked the scan"]
            },
            "ids_ips_detection": {"detected": False},
            "honeypot_indicators": {"detected": False},
            "zero_day_risks": []
        }

    # ── AI Security Agent ────────────────────────────────────────────
    results["analysis"] = ""
    results["mitigation"] = ""
    results["ai_chain"] = {}
    results["ai_analysis"] = None
    results["ai_mitigation"] = {"summary": "", "steps": []}
    results["ai_analysis_items"] = []
    if ai_active:
        _send_step("AI analysis", "running")
        loading_animation("AI Agent analyzing scan data", duration=2, enabled=not quiet)
        ai_analysis = {}

        try:
            _log(f"  {CYAN}[AI] Analyzing vulnerabilities...{RESET}")
            vuln_intel = analyze_vulnerabilities(results, behavior_results, monitoring_data)
            if not vuln_intel:
                _log(f"  {YELLOW}[AI] API unavailable or rate-limited. Generating local fallback intelligence...{RESET}")
                vuln_intel = _build_local_fallback_intel(results)

            if vuln_intel:
                ai_analysis["vulnerability_intel"] = vuln_intel
                cve_mitigations = vuln_intel.get("cve_mitigations", {}) or {}
                for host in results["hosts"]:
                    for port in host["open_ports"]:
                        for vuln in port.get("vulnerabilities", []):
                            ai_mit = cve_mitigations.get(vuln["cve_id"])
                            if ai_mit:
                                vuln["ai_analysis"] = {
                                    "severity": vuln.get("severity", "INFO"),
                                    "finding": f"Mitigation available for {vuln['cve_id']}",
                                    "reason": ai_mit,
                                    "recommendation": ai_mit,
                                }
                                vuln["ai_mitigation"] = {
                                    "summary": f"AI mitigation for {vuln['cve_id']}",
                                    "steps": [ai_mit] if isinstance(ai_mit, str) else [str(ai_mit)],
                                }
                            else:
                                vuln["ai_analysis"] = {
                                    "severity": vuln.get("severity", "INFO"),
                                    "finding": "AI analysis unavailable",
                                    "reason": "No structured mitigation data returned for this CVE.",
                                    "recommendation": "Review the vulnerability and apply vendor patches.",
                                }
                                vuln["ai_mitigation"] = {
                                    "summary": "No AI mitigation available.",
                                    "steps": [],
                                }

            if behavior_results:
                time.sleep(AI_CALL_DELAY)
                _log(f"  {CYAN}[AI] Analyzing network behavior...{RESET}")
                pkt_data = behavior_results.get("packet_analysis")
                behavior_intel = analyze_network_behavior(behavior_results, pkt_data)
                if not behavior_intel:
                    behavior_intel = _build_local_behavior_intel()
                if behavior_intel:
                    ai_analysis["behavior_intel"] = behavior_intel

            if ai_analysis:
                results["ai_analysis"] = ai_analysis
                results["analysis"] = ai_analysis.get("vulnerability_intel", {}).get("overall_risk_summary", "") or results["analysis"]
                results["ai_chain"] = ai_analysis.get("vulnerability_intel", {})
                results["ai_mitigation"] = {
                    "summary": ai_analysis.get("vulnerability_intel", {}).get("overall_risk_summary", "Use standard hardening and patch management."),
                    "steps": [str(step) for step in ai_analysis.get("vulnerability_intel", {}).get("priority_actions", []) if step] or ["Review the AI vulnerability report and apply the recommended mitigations."],
                }
                _log(f"  {GREEN}[AI] Analysis complete [OK]{RESET}")
            else:
                _log(f"  {YELLOW}[AI] No analysis results returned{RESET}")

        except Exception as e:
            _log(f"  {YELLOW}[AI] Analysis failed: {e}{RESET}")
            _log(f"  {YELLOW}      Scan results are still valid.{RESET}")
            results["ai_analysis"] = None

        if isinstance(results["ai_analysis"], dict):
            ai_items = _build_ai_analysis_items(results["ai_analysis"])
            if ai_items:
                results["ai_analysis_items"] = ai_items
            else:
                results["ai_analysis_items"] = [{
                    "severity": "INFO",
                    "finding": "AI unavailable",
                    "reason": "The AI service returned no structured findings.",
                    "recommendation": "Check your Gemini API key and try again later.",
                }]
        else:
            if not ai_agent.GEMINI_API_KEY:
                reason = "GEMINI_API_KEY is not set in the current process environment."
                recommendation = "Set GEMINI_API_KEY in .env or the shell environment and restart the backend."
            elif not getattr(ai_agent, "_GEMINI_SDK", False):
                reason = "Gemini SDK is not installed in the backend environment."
                recommendation = "Install google-genai or google-generativeai in the same Python environment as the backend."
            else:
                reason = "Gemini unavailable or rate-limited."
                recommendation = "Validate GEMINI_API_KEY and retry later."

            results["ai_analysis_items"] = [{
                "severity": "INFO",
                "finding": "AI service failed",
                "reason": reason,
                "recommendation": recommendation,
            }]
            results["ai_mitigation"] = {
                "summary": "AI analysis unavailable.",
                "steps": ["Ensure GEMINI_API_KEY is configured correctly.", "Retry the scan after a short delay."],
            }

        _send_step("AI analysis", "done")

    else:
        results["ai_analysis_items"] = [{
            "severity": "INFO",
            "finding": "AI agent disabled.",
            "reason": "Gemini AI is not enabled or not configured.",
            "recommendation": "Enable AI or configure GEMINI_API_KEY.",
        }]

    _send_step("Scan complete", "done")

    if not results.get("analysis"):
        results["analysis"] = "AI analysis unavailable. Review the scan output and secure exposed services manually."
    if not results.get("mitigation"):
        results["mitigation"] = results["ai_mitigation"]["summary"]
    if not results.get("ai_chain"):
        results["ai_chain"] = {}

    if pretty_output:
        print_results(results, output_mode)
    return results


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
    gemini_status = f"{GREEN}available{RESET}" if ai_agent.GEMINI_AVAILABLE else f"{YELLOW}no API key{RESET}"
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