#!/usr/bin/env python3

import argparse
from dotenv import load_dotenv
load_dotenv()

from scanner.network import scan_target
from api.Api import query_nvd
from api.exploitdb import search_exploit_by_cve
from output.formatter import print_results


def banner():
    print("""
========================================
 VulnScan - API Driven Vulnerability Tool
 API-based Vulnerability Correlation
========================================
""")


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


def main():
    banner()

    parser = argparse.ArgumentParser(
        description="API-driven vulnerability discovery tool"
    )

    parser.add_argument("-t", "--target", required=True)
    parser.add_argument("-p", "--ports", default="common")
    parser.add_argument("-o", "--output", choices=["text", "json"], default="text")
    parser.add_argument("-n", "--num-cves", type=int, default=10,
                        help="Number of CVEs to display per port (default: 10)")

    args = parser.parse_args()

    results = scan_target(args.target, args.ports)

    for host in results["hosts"]:
        for port in host["open_ports"]:
            meta = port.get("meta")
            if not meta:
                continue

            raw_vulns = query_nvd(
                cpe=meta.get("cpe"),
                keyword=meta.get("keyword"),
                limit=max(20, args.num_cves)  # Fetch enough to fill requested count
            )

            enriched_vulns = []

            for v in raw_vulns:
                parsed = parse_cve(v)
                parsed["mitigation"] = preventive_measures(parsed["cwe"])

                exploits = search_exploit_by_cve(parsed["cve_id"])
                parsed["exploits"] = exploits
                parsed["exploit_available"] = bool(exploits)

                enriched_vulns.append(parsed)

            # Sort by CVSS score descending (most critical first)
            enriched_vulns.sort(
                key=lambda v: float(v["cvss_score"]) if v["cvss_score"] != "N/A" else -1,
                reverse=True
            )

            # Limit to the requested number of CVEs
            port["vulnerabilities"] = enriched_vulns[:args.num_cves]

    print_results(results, args.output)


if __name__ == "__main__":
    main()
