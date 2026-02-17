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


def banner():
    print("""
========================================
 VulnScan - API Driven Vulnerability Tool
 API-based Vulnerability Correlation
========================================
""")


def parse_cve(cve_item):
    cve = cve_item["cve"]

    cve_id = cve["id"]
    description = cve["descriptions"][0]["value"]

    cwe = "Unknown"
    weaknesses = cve.get("weaknesses", [])
    if weaknesses:
        cwe = weaknesses[0]["description"][0]["value"]

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
                limit=20   # Increased limit
            )

            enriched_vulns = []

            for v in raw_vulns:
                parsed = parse_cve(v)
                parsed["mitigation"] = preventive_measures(parsed["cwe"])

                exploits = search_exploit_by_cve(parsed["cve_id"])
                parsed["exploits"] = exploits
                parsed["exploit_available"] = bool(exploits)

                enriched_vulns.append(parsed)

            port["vulnerabilities"] = enriched_vulns

    print_results(results, args.output)


if __name__ == "__main__":
    main()
