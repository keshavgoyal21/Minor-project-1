#!/usr/bin/env python3

import argparse

from dotenv import load_dotenv
load_dotenv()

from scanner.network import scan_target
from api.Api import query_nvd
from output.formatter import print_results

load_dotenv()


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

    # CWE (Vulnerability Type)
    cwe = "Unknown"
    weaknesses = cve.get("weaknesses", [])
    if weaknesses:
        cwe = weaknesses[0]["description"][0]["value"]

    # CVSS
    severity = "Unknown"
    score = "N/A"
    metrics = cve.get("metrics", {})
    if "cvssMetricV31" in metrics:
        cvss = metrics["cvssMetricV31"][0]["cvssData"]
        score = cvss["baseScore"]
        severity = cvss["baseSeverity"]

    # Exploit / reference URLs
    references = []
    for ref in cve.get("references", []):
        url = ref.get("url", "")
        if any(x in url.lower() for x in ["exploit", "github", "packetstorm"]):
            references.append(url)

    return {
        "cve_id": cve_id,
        "description": description,
        "cwe": cwe,
        "cvss_score": score,
        "severity": severity,
        "references": references
    }


def preventive_measures(cwe):
    cwe = cwe.lower()

    if "sql" in cwe:
        return "Use parameterized queries, input validation, least privilege DB access"
    if "xss" in cwe:
        return "Apply output encoding, CSP, sanitize user input"
    if "path traversal" in cwe:
        return "Normalize file paths, restrict file access, patch affected software"
    if "buffer overflow" in cwe:
        return "Use bounds checking, safe libraries, enable ASLR/DEP"
    if "authentication" in cwe:
        return "Implement strong authentication, MFA, secure password storage"

    return "Apply vendor patches, upgrade software, follow secure configuration guidelines"


def main():
    banner()

    parser = argparse.ArgumentParser(
        description="API-driven vulnerability discovery tool"
    )

    parser.add_argument(
        "-t", "--target",
        required=True,
        help="IP, Domain, or Network CIDR"
    )

    parser.add_argument(
        "-p", "--ports",
        default="common",
        help="Ports to scan (common or comma-separated list)"
    )

    parser.add_argument(
        "-o", "--output",
        choices=["text", "json"],
        default="text",
        help="Output format"
    )

    args = parser.parse_args()

    results = scan_target(args.target, args.ports)

    # === CVE ENRICHMENT ===
    for host in results["hosts"]:
        for port in host["open_ports"]:
            meta = port.get("meta")
            if not meta:
                continue

            raw_vulns = query_nvd(
                cpe=meta.get("cpe"),
                keyword=meta.get("keyword")
            )

            enriched_vulns = []
            for v in raw_vulns:
                parsed = parse_cve(v)
                parsed["mitigation"] = preventive_measures(parsed["cwe"])
                enriched_vulns.append(parsed)

            port["vulnerabilities"] = enriched_vulns

    print_results(results, args.output)


if __name__ == "__main__":
    main()
