import json


def print_vuln_table(vulns):
    print("\n      Vulnerability Details")
    print("      " + "-" * 110)
    print(f"{'CVE ID':15} {'Severity':10} {'Score':6} {'Vulnerability Type'}")
    print("      " + "-" * 110)

    for v in vulns:
        print(f"{v['cve_id']:15} {v['severity']:10} {str(v['cvss_score']):6} {v['cwe']}")


def print_results(data, mode):
    if mode == "json":
        print(json.dumps(data, indent=2))
        return

    print("\nScan Results")
    print("=" * 60)

    for host in data["hosts"]:
        print(f"\nHost: {host['ip']}")

        if not host["open_ports"]:
            print("  No open ports found")
            continue

        for port in host["open_ports"]:
            print(f"\n  [+] Port {port['port']} OPEN")

            if port.get("service"):
                print(f"      Service : {port['service']}")

            if port.get("version"):
                print(f"      Version : {port['version']}")

            meta = port.get("meta")
            if meta:
                print(f"      Vendor  : {meta.get('vendor')}")
                print(f"      Product : {meta.get('product')}")
                print(f"      CPE     : {meta.get('cpe')}")

            vulns = port.get("vulnerabilities")
            if not vulns:
                print("      No known CVEs found")
                continue

            print_vuln_table(vulns)

            for v in vulns:
                print(f"\n        Description : {v['description']}")
                print(f"        Impact      : {v['severity']} severity vulnerability")
                print(f"        Mitigation  : {v['mitigation']}")

                if v["references"]:
                    print("        Exploit / References:")
                    for ref in v["references"][:3]:
                        print(f"          - {ref}")
