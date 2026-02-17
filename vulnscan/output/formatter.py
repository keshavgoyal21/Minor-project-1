import json


def print_vuln_table(vulns):
    print("\n      Vulnerability Details")
    print("      " + "-" * 110)
    print(f"{'CVE ID':15} {'Severity':10} {'Score':6} {'Exploit':8} {'Type'}")
    print("      " + "-" * 110)

    for v in vulns:
        exploit_flag = "YES" if v.get("exploit_available") else "NO"
        print(f"{v['cve_id']:15} {v['severity']:10} {str(v['cvss_score']):6} {exploit_flag:8} {v['cwe']}")


def print_detailed_vulns(vulns):
    print("\n      Detailed Vulnerability Intelligence")
    print("      " + "=" * 110)

    for v in vulns:
        print(f"\n      {v['cve_id']}")
        print(f"      Severity        : {v['severity']}")
        print(f"      CVSS Score      : {v['cvss_score']}")
        print(f"      CWE             : {v['cwe']}")
        print(f"      Published       : {v.get('published')}")
        print(f"      Last Modified   : {v.get('last_modified')}")
        print(f"      Mitigation      : {v.get('mitigation')}")

        print(f"\n      Description:")
        print(f"      {v['description']}")

        if v.get("exploit_available"):
            print("\n      Exploit Available: YES")
            for exp in v["exploits"]:
                print(f"      Exploit Link: {exp['exploit_url']}")
        else:
            print("\n      Exploit Available: NO")

        print("      " + "-" * 110)


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
            print_detailed_vulns(vulns)
