import json


def print_results(data, mode):
    if mode == "json":
        print(json.dumps(data, indent=2))
        return

    print("\nScan Results")
    print("-" * 50)

    for host in data["hosts"]:
        print(f"\nHost: {host['ip']}")

        if not host["open_ports"]:
            print("  No open ports found")
            continue

        for port in host["open_ports"]:
            print(f"  [+] Port {port['port']} OPEN")

            if port.get("service"):
                print(f"      Service: {port['service']}")

            if port.get("version"):
                print(f"      Version: {port['version']}")

            if port.get("banner"):
                print(f"      Banner: {port['banner'][:80]}")

            meta = port.get("meta")
            if meta:
                print(f"      Vendor: {meta.get('vendor')}")
                print(f"      Product: {meta.get('product')}")
                print(f"      CPE: {meta.get('cpe')}")

            if port.get("vulnerabilities"):
                print("      Vulnerabilities:")
                for v in port["vulnerabilities"]:
                    print(f"        - {v['cve_id']}")
