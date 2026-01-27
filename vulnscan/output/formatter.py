import json

def print_results(data, mode):
    if mode == "json":
        print(json.dumps(data, indent=2))
        return

    print("\nScan Results")
    print("-" * 40)

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
            if port["banner"]:
                print(f"      Banner: {port['banner'][:60]}")
