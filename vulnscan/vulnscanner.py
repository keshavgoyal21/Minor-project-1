#!/usr/bin/env python3

import argparse
from scanner.network import scan_target
from output.formatter import print_results

def banner():
    print("""
========================================
 VulnScan - API Driven Vulnerability Tool
 Target: Web & IoT Environments
 Platform: Kali Linux
========================================
""")

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
    print_results(results, args.output)

if __name__ == "__main__":
    main()