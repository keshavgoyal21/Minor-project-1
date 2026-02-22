import json
import re
import textwrap

# ── ANSI Colors ──────────────────────────────────────
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"

SEV_COLOR = {
    "CRITICAL": RED, "HIGH": RED, "MEDIUM": YELLOW,
    "LOW": GREEN, "NONE": DIM, "Unknown": DIM,
}


def _c(severity):
    """Return colored severity string."""
    color = SEV_COLOR.get(severity, DIM)
    return f"{color}{severity}{RESET}"


def _wrap(text, width=56, pad=6):
    """Word-wrap long text."""
    prefix = " " * pad
    return ("\n" + prefix).join(textwrap.wrap(text, width))


def _trunc(text, length):
    """Truncate text with ellipsis if needed."""
    if len(text) <= length:
        return text
    return text[:length - 1] + "…"


def _vlen(s):
    """Visible length of a string (excluding ANSI escape codes & OSC 8 hyperlinks)."""
    s = str(s)
    s = re.sub(r'\033\]8;;[^\a]*\a', '', s)   # strip OSC 8 hyperlink sequences
    s = re.sub(r'\033\[[0-9;]*m', '', s)          # strip SGR color codes
    return len(s)


def _pad(s, width, align='left'):
    """Pad string to visible width, correctly ignoring ANSI codes."""
    diff = max(0, width - _vlen(s))
    if align == 'center':
        left = diff // 2
        return ' ' * left + s + ' ' * (diff - left)
    elif align == 'right':
        return ' ' * diff + s
    return s + ' ' * diff


# ── Port Info Table ──────────────────────────────────
def print_port_info(port):
    meta = port.get("meta")
    rows = []
    if port.get("service"):
        rows.append(("Service", port["service"]))
    if port.get("version"):
        rows.append(("Version", port["version"]))
    if meta:
        if meta.get("vendor"):
            rows.append(("Vendor", meta["vendor"]))
        if meta.get("product"):
            rows.append(("Product", meta["product"]))
        if meta.get("cpe"):
            rows.append(("CPE", meta["cpe"]))

    if not rows:
        return

    kw = 9   # key width
    vw = 48  # value width
    tw = kw + vw + 5  # total inner width (+5 for borders/padding)

    print(f"  ┌{'─' * tw}┐")
    for key, val in rows:
        print(f"  │ {CYAN}{key:<{kw}}{RESET} │ {val:<{vw}} │")
    print(f"  └{'─' * tw}┘")


# ── CVE Summary Table ────────────────────────────────
def print_vuln_table(vulns):
    # Column widths: No(3) CVE(15) Sev(9) Score(6) Exp(4) Type(22)
    print(f"\n  {BOLD}┌{'─' * 3}┬{'─' * 17}┬{'─' * 11}┬{'─' * 7}┬{'─' * 6}┬{'─' * 24}┐{RESET}")
    print(f"  {BOLD}│{'#':^3}│ {'CVE ID':<15} │ {'Severity':<9} │ {'Score':^5} │ {'Exp':^4} │ {'Type':<22} │{RESET}")
    print(f"  {BOLD}├{'─' * 3}┼{'─' * 17}┼{'─' * 11}┼{'─' * 7}┼{'─' * 6}┼{'─' * 24}┤{RESET}")

    for i, v in enumerate(vulns, 1):
        sev_str = _c(v["severity"])
        exp_str = f"{RED}✘{RESET}" if v.get("exploit_available") else f"{GREEN}✔{RESET}"
        cwe_short = _trunc(v["cwe"], 22)
        score = str(v["cvss_score"])

        print(f"  │{i:^3}│ {v['cve_id']:<15} │ {_pad(sev_str, 9)} │ {score:^5} │ {_pad(exp_str, 4, 'center')} │ {cwe_short:<22} │")

    print(f"  {BOLD}└{'─' * 3}┴{'─' * 17}┴{'─' * 11}┴{'─' * 7}┴{'─' * 6}┴{'─' * 24}┘{RESET}")
    print(f"  {DIM}  ✔ = No exploit   ✘ = Exploit available{RESET}")


# ── Detailed CVE Cards ───────────────────────────────
def print_detailed_vulns(vulns):
    bw = 66  # box inner width

    print(f"\n  {BOLD}{CYAN}▶ Detailed Vulnerability Intelligence{RESET}\n")

    for i, v in enumerate(vulns, 1):
        sev = _c(v["severity"])

        # ── Card header ──
        title = f" [{i}] {v['cve_id']} "
        pad_total = bw - len(f" [{i}] {v['cve_id']} ")
        pad_left = pad_total // 2
        pad_right = pad_total - pad_left
        print(f"  ╔{'═' * pad_left}{BOLD}{title}{RESET}{'═' * pad_right}╗")

        # ── Card body ──
        def row(key, val, val_fmt=""):
            vf = val_fmt if val_fmt else str(val)
            print(f"  ║  {DIM}{key:<14}{RESET} {_pad(vf, bw - 18)} ║")

        row("Severity",      v["severity"],   sev)
        row("CVSS Score",    v["cvss_score"],  f"{BOLD}{v['cvss_score']}{RESET}")
        row("CWE Type",      v["cwe"])
        row("Published",     v.get("published", "N/A"))
        row("Last Modified", v.get("last_modified", "N/A"))

        if v.get("mitigation"):
            row("Mitigation", v["mitigation"], f"{CYAN}{v['mitigation']}{RESET}")

        # ── Description ──
        print(f"  ║{'─' * bw}║")
        print(f"  ║  {BOLD}Description{RESET}{' ' * (bw - 13)}║")
        desc_lines = textwrap.wrap(v["description"], width=bw - 4)
        for line in desc_lines:
            print(f"  ║  {line:<{bw - 2}}║")

        # ── Exploit status ──
        print(f"  ║{'─' * bw}║")
        if v.get("exploit_available"):
            label = f"{RED}{BOLD}⚠  Exploit Available{RESET}"
            print(f"  ║  {_pad(label, bw - 2)}║")
            for exp in v["exploits"]:
                url = exp["exploit_url"]
                # OSC 8 clickable hyperlink: \033]8;;URL\a DISPLAY \033]8;;\a
                link = f"\033]8;;{url}\a{CYAN}{url}{RESET}\033]8;;\a"
                print(f"  ║    → {_pad(link, bw - 6)}║")
        else:
            label = f"{GREEN}✔  No known exploits{RESET}"
            print(f"  ║  {_pad(label, bw - 2)}║")

        # ── Card footer ──
        print(f"  ╚{'═' * bw}╝\n")


# ── Main Output ──────────────────────────────────────
def print_results(data, mode):
    if mode == "json":
        print(json.dumps(data, indent=2))
        return

    tw = 68  # total width

    print(f"\n  {'═' * tw}")
    print(f"  {BOLD}{'SCAN RESULTS':^{tw}}{RESET}")
    print(f"  {'═' * tw}")
    print(f"  Target : {data.get('target', 'N/A')}")
    print(f"  Time   : {data.get('scan_time', 'N/A')}")

    for host in data["hosts"]:
        print(f"\n  {BOLD}┌─ Host: {host['ip']}{RESET}")
        print(f"  {'─' * tw}")

        if not host["open_ports"]:
            print(f"  {DIM}  No open ports found{RESET}")
            continue

        for port in host["open_ports"]:
            print(f"\n  {GREEN}{BOLD}  [+] Port {port['port']}{RESET} — {BOLD}OPEN{RESET}")
            print_port_info(port)

            vulns = port.get("vulnerabilities")
            if not vulns:
                print(f"  {DIM}  No known CVEs found{RESET}")
                continue

            print(f"  {BOLD}  Found {len(vulns)} CVE(s):{RESET}")
            print_vuln_table(vulns)
            print_detailed_vulns(vulns)

    print(f"\n  {'═' * tw}")
    print(f"  {DIM}Scan complete.{RESET}")
    print(f"  {'═' * tw}\n")
