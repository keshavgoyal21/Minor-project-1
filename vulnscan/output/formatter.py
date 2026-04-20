import json
import re
import textwrap
import unicodedata

# ── ANSI Colors ──────────────────────────────────────
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
MAGENTA = "\033[95m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"

SEV_COLOR = {
    "CRITICAL": RED, "HIGH": RED, "MEDIUM": YELLOW,
    "LOW": GREEN, "NONE": DIM, "Unknown": DIM, "INFO": CYAN,
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
    """Visible column-width of a string (strips ANSI codes, counts wide chars as 2)."""
    s = str(s)
    s = re.sub(r'\033\]8;;[^\a]*\a', '', s)   # strip OSC 8 hyperlink sequences
    s = re.sub(r'\033\[[0-9;]*m', '', s)          # strip SGR color codes
    width = 0
    for ch in s:
        eaw = unicodedata.east_asian_width(ch)
        width += 2 if eaw in ('W', 'F') else 1
    return width


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

    # Telemetry rows
    tel = port.get("telemetry", {})
    if tel.get("connect_ms") is not None:
        rows.append(("Latency", f"{tel['connect_ms']} ms"))
    if tel.get("response_ms") is not None:
        rows.append(("Response", f"{tel['response_ms']} ms"))

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
        exp_str = f"{GREEN}✔{RESET}" if v.get("exploit_available") else f"{RED}✘{RESET}"
        cwe_short = _trunc(v["cwe"], 22)
        score = str(v["cvss_score"])

        print(f"  │{i:^3}│ {v['cve_id']:<15} │ {_pad(sev_str, 9)} │ {score:^5} │ {_pad(exp_str, 4, 'center')} │ {cwe_short:<22} │")

    print(f"  {BOLD}└{'─' * 3}┴{'─' * 17}┴{'─' * 11}┴{'─' * 7}┴{'─' * 6}┴{'─' * 24}┘{RESET}")
    print(f"  {DIM} ✔ = No exploit   ✘ = Exploit available{RESET}")


# ── Detailed CVE Cards ───────────────────────────────
def print_detailed_vulns(vulns):
    # bw = visible chars between the two ║ on every row
    # Every row must satisfy: inner_visible == bw
    #
    # Row types and their formulas:
    #   row()   : "  " + key(14) + " " + val(bw-18) + " "  = bw  (row helper)
    #   section : "  " + content(bw-3) + " "                = bw  (_pad to bw-3)
    #   wrapped : "  " + plain_text(bw-4) + "  "            = bw  (f-string :<{bw-4})
    #   exploit : "    → " + url(bw-7) + " "               = bw  (_pad to bw-7)
    bw = 66

    print(f"\n  {BOLD}{CYAN}▶ Detailed Vulnerability Intelligence{RESET}\n")

    for i, v in enumerate(vulns, 1):
        sev = _c(v["severity"])

        # ── Card header ──
        title = f" [{i}] {v['cve_id']} "
        # bw - title_len must be even-ish; title has no ANSI codes
        pad_total = bw - len(title)
        pad_left  = pad_total // 2
        pad_right = pad_total - pad_left
        print(f"  ╔{'═' * pad_left}{BOLD}{title}{RESET}{'═' * pad_right}╗")

        # row(key, plain_val, colored_val)
        # inner = 2(margin) + 14(key) + 1(sep) + (bw-18)(val) + 1(right) = bw
        def row(key, plain, colored=""):
            c = colored if colored else str(plain)
            print(f"  ║  {DIM}{key:<14}{RESET} {_pad(c, bw - 18)} ║")

        # section_line(colored_content)
        # inner = 2(margin) + (bw-3)(content) + 1(right) = bw
        def section(colored):
            print(f"  ║  {_pad(colored, bw - 3)} ║")

        # text_line(plain_text)
        # inner = 2(margin) + (bw-4)(text) + 2(right) = bw
        def textline(plain):
            print(f"  ║  {plain:<{bw - 4}}  ║")

        row("Severity",      v["severity"],               sev)
        row("CVSS Score",    v["cvss_score"],              f"{BOLD}{v['cvss_score']}{RESET}")
        row("CWE Type",      v["cwe"])
        row("Published",     v.get("published",     "N/A"))
        row("Last Modified", v.get("last_modified", "N/A"))

        # ── Mitigation ──────────────────────────────────────────────
        if v.get("mitigation"):
            mit_text = v["mitigation"]
            if v.get("ai_mitigation"):
                print(f"  ║{'─' * bw}║")
                section(f"{GREEN}{BOLD}\U0001f916 AI Mitigation{RESET}")
                for line in textwrap.wrap(mit_text, width=bw - 4):
                    textline(line)
            else:
                row("Mitigation", mit_text, f"{CYAN}{mit_text}{RESET}")

        if v.get("source_keyword"):
            row("Source Query", v["source_keyword"],
                f"{MAGENTA}{v['source_keyword']}{RESET}")

        # ── Description ─────────────────────────────────────────────
        print(f"  ║{'─' * bw}║")
        section(f"{BOLD}Description{RESET}")
        for line in textwrap.wrap(v["description"], width=bw - 4):
            textline(line)

        # ── Exploit status ───────────────────────────────────────────
        print(f"  ║{'─' * bw}║")
        if v.get("exploit_available"):
            section(f"{RED}{BOLD}\u26a0  Exploit Available{RESET}")
            for exp in v.get("exploits", []):
                url  = exp.get("exploit_url", "")
                link = f"\033]8;;{url}\a{CYAN}{url}{RESET}\033]8;;\a"
                # inner = 4(→ prefix+space) + 2("  ") + (bw-7)(url) + 1(right) = bw
                print(f"  ║  \u2192 {_pad(link, bw - 5)} ║")
        else:
            section(f"{GREEN}\u2714  No known exploits{RESET}")

        # ── Card footer ──────────────────────────────────────────────
        print(f"  ╚{'═' * bw}╝\n")


# ══════════════════════════════════════════════════════
# BEHAVIOR ANALYSIS OUTPUT
# ══════════════════════════════════════════════════════

def _risk_bar(score, width=20):
    """Render an ASCII risk gauge: [████████░░░░░░░░░░░░]"""
    filled = int(score / 100 * width)
    empty = width - filled

    if score >= 75:
        color = RED
    elif score >= 50:
        color = YELLOW
    elif score >= 25:
        color = CYAN
    else:
        color = GREEN

    return f"{color}[{'█' * filled}{'░' * empty}]{RESET}"


def print_behavior_assessment(behavior_results, show_cves=True):
    """Print host behavior profiles, findings, and optionally behavior-driven CVEs.

    Parameters
    ----------
    show_cves : bool
        If False, skip behavior-driven CVE tables (AI handles intelligence).
    """
    profiles = behavior_results.get("host_profiles", [])
    if not profiles:
        return

    tw = 68

    print(f"\n  {'═' * tw}")
    print(f"  {BOLD}{MAGENTA}{'HOST BEHAVIOR ASSESSMENT':^{tw}}{RESET}")
    print(f"  {'═' * tw}")

    for hp in profiles:
        profile = hp.get("profile", {})
        findings = hp.get("findings", [])
        behavior_cves = hp.get("behavior_cves", [])
        anomalies = hp.get("anomalies", {})

        # ── Risk header ──────────────────────────────────────────────
        score = hp["risk_score"]
        level = hp["risk_level"]
        bar = _risk_bar(score)

        print(f"\n  {BOLD}┌─ Host: {hp['ip']}{RESET}")
        print(f"  {'─' * tw}")
        print(f"  {BOLD}  RISK SCORE:{RESET}  {score}/100  {bar}  {_c(level)}")
        print()

        # ── Profile metrics ──────────────────────────────────────────
        print(f"  {DIM}  ┌─ Profile Metrics ─────────────────────────────────────┐{RESET}")
        print(f"  {DIM}  │{RESET}  Open ports      : {BOLD}{profile.get('open_port_count', 0)}{RESET}")
        print(f"  {DIM}  │{RESET}  High-risk ports  : {BOLD}{len(profile.get('high_risk_ports', []))}{RESET}")
        print(f"  {DIM}  │{RESET}  Avg latency      : {BOLD}{profile.get('avg_connect_latency_ms', 0)} ms{RESET}")
        print(f"  {DIM}  │{RESET}  Service diversity : {BOLD}{profile.get('service_diversity', 0)}{RESET}")
        print(f"  {DIM}  │{RESET}  Banner disclosures: {BOLD}{profile.get('banner_disclosure_count', 0)}{RESET}")
        ct_count = len(profile.get("cleartext_services", []))
        print(f"  {DIM}  │{RESET}  Cleartext svcs   : {BOLD}{ct_count}{RESET}")
        print(f"  {DIM}  └───────────────────────────────────────────────────────┘{RESET}")

        # ── Anomaly detection summary ────────────────────────────────
        if anomalies:
            fw = anomalies.get("firewall", {})
            ids = anomalies.get("ids_ips", {})
            honeypot = anomalies.get("honeypot", {})
            print(f"\n  {BOLD}  Anomaly Detection:{RESET}")
            fw_icon = f"{GREEN}✔ Detected{RESET} ({fw.get('firewall_type', '?')}, {fw.get('confidence', 0)}%)" if fw.get("detected") else f"{DIM}✘ Not detected{RESET}"
            ids_icon = f"{GREEN}✔ Detected{RESET} ({ids.get('confidence', 0)}%)" if ids.get("detected") else f"{DIM}✘ Not detected{RESET}"
            hp_icon = f"{RED}⚠ Possible{RESET} ({honeypot.get('confidence', 0)}%)" if honeypot.get("detected") else f"{DIM}✘ Not detected{RESET}"
            print(f"    Firewall : {fw_icon}")
            print(f"    IDS/IPS  : {ids_icon}")
            print(f"    Honeypot : {hp_icon}")

        # ── Findings table ───────────────────────────────────────────
        if findings:
            print(f"\n  {BOLD}{YELLOW}  ▶ Behavioral Findings ({len(findings)}){RESET}\n")

            print(f"  {BOLD}  ┌{'─' * 8}┬{'─' * 10}┬{'─' * 46}┐{RESET}")
            print(f"  {BOLD}  │{'ID':^8}│{'Severity':^10}│ {'Title':<44} │{RESET}")
            print(f"  {BOLD}  ├{'─' * 8}┼{'─' * 10}┼{'─' * 46}┤{RESET}")

            for f in findings:
                sev_s = _c(f["severity"])
                title_s = _trunc(f["title"], 44)
                print(f"    │{f['id']:^8}│ {_pad(sev_s, 8)} │ {title_s:<44} │")

            print(f"  {BOLD}  └{'─' * 8}┴{'─' * 10}┴{'─' * 46}┘{RESET}")

            # Compact finding details
            for f in findings:
                sev = _c(f["severity"])
                print(f"    {sev} {BOLD}{f['id']}{RESET}: {f['title']}")
                print(f"      {CYAN}→{RESET} {f['recommendation']}")

        # ── Behavior-driven CVEs (only when AI is OFF) ───────────────
        if show_cves and behavior_cves:
            print(f"\n  {BOLD}{RED}  ▶ Behavior-Driven Vulnerabilities ({len(behavior_cves)}){RESET}")
            print(f"  {DIM}    CVEs discovered from behavioral pattern analysis{RESET}")
            print_vuln_table(behavior_cves)
            print_detailed_vulns(behavior_cves)

    print(f"\n  {'═' * tw}")


def print_packet_analysis(packet_analysis):
    """Print packet capture analysis: protocol dist, patterns, pattern-driven CVEs."""
    if not packet_analysis:
        return

    tw = 68

    print(f"\n  {'═' * tw}")
    print(f"  {BOLD}{CYAN}{'PACKET CAPTURE ANALYSIS':^{tw}}{RESET}")
    print(f"  {'═' * tw}")

    # ── Traffic overview ─────────────────────────────────────────────
    total = packet_analysis.get("total_packets", 0)
    duration = packet_analysis.get("duration_secs", 0)
    print(f"\n  {BOLD}  Traffic Overview{RESET}")
    print(f"    Total packets : {BOLD}{total:,}{RESET}")
    print(f"    Duration      : {BOLD}{duration:.1f}s{RESET}")
    if duration > 0:
        print(f"    Avg rate      : {BOLD}{total / duration:,.0f} pps{RESET}")

    # ── Protocol distribution (ASCII bar chart) ──────────────────────
    proto_dist = packet_analysis.get("protocol_distribution", {})
    if proto_dist:
        print(f"\n  {BOLD}  Protocol Distribution{RESET}")
        max_pct = max(proto_dist.values()) if proto_dist else 1
        bar_max = 30
        for proto, pct in sorted(proto_dist.items(), key=lambda x: -x[1]):
            bar_len = int(pct / max_pct * bar_max) if max_pct else 0
            color = {"TCP": CYAN, "UDP": GREEN, "ICMP": YELLOW}.get(proto, DIM)
            print(f"    {proto:<6} {color}{'█' * bar_len}{RESET} {pct}%")

    # ── Top talkers ──────────────────────────────────────────────────
    talkers = packet_analysis.get("top_talkers", [])
    if talkers:
        print(f"\n  {BOLD}  Top Talkers{RESET}")
        for t in talkers:
            print(f"    {t['ip']:<20} {BOLD}{t['packets']:>6}{RESET} packets")

    # ── Detected patterns ────────────────────────────────────────────
    patterns = packet_analysis.get("patterns", [])
    if patterns:
        print(f"\n  {BOLD}{RED}  ▶ Detected Packet Patterns ({len(patterns)}){RESET}\n")

        print(f"  {BOLD}  ┌{'─' * 12}┬{'─' * 10}┬{'─' * 6}┬{'─' * 36}┐{RESET}")
        print(f"  {BOLD}  │{'Pattern':^12}│{'Severity':^10}│{'Conf':^6}│ {'Name':<34} │{RESET}")
        print(f"  {BOLD}  ├{'─' * 12}┼{'─' * 10}┼{'─' * 6}┼{'─' * 36}┤{RESET}")

        for p in patterns:
            sev = _c(p["severity"])
            pid = _trunc(p["pattern_id"], 12)
            name = _trunc(p["name"], 34)
            conf = f"{p['confidence']}%"
            print(f"    │{pid:^12}│ {_pad(sev, 8)} │{conf:^6}│ {name:<34} │")

        print(f"  {BOLD}  └{'─' * 12}┴{'─' * 10}┴{'─' * 6}┴{'─' * 36}┘{RESET}")

        # Detail for each pattern
        print(f"\n  {DIM}  ── Pattern Details ──{RESET}")
        for p in patterns:
            sev = _c(p["severity"])
            print(f"\n    {sev} {BOLD}{p['pattern_id']}: {p['name']}{RESET}")
            print(f"      {DIM}Confidence:{RESET} {p['confidence']}%")
            print(f"      {DIM}Detail:{RESET}     {p['detail']}")
    else:
        print(f"\n  {GREEN}  ✔ No suspicious packet patterns detected.{RESET}")

    # ── Pattern-driven CVEs ──────────────────────────────────────────
    pattern_cves = packet_analysis.get("pattern_cves", [])
    if pattern_cves:
        print(f"\n  {BOLD}{RED}  ▶ Pattern-Driven Vulnerabilities ({len(pattern_cves)}){RESET}")
        print(f"  {DIM}    CVEs discovered from packet pattern analysis{RESET}")
        print_vuln_table(pattern_cves)
        print_detailed_vulns(pattern_cves)

    print(f"\n  {'═' * tw}")


# ══════════════════════════════════════════════════════
# AI SECURITY INTELLIGENCE OUTPUT
# ══════════════════════════════════════════════════════

def print_ai_analysis(ai_analysis):
    """Print AI-powered security intelligence sections."""
    if not ai_analysis:
        return

    tw = 68

    print(f"\n  {'═' * tw}")
    print(f"  {BOLD}{MAGENTA}{'🤖 AI SECURITY INTELLIGENCE':^{tw}}{RESET}")
    print(f"  {'═' * tw}")
    print(f"  {DIM}  Powered by Google Gemini — contextual analysis of scan data{RESET}")

    # ── 1. Vulnerability Intelligence ────────────────────────────────
    vuln_intel = ai_analysis.get("vulnerability_intel")
    if vuln_intel:
        # Risk summary
        summary = vuln_intel.get("overall_risk_summary", "")
        if summary:
            print(f"\n  {BOLD}{RED}  ▶ Risk Summary{RESET}")
            for line in _wrap_lines(summary, 62):
                print(f"    {line}")

        # Precise mitigations
        mitigations = vuln_intel.get("precise_mitigations", [])
        if mitigations:
            print(f"\n  {BOLD}{CYAN}  ▶ AI-Powered Mitigations ({len(mitigations)}){RESET}\n")

            print(f"  {BOLD}  ┌{'─' * 4}┬{'─' * 60}┐{RESET}")
            print(f"  {BOLD}  │{'#':^4}│ {'Mitigation':<58} │{RESET}")
            print(f"  {BOLD}  ├{'─' * 4}┼{'─' * 60}┤{RESET}")

            for m in mitigations:
                pri = m.get("priority", "?")
                target = m.get("target", "")
                action = m.get("action", "")
                display = f"{target}: {action}" if target else action
                display_trunc = _trunc(display, 58)
                print(f"    │{pri:^4}│ {display_trunc:<58} │")

            print(f"  {BOLD}  └{'─' * 4}┴{'─' * 60}┘{RESET}")

            # Detail cards
            print(f"\n  {DIM}  ── Mitigation Details ──{RESET}")
            for m in mitigations:
                pri = m.get("priority", "?")
                print(f"\n    {CYAN}#{pri}{RESET} {BOLD}{m.get('target', 'General')}{RESET}")
                print(f"      {DIM}Action:{RESET}  {m.get('action', 'N/A')}")
                if m.get("reason"):
                    print(f"      {DIM}Reason:{RESET}  {m['reason']}")

        # Exploit chains
        chains = vuln_intel.get("exploit_chains", [])
        if chains:
            print(f"\n  {BOLD}{RED}  ▶ Exploit Chain Analysis ({len(chains)}){RESET}")

            for i, chain in enumerate(chains, 1):
                sev = _c(chain.get("severity", "MEDIUM"))
                likelihood = chain.get("likelihood", "?")
                print(f"\n    {BOLD}Chain {i}: {chain.get('chain_name', 'Unknown')}{RESET}")
                print(f"      Severity: {sev}   Likelihood: {BOLD}{likelihood}{RESET}")

                steps = chain.get("steps", [])
                for j, step in enumerate(steps):
                    connector = "└─" if j == len(steps) - 1 else "├─"
                    print(f"      {DIM}{connector}{RESET} {step}")

                if chain.get("explanation"):
                    print(f"      {DIM}Analysis:{RESET} {chain['explanation']}")

        # Priority actions
        actions = vuln_intel.get("priority_actions", [])
        if actions:
            print(f"\n  {BOLD}{YELLOW}  ▶ Priority Actions{RESET}")
            for i, action in enumerate(actions, 1):
                print(f"    {YELLOW}{i}.{RESET} {action}")

    # ── 2. Network Behavior Intelligence ─────────────────────────────
    behavior_intel = ai_analysis.get("behavior_intel")
    if behavior_intel:
        print(f"\n  {'─' * tw}")
        print(f"  {BOLD}{CYAN}  ▶ Network Anomaly Detection (AI){RESET}")

        # Anomaly assessment
        assessment = behavior_intel.get("anomaly_assessment", "")
        if assessment:
            print(f"\n    {DIM}Assessment:{RESET}")
            for line in _wrap_lines(assessment, 60):
                print(f"    {line}")

        # Firewall
        fw = behavior_intel.get("firewall_detection", {})
        fw_icon = f"{GREEN}✔ Detected{RESET}" if fw.get("detected") else f"{DIM}✘ Not detected{RESET}"
        fw_detail = ""
        if fw.get("detected"):
            fw_detail = f" ({fw.get('firewall_type', '?')}, conf {fw.get('confidence', 0)}%)"
        print(f"\n    {BOLD}Firewall:{RESET}  {fw_icon}{fw_detail}")
        for ev in fw.get("evidence", []):
            print(f"      {DIM}•{RESET} {ev}")

        # IDS/IPS
        ids = behavior_intel.get("ids_ips_detection", {})
        ids_icon = f"{GREEN}✔ Detected{RESET}" if ids.get("detected") else f"{DIM}✘ Not detected{RESET}"
        ids_detail = f" (conf {ids.get('confidence', 0)}%)" if ids.get("detected") else ""
        print(f"    {BOLD}IDS/IPS:{RESET}   {ids_icon}{ids_detail}")
        for ev in ids.get("evidence", []):
            print(f"      {DIM}•{RESET} {ev}")
        if ids.get("evasion_notes"):
            print(f"      {YELLOW}Evasion:{RESET} {ids['evasion_notes']}")

        # Honeypot
        hp = behavior_intel.get("honeypot_indicators", {})
        hp_icon = f"{RED}⚠ Likely honeypot{RESET}" if hp.get("detected") else f"{DIM}✘ Not detected{RESET}"
        hp_detail = f" (conf {hp.get('confidence', 0)}%)" if hp.get("detected") else ""
        print(f"    {BOLD}Honeypot:{RESET}  {hp_icon}{hp_detail}")
        for ind in hp.get("indicators", []):
            print(f"      {DIM}•{RESET} {ind}")

    # ── 3. Zero-Day Risk Assessment ──────────────────────────────────
    zeroday = ai_analysis.get("zero_day_assessment", [])
    if zeroday:
        print(f"\n  {'─' * tw}")
        print(f"  {BOLD}{RED}  ▶ Zero-Day Risk Assessment (AI){RESET}")

        for zd in zeroday:
            ip = zd.get("ip", "Unknown")
            risk = zd.get("risk_level", "UNKNOWN")
            conf = zd.get("confidence", 0)
            print(f"\n    {BOLD}Host: {ip}{RESET}  —  Risk: {_c(risk)}  Confidence: {conf}%")

            summary = zd.get("assessment_summary", "")
            if summary:
                for line in _wrap_lines(summary, 60):
                    print(f"      {line}")

            # Suspicious indicators
            indicators = zd.get("suspicious_indicators", [])
            if indicators:
                print(f"\n      {BOLD}Suspicious Indicators:{RESET}")
                for ind in indicators:
                    sev = _c(ind.get("severity", "LOW"))
                    print(f"        {sev} {ind.get('indicator', '')}")
                    if ind.get("explanation"):
                        print(f"          {DIM}{ind['explanation']}{RESET}")

            # Potential attack vectors
            vectors = zd.get("potential_attack_vectors", [])
            if vectors:
                print(f"\n      {BOLD}Potential Attack Vectors:{RESET}")
                for vec in vectors:
                    print(f"        {RED}→{RESET} {BOLD}{vec.get('vector', '')}{RESET}")
                    print(f"          Target: {vec.get('target_service', '?')}")
                    if vec.get("description"):
                        print(f"          {DIM}{vec['description']}{RESET}")

            # Monitoring recommendations
            monitoring = zd.get("recommended_monitoring", [])
            if monitoring:
                print(f"\n      {BOLD}Recommended Monitoring:{RESET}")
                for mon in monitoring:
                    print(f"        {CYAN}▸{RESET} {mon}")

    print(f"\n  {'═' * tw}")


def _wrap_lines(text, width=60):
    """Wrap text into multiple lines."""
    import textwrap as tw
    return tw.wrap(text, width=width)


# ── Main Output ──────────────────────────────────────
def print_results(data, mode):
    if mode == "json":
        print(json.dumps(data, indent=2, default=str))
        return

    tw = 68  # total width
    ai_active = bool(data.get("ai_analysis"))

    print(f"\n  {'═' * tw}")
    print(f"  {BOLD}{'SCAN RESULTS':^{tw}}{RESET}")
    print(f"  {'═' * tw}")
    print(f"  Target : {data.get('target', 'N/A')}")
    print(f"  Time   : {data.get('scan_time', 'N/A')}")

    for host in data["hosts"]:
        print(f"\n  {BOLD}\u250c\u2500 Host: {host['ip']}{RESET}")
        print(f"  {'\u2500' * tw}")

        if not host["open_ports"]:
            print(f"  {DIM}  No open ports found{RESET}")
            continue

        for port in host["open_ports"]:
            print(f"\n  {GREEN}{BOLD}  [+] Port {port['port']}{RESET} \u2014 {BOLD}OPEN{RESET}")
            print_port_info(port)

            vulns = port.get("vulnerabilities")
            if not vulns:
                print(f"  {DIM}  No known CVEs found{RESET}")
                continue

            print(f"  {BOLD}  Found {len(vulns)} CVE(s):{RESET}")
            print_vuln_table(vulns)
            print_detailed_vulns(vulns)

    print(f"\n  {'\u2550' * tw}")
    print(f"  {DIM}Scan complete.{RESET}")
    print(f"  {'\u2550' * tw}\n")

    # \u2500\u2500 Behavior analysis (always show profile + findings) \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
    behavior = data.get("behavior_results")
    if behavior:
        print_behavior_assessment(behavior, show_cves=(not ai_active))

    # \u2500\u2500 Monitoring report (if present) \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
    monitoring = data.get("monitoring")
    if monitoring:
        print_monitor_report(monitoring)

    # \u2500\u2500 AI analysis section (primary intelligence when active) \u2500\u2500\u2500\u2500\u2500\u2500
    if ai_active:
        print_ai_analysis(data.get("ai_analysis"))


def print_monitor_report(monitoring_data):
    """Print active monitoring results."""
    if not monitoring_data:
        return

    tw = 68

    print(f"\n  {'\u2550' * tw}")
    print(f"  {BOLD}{CYAN}{'\U0001f50d ACTIVE MONITORING REPORT':^{tw}}{RESET}")
    print(f"  {'\u2550' * tw}")
    print(f"  Duration: {monitoring_data.get('duration_secs', 0)}s  |  "
          f"Rounds: {monitoring_data.get('total_rounds', 0)}  |  "
          f"Anomalies: {len(monitoring_data.get('anomalies', []))}")

    # Per-port stats
    port_data = monitoring_data.get("port_data", {})
    if port_data:
        print(f"\n  {BOLD}  Port Stability:{RESET}\n")
        print(f"  {BOLD}  \u250c{'\u2500' * 7}\u252c{'\u2500' * 10}\u252c{'\u2500' * 10}\u252c{'\u2500' * 10}\u252c{'\u2500' * 12}\u252c{'\u2500' * 14}\u2510{RESET}")
        print(f"  {BOLD}  \u2502{'Port':^7}\u2502{'Probes':^10}\u2502{'Success':^10}\u2502{'Drop%':^10}\u2502{'Avg ms':^12}\u2502{'Stdev ms':^14}\u2502{RESET}")
        print(f"  {BOLD}  \u251c{'\u2500' * 7}\u253c{'\u2500' * 10}\u253c{'\u2500' * 10}\u253c{'\u2500' * 10}\u253c{'\u2500' * 12}\u253c{'\u2500' * 14}\u2524{RESET}")

        for port, pd in port_data.items():
            drop_color = RED if pd['drop_rate'] > 20 else (YELLOW if pd['drop_rate'] > 0 else GREEN)
            avg = f"{pd['avg_ms']:.1f}" if pd['avg_ms'] else "N/A"
            stdev = f"{pd['stdev_ms']:.1f}" if pd['stdev_ms'] else "N/A"
            print(f"    \u2502{port:^7}\u2502{pd['total_probes']:^10}\u2502"
                  f"{pd['successful']:^10}\u2502"
                  f" {drop_color}{pd['drop_rate']:.0f}%{RESET}{'':>{7}}\u2502"
                  f"{avg:^12}\u2502{stdev:^14}\u2502")

        print(f"  {BOLD}  \u2514{'\u2500' * 7}\u2534{'\u2500' * 10}\u2534{'\u2500' * 10}\u2534{'\u2500' * 10}\u2534{'\u2500' * 12}\u2534{'\u2500' * 14}\u2518{RESET}")

    # Anomalies
    anomalies = monitoring_data.get("anomalies", [])
    if anomalies:
        print(f"\n  {BOLD}{RED}  \u25b6 Detected Anomalies ({len(anomalies)}){RESET}")
        for a in anomalies:
            sev = _c(a.get('severity', 'LOW'))
            print(f"    {sev} {a.get('detail', '')}")
    else:
        print(f"\n  {GREEN}  \u2714 No anomalies detected during monitoring{RESET}")

    # Summary
    summary = monitoring_data.get("summary", [])
    if summary:
        print(f"\n  {DIM}  Summary:{RESET}")
        for line in summary:
            print(f"    {line}")

    print(f"\n  {'\u2550' * tw}")


