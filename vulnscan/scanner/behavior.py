"""
Behavior Analysis Engine
─────────────────────────
Builds a host behavior profile from connection telemetry collected during
port scanning.  Produces risk scores, findings, and NVD search keywords
that feed the behavior-driven vulnerability enrichment pipeline.
"""

# ── Known-dangerous ports and their service context ──────────────────
HIGH_RISK_PORTS = {
    21:   ("ftp",    "FTP — cleartext file transfer"),
    23:   ("telnet", "Telnet — cleartext remote shell"),
    25:   ("smtp",   "SMTP — mail relay, potential open relay"),
    110:  ("pop3",   "POP3 — cleartext mail retrieval"),
    135:  ("msrpc",  "MSRPC — Windows RPC, worm vector"),
    139:  ("netbios","NetBIOS — Windows file sharing"),
    445:  ("smb",    "SMB — Windows file sharing / EternalBlue"),
    1433: ("mssql",  "MSSQL — database service"),
    1521: ("oracle", "Oracle DB — database service"),
    3306: ("mysql",  "MySQL — database service"),
    3389: ("rdp",    "RDP — Remote Desktop Protocol"),
    5432: ("pgsql",  "PostgreSQL — database service"),
    5900: ("vnc",    "VNC — remote framebuffer"),
    6379: ("redis",  "Redis — in-memory data store"),
    8443: ("https-alt", "Alternate HTTPS"),
    27017:("mongodb","MongoDB — NoSQL database"),
}

# NVD keyword templates keyed by port-service tag
_PORT_NVD_KEYWORDS = {
    "ftp":     ["ftp anonymous access vulnerability", "ftp cleartext credentials"],
    "telnet":  ["telnet unauthorized access", "telnet remote code execution"],
    "smb":     ["smb remote code execution", "smb vulnerability"],
    "rdp":     ["rdp remote code execution", "rdp brute force vulnerability"],
    "vnc":     ["vnc authentication bypass", "vnc remote code execution"],
    "netbios": ["netbios information disclosure"],
    "msrpc":   ["windows rpc vulnerability"],
    "mysql":   ["mysql privilege escalation"],
    "mssql":   ["mssql remote code execution"],
    "redis":   ["redis unauthorized access"],
    "mongodb": ["mongodb unauthorized access"],
    "smtp":    ["smtp open relay vulnerability"],
    "pop3":    ["pop3 cleartext credentials"],
    "oracle":  ["oracle database vulnerability"],
    "pgsql":   ["postgresql privilege escalation"],
}

# ── Risk-score weight constants ──────────────────────────────────────
_W_OPEN_PORTS      = 15   # many open ports increase attack surface
_W_HIGH_RISK       = 30   # dangerous services exposed
_W_BANNER_LEAK     = 15   # version disclosure
_W_LATENCY_ANOMALY = 10   # unusual response times
_W_SERVICE_DIVERSE = 10   # diverse service = complex host
_W_CLOSED_RATIO    = 10   # mostly closed → targeted exposure
_W_CLEARTEXT       = 10   # cleartext protocols present

_CLEARTEXT_SERVICES = {"ftp", "telnet", "pop3", "smtp", "http"}


# =====================================================================
#  Public API
# =====================================================================

def build_host_profile(host_data):
    """Build a behavior profile dict from one host's scan results.

    Parameters
    ----------
    host_data : dict
        A single host entry from scan_target() — must include ``open_ports``
        (each with ``telemetry``) and ``closed_filtered_count``.

    Returns
    -------
    dict   with keys: ip, open_port_count, high_risk_ports, avg_connect_latency_ms,
           service_diversity, banner_disclosure_count, cleartext_services,
           risk_score, risk_level
    """
    open_ports = host_data.get("open_ports", [])
    closed_filtered = host_data.get("closed_filtered_count", 0)

    # ── Gather metrics ───────────────────────────────────────────────
    high_risk = []
    latencies = []
    services = set()
    banner_count = 0
    cleartext = []

    for p in open_ports:
        port_num = p["port"]
        if port_num in HIGH_RISK_PORTS:
            tag, description = HIGH_RISK_PORTS[port_num]
            high_risk.append({"port": port_num, "tag": tag, "description": description})

        svc = (p.get("service") or "").lower()
        if svc:
            services.add(svc)
        if svc in _CLEARTEXT_SERVICES:
            cleartext.append({"port": port_num, "service": svc})

        tel = p.get("telemetry", {})
        if tel.get("connect_ms") is not None:
            latencies.append(tel["connect_ms"])
        if tel.get("banner_recv"):
            banner_count += 1

    avg_latency = round(sum(latencies) / len(latencies), 2) if latencies else 0.0
    open_count = len(open_ports)
    total_scanned = open_count + closed_filtered

    # ── Compute composite risk score (0 – 100) ──────────────────────
    score = 0.0

    # Open port count contribution
    if open_count >= 10:
        score += _W_OPEN_PORTS
    elif open_count >= 6:
        score += _W_OPEN_PORTS * 0.7
    elif open_count >= 3:
        score += _W_OPEN_PORTS * 0.3

    # High-risk ports
    if high_risk:
        score += min(_W_HIGH_RISK, _W_HIGH_RISK * len(high_risk) / 3)

    # Banner / version disclosure
    if banner_count:
        score += min(_W_BANNER_LEAK, _W_BANNER_LEAK * banner_count / 4)

    # Latency anomaly (very fast = automated service; very slow = overloaded)
    if avg_latency > 0:
        if avg_latency < 5:
            score += _W_LATENCY_ANOMALY * 0.6
        elif avg_latency > 2000:
            score += _W_LATENCY_ANOMALY

    # Service diversity
    if len(services) >= 5:
        score += _W_SERVICE_DIVERSE
    elif len(services) >= 3:
        score += _W_SERVICE_DIVERSE * 0.5

    # Closed ratio (mostly closed but few open → intentional exposure)
    if total_scanned > 0 and open_count > 0:
        closed_ratio = closed_filtered / total_scanned
        if closed_ratio > 0.9:
            score += _W_CLOSED_RATIO * 0.3  # mostly locked down, lower risk
        elif closed_ratio < 0.5:
            score += _W_CLOSED_RATIO  # many ports open

    # Cleartext protocols
    if cleartext:
        score += min(_W_CLEARTEXT, _W_CLEARTEXT * len(cleartext) / 2)

    score = min(100, round(score))

    # ── Risk level ───────────────────────────────────────────────────
    if score >= 75:
        risk_level = "CRITICAL"
    elif score >= 50:
        risk_level = "HIGH"
    elif score >= 25:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    return {
        "ip": host_data.get("ip"),
        "open_port_count": open_count,
        "high_risk_ports": high_risk,
        "avg_connect_latency_ms": avg_latency,
        "service_diversity": len(services),
        "banner_disclosure_count": banner_count,
        "cleartext_services": cleartext,
        "risk_score": score,
        "risk_level": risk_level,
    }


def generate_findings(profile):
    """Produce a list of human-readable findings from a host profile.

    Each finding is a dict with keys:
        id, severity, title, reason, recommendation
    """
    findings = []
    _id = 0

    def _add(severity, title, reason, recommendation):
        nonlocal _id
        _id += 1
        findings.append({
            "id": f"BHV-{_id:03d}",
            "severity": severity,
            "title": title,
            "reason": reason,
            "recommendation": recommendation,
        })

    # ── Excessive open ports ─────────────────────────────────────────
    opc = profile["open_port_count"]
    if opc >= 10:
        _add("HIGH", "Excessive open ports",
             f"{opc} open ports detected — large attack surface.",
             "Close unnecessary ports; apply host firewall rules.")
    elif opc >= 6:
        _add("MEDIUM", "Multiple open ports",
             f"{opc} open ports detected.",
             "Review whether all exposed services are required.")

    # ── Dangerous services ───────────────────────────────────────────
    for hr in profile["high_risk_ports"]:
        _add("HIGH", f"Dangerous service: {hr['description']}",
             f"Port {hr['port']} ({hr['tag']}) is open and historically targeted.",
             f"Restrict access to port {hr['port']} or replace with a secure alternative.")

    # ── Banner / version disclosure ──────────────────────────────────
    bc = profile["banner_disclosure_count"]
    if bc >= 3:
        _add("MEDIUM", "Widespread version disclosure",
             f"{bc} services reveal version information in banners.",
             "Suppress version strings in service configurations.")
    elif bc >= 1:
        _add("LOW", "Service version disclosure",
             f"{bc} service(s) reveal version information.",
             "Consider suppressing version strings to reduce recon value.")

    # ── Cleartext protocols ──────────────────────────────────────────
    for ct in profile["cleartext_services"]:
        _add("MEDIUM", f"Cleartext protocol: {ct['service'].upper()} on port {ct['port']}",
             f"Traffic on port {ct['port']} is unencrypted.",
             f"Replace {ct['service'].upper()} with an encrypted alternative (e.g., SFTP, SSH, HTTPS).")

    # ── Latency anomalies ────────────────────────────────────────────
    lat = profile["avg_connect_latency_ms"]
    if lat > 2000:
        _add("LOW", "High average connection latency",
             f"Average connect time is {lat} ms — host may be overloaded or rate-limiting.",
             "Investigate host resource utilization.")
    elif 0 < lat < 3:
        _add("INFO", "Extremely fast response time",
             f"Average connect time is {lat} ms — may indicate a honeypot or load balancer.",
             "Verify host identity; consider additional fingerprinting.")

    return findings


def generate_nvd_keywords(profile, findings):
    """Map behavioral signals to NVD keyword-search strings.

    Returns at most 5 distinct keyword strings to avoid NVD rate-limit pressure.
    """
    keywords = []

    # Keywords from high-risk ports
    for hr in profile["high_risk_ports"]:
        tag = hr["tag"]
        if tag in _PORT_NVD_KEYWORDS:
            keywords.extend(_PORT_NVD_KEYWORDS[tag])

    # Keywords from cleartext services
    for ct in profile["cleartext_services"]:
        svc = ct["service"]
        keywords.append(f"{svc} cleartext credential vulnerability")

    # Keywords from excessive open ports
    if profile["open_port_count"] >= 8:
        keywords.append("network service enumeration vulnerability")

    # Keywords from banner disclosures
    if profile["banner_disclosure_count"] >= 2:
        keywords.append("service version information disclosure")

    # De-duplicate and cap
    seen = set()
    unique = []
    for kw in keywords:
        kw_lower = kw.lower()
        if kw_lower not in seen:
            seen.add(kw_lower)
            unique.append(kw)

    return unique[:5]


# =====================================================================
#  Active Anomaly Detection
# =====================================================================

def detect_firewall_signatures(host_data):
    """Detect firewall presence from connection timing patterns.

    Logic:
    - Consistent timeout on closed/filtered ports → stateful firewall
    - All closed ports same latency vs varied → filtering evidence
    - High closed/filtered ratio with specific open ports → intentional exposure
    """
    open_ports = host_data.get("open_ports", [])
    closed_count = host_data.get("closed_filtered_count", 0)
    total = len(open_ports) + closed_count

    evidence = []
    confidence = 0

    if total == 0:
        return {"detected": False, "confidence": 0, "firewall_type": "unknown", "evidence": []}

    # High filtered ratio → likely firewall
    if closed_count > 0 and total > 3:
        filtered_ratio = closed_count / total
        if filtered_ratio > 0.8:
            confidence += 30
            evidence.append(
                f"{filtered_ratio * 100:.0f}% of scanned ports are filtered/closed "
                f"— consistent with firewall policy")

    # Few specific ports open among many filtered → deliberate firewall rules
    if len(open_ports) <= 4 and closed_count >= 8:
        confidence += 25
        open_list = [str(p["port"]) for p in open_ports]
        evidence.append(
            f"Only ports {', '.join(open_list)} open out of {total} scanned "
            f"— suggests explicit allow rules")

    # Analyze open-port latency variance
    open_latencies = [p.get("telemetry", {}).get("connect_ms", 0) for p in open_ports
                      if p.get("telemetry", {}).get("connect_ms") is not None]
    if len(open_latencies) >= 2:
        lat_range = max(open_latencies) - min(open_latencies)
        if lat_range < 5:
            confidence += 15
            evidence.append(
                f"Open-port latency variance is very low ({lat_range:.1f} ms) "
                f"— consistent with centralized firewall/proxy")

    # Determine firewall type
    if confidence >= 50:
        if len(open_ports) <= 3:
            fw_type = "stateful"
        elif any(p["port"] in (80, 443, 8080, 8443) for p in open_ports):
            fw_type = "WAF"
        else:
            fw_type = "stateful"
    else:
        fw_type = "unknown"

    return {
        "detected": confidence >= 40,
        "confidence": min(95, confidence),
        "firewall_type": fw_type,
        "evidence": evidence,
    }


def detect_ids_indicators(host_data):
    """Detect IDS/IPS presence from connection behavior patterns.

    Logic:
    - Increasing latency across sequential port scans → rate limiting
    - Connection resets after banner grab → IDS killing connections
    - Inconsistent banner responses → response manipulation
    """
    open_ports = host_data.get("open_ports", [])
    evidence = []
    confidence = 0

    if len(open_ports) < 2:
        return {"detected": False, "confidence": 0, "evidence": [],
                "evasion_notes": ""}

    # Check for increasing latency pattern (rate limiting)
    latencies = []
    for p in open_ports:
        tel = p.get("telemetry", {})
        if tel.get("connect_ms") is not None:
            latencies.append(tel["connect_ms"])

    if len(latencies) >= 3:
        # Check if latency is monotonically increasing (rate limiting sign)
        increasing = sum(1 for i in range(1, len(latencies))
                         if latencies[i] > latencies[i - 1] * 1.2)
        if increasing >= len(latencies) * 0.6:
            confidence += 35
            evidence.append(
                f"Connection latency increases across sequential ports "
                f"({latencies[0]:.0f} ms → {latencies[-1]:.0f} ms) — "
                f"consistent with IDS rate limiting")

    # Check for banner inconsistencies (received banner but very short/truncated)
    truncated_banners = 0
    for p in open_ports:
        tel = p.get("telemetry", {})
        if tel.get("banner_recv") and tel.get("banner_len", 0) < 10:
            truncated_banners += 1

    if truncated_banners >= 2:
        confidence += 25
        evidence.append(
            f"{truncated_banners} ports returned truncated banners "
            f"— possible IDS connection termination")

    # Check for response time spikes (some ports much slower than others)
    if len(latencies) >= 3:
        avg_lat = sum(latencies) / len(latencies)
        spikes = [l for l in latencies if l > avg_lat * 3]
        if spikes:
            confidence += 20
            evidence.append(
                f"{len(spikes)} port(s) showed response time spikes "
                f"(>3x average) — possible deep packet inspection")

    evasion = ""
    if confidence >= 30:
        evasion = ("Consider fragmenting probes, randomizing port scan order, "
                   "or reducing scan speed to avoid triggering thresholds.")

    return {
        "detected": confidence >= 35,
        "confidence": min(90, confidence),
        "evidence": evidence,
        "evasion_notes": evasion,
    }


def detect_honeypot_indicators(host_data):
    """Detect honeypot characteristics from scan behavior.

    Logic:
    - Unusually many open ports (> 15)
    - Unusual service combinations (e.g., multiple competing DBs)
    - Extremely fast, uniform response times
    - All ports respond with banners
    """
    open_ports = host_data.get("open_ports", [])
    closed_count = host_data.get("closed_filtered_count", 0)
    indicators = []
    confidence = 0

    open_count = len(open_ports)

    # Too many open ports
    if open_count >= 15:
        confidence += 30
        indicators.append(
            f"{open_count} ports open — unusually high, common in honeypots")
    elif open_count >= 10:
        confidence += 15
        indicators.append(
            f"{open_count} ports open — higher than typical production hosts")

    # Almost no closed ports
    total = open_count + closed_count
    if total > 5 and closed_count <= 1:
        confidence += 20
        indicators.append(
            "Almost no closed/filtered ports — unusual for real hosts")

    # Unusual service combinations
    services = set()
    db_services = set()
    for p in open_ports:
        svc = (p.get("service") or "").lower()
        if svc:
            services.add(svc)
        if svc in ("mysql", "mssql", "oracle", "postgresql", "mongodb", "redis"):
            db_services.add(svc)

    if len(db_services) >= 3:
        confidence += 25
        indicators.append(
            f"Multiple competing database services ({', '.join(db_services)}) "
            f"— unusual for production hosts")

    # Extremely uniform response times
    latencies = [p.get("telemetry", {}).get("connect_ms", 0) for p in open_ports
                 if p.get("telemetry", {}).get("connect_ms") is not None]
    if len(latencies) >= 5:
        lat_range = max(latencies) - min(latencies)
        avg_lat = sum(latencies) / len(latencies)
        if lat_range < 2 and avg_lat < 5:
            confidence += 20
            indicators.append(
                f"All ports respond in {avg_lat:.1f}±{lat_range:.1f} ms "
                f"— suspiciously uniform and fast")

    # All ports have banners
    if open_count >= 5:
        banner_count = sum(1 for p in open_ports
                           if p.get("telemetry", {}).get("banner_recv"))
        if banner_count == open_count:
            confidence += 15
            indicators.append(
                "Every open port returns a banner — uncommon for real hosts")

    return {
        "detected": confidence >= 40,
        "confidence": min(95, confidence),
        "indicators": indicators,
    }


def detect_anomalies(host_data):
    """Run all anomaly detectors and return combined results.

    Returns
    -------
    dict  with keys: firewall, ids_ips, honeypot
    """
    return {
        "firewall": detect_firewall_signatures(host_data),
        "ids_ips": detect_ids_indicators(host_data),
        "honeypot": detect_honeypot_indicators(host_data),
    }

