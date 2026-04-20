"""
Packet Pattern Analyzer
───────────────────────
Optional pcap-based traffic analysis using Scapy.  If Scapy is not
installed the module exposes ``SCAPY_AVAILABLE = False`` and
``analyze_pcap()`` returns None, allowing the rest of the scanner to
continue gracefully.
"""

import os
from collections import Counter, defaultdict

# ── Lazy / optional Scapy import ─────────────────────────────────────
try:
    from scapy.all import rdpcap, IP, TCP, UDP, ICMP, DNS  # type: ignore
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False


# ── Thresholds for pattern detection ────────────────────────────────
_SYN_SCAN_RATIO_THRESH   = 3.0    # SYN-only / SYN-ACK ratio
_SYN_FLOOD_PPS_THRESH    = 100    # SYN packets-per-second burst
_DNS_AMP_RATIO_THRESH    = 3.0    # DNS response bytes / query bytes
_PORT_SWEEP_THRESH       = 15     # Distinct dest ports from one source
_ICMP_FLOOD_PPS_THRESH   = 50     # ICMP packets-per-second
_SMB_RDP_PERCENT_THRESH  = 40     # % of TCP traffic on 445/3389


# =====================================================================
#  Public API
# =====================================================================

def analyze_pcap(pcap_path):
    """Parse a pcap file and return traffic statistics + detected patterns.

    Parameters
    ----------
    pcap_path : str
        Absolute or relative path to a ``.pcap`` / ``.pcapng`` file.

    Returns
    -------
    dict | None
        ``None`` if Scapy is unavailable or the file cannot be read.
        Otherwise a dict with keys: total_packets, duration_secs,
        protocol_distribution, top_talkers, patterns.
    """
    if not SCAPY_AVAILABLE:
        return None

    if not pcap_path or not os.path.isfile(pcap_path):
        return None

    try:
        packets = rdpcap(pcap_path)
    except Exception:
        return None

    if not packets:
        return {"total_packets": 0, "duration_secs": 0,
                "protocol_distribution": {}, "top_talkers": [], "patterns": []}

    # ── Basic statistics ─────────────────────────────────────────────
    total = len(packets)
    timestamps = [float(p.time) for p in packets if hasattr(p, "time")]
    duration = max(timestamps) - min(timestamps) if len(timestamps) >= 2 else 0.0

    proto_counts = Counter()
    src_counter = Counter()
    tcp_packets = []
    udp_packets = []
    icmp_count = 0
    dns_queries = []
    dns_responses = []
    dest_ports_by_src = defaultdict(set)
    smb_rdp_count = 0
    total_tcp = 0

    for pkt in packets:
        if not pkt.haslayer(IP):
            proto_counts["Other"] += 1
            continue

        src_ip = pkt[IP].src
        src_counter[src_ip] += 1

        if pkt.haslayer(TCP):
            proto_counts["TCP"] += 1
            total_tcp += 1
            tcp_packets.append(pkt)
            dport = pkt[TCP].dport
            dest_ports_by_src[src_ip].add(dport)
            if dport in (445, 3389) or pkt[TCP].sport in (445, 3389):
                smb_rdp_count += 1
        elif pkt.haslayer(UDP):
            proto_counts["UDP"] += 1
            udp_packets.append(pkt)
        elif pkt.haslayer(ICMP):
            proto_counts["ICMP"] += 1
            icmp_count += 1
        else:
            proto_counts["Other"] += 1

        # DNS tracking
        if pkt.haslayer(DNS):
            dns_pkt = pkt[DNS]
            if dns_pkt.qr == 0:  # query
                dns_queries.append(pkt)
            else:  # response
                dns_responses.append(pkt)

    # Protocol distribution as percentages
    proto_dist = {}
    for proto, count in proto_counts.items():
        proto_dist[proto] = round(count / total * 100, 1) if total else 0

    # Top talkers (top 5 source IPs)
    top_talkers = [{"ip": ip, "packets": cnt}
                   for ip, cnt in src_counter.most_common(5)]

    # ── Pattern detection ────────────────────────────────────────────
    patterns = []

    patterns.extend(_detect_syn_scan(tcp_packets, duration))
    patterns.extend(_detect_syn_flood(tcp_packets, duration))
    patterns.extend(_detect_dns_amplification(dns_queries, dns_responses))
    patterns.extend(_detect_smb_rdp_concentration(smb_rdp_count, total_tcp))
    patterns.extend(_detect_port_sweep(dest_ports_by_src))
    patterns.extend(_detect_icmp_flood(icmp_count, duration))

    return {
        "total_packets": total,
        "duration_secs": round(duration, 2),
        "protocol_distribution": proto_dist,
        "top_talkers": top_talkers,
        "patterns": patterns,
    }


# =====================================================================
#  Pattern Detectors  (private)
# =====================================================================

def _detect_syn_scan(tcp_packets, duration):
    """Detect SYN-scan behavior: many SYN-only packets without ACK."""
    if not tcp_packets:
        return []

    syn_only = 0
    syn_ack = 0
    for pkt in tcp_packets:
        flags = pkt[TCP].flags
        if flags == "S":      # SYN only
            syn_only += 1
        elif flags == "SA":   # SYN-ACK
            syn_ack += 1

    if syn_ack == 0 and syn_only > 20:
        ratio = float("inf")
    elif syn_ack > 0:
        ratio = syn_only / syn_ack
    else:
        return []

    if ratio >= _SYN_SCAN_RATIO_THRESH and syn_only > 10:
        confidence = min(95, 50 + int(ratio * 5))
        return [{
            "pattern_id": "PKT-SYN-SCAN",
            "name": "SYN Scan Detected",
            "severity": "HIGH",
            "confidence": confidence,
            "detail": (f"{syn_only} SYN-only packets vs {syn_ack} SYN-ACK "
                       f"(ratio {ratio:.1f}x) — classic port-scan signature."),
            "nvd_keywords": ["port scan detection evasion",
                             "network reconnaissance vulnerability"],
        }]
    return []


def _detect_syn_flood(tcp_packets, duration):
    """Detect SYN-flood–style burst traffic."""
    if not tcp_packets or duration <= 0:
        return []

    syn_count = sum(1 for p in tcp_packets if p[TCP].flags == "S")
    pps = syn_count / duration

    if pps >= _SYN_FLOOD_PPS_THRESH:
        confidence = min(95, 60 + int((pps / _SYN_FLOOD_PPS_THRESH) * 10))
        return [{
            "pattern_id": "PKT-SYN-FLOOD",
            "name": "SYN Flood Indicator",
            "severity": "CRITICAL",
            "confidence": confidence,
            "detail": (f"SYN packet rate of {pps:.0f} pps detected over "
                       f"{duration:.1f}s — potential denial-of-service."),
            "nvd_keywords": ["syn flood denial of service",
                             "tcp syn attack vulnerability"],
        }]
    return []


def _detect_dns_amplification(queries, responses):
    """Detect DNS amplification / reflection patterns."""
    if not queries and not responses:
        return []

    query_bytes = sum(len(bytes(p)) for p in queries) or 1
    response_bytes = sum(len(bytes(p)) for p in responses)
    ratio = response_bytes / query_bytes

    if ratio >= _DNS_AMP_RATIO_THRESH and len(responses) > 10:
        confidence = min(90, 50 + int(ratio * 5))
        return [{
            "pattern_id": "PKT-DNS-AMP",
            "name": "DNS Amplification Pattern",
            "severity": "HIGH",
            "confidence": confidence,
            "detail": (f"DNS response/query byte ratio is {ratio:.1f}x "
                       f"({len(responses)} responses vs {len(queries)} queries)."),
            "nvd_keywords": ["dns amplification attack",
                             "dns reflection vulnerability"],
        }]
    return []


def _detect_smb_rdp_concentration(smb_rdp_count, total_tcp):
    """Detect heavy SMB/RDP traffic concentration."""
    if total_tcp == 0:
        return []

    pct = smb_rdp_count / total_tcp * 100
    if pct >= _SMB_RDP_PERCENT_THRESH and smb_rdp_count > 20:
        confidence = min(85, 50 + int(pct / 2))
        return [{
            "pattern_id": "PKT-SMB-RDP",
            "name": "SMB/RDP Traffic Concentration",
            "severity": "HIGH",
            "confidence": confidence,
            "detail": (f"{pct:.0f}% of TCP traffic targets SMB (445) or "
                       f"RDP (3389) — {smb_rdp_count} packets."),
            "nvd_keywords": ["smb remote code execution",
                             "rdp brute force vulnerability"],
        }]
    return []


def _detect_port_sweep(dest_ports_by_src):
    """Detect port-sweep behavior from a single source."""
    patterns = []
    for src_ip, ports in dest_ports_by_src.items():
        if len(ports) >= _PORT_SWEEP_THRESH:
            confidence = min(90, 50 + len(ports))
            patterns.append({
                "pattern_id": "PKT-PORT-SWEEP",
                "name": f"Port Sweep from {src_ip}",
                "severity": "MEDIUM",
                "confidence": confidence,
                "detail": (f"Source {src_ip} contacted {len(ports)} distinct "
                           f"destination ports — reconnaissance indicator."),
                "nvd_keywords": ["port sweep reconnaissance",
                                 "network scanning vulnerability"],
            })
    return patterns


def _detect_icmp_flood(icmp_count, duration):
    """Detect ICMP flood traffic."""
    if duration <= 0 or icmp_count == 0:
        return []

    pps = icmp_count / duration
    if pps >= _ICMP_FLOOD_PPS_THRESH:
        confidence = min(90, 55 + int(pps / 5))
        return [{
            "pattern_id": "PKT-ICMP-FLOOD",
            "name": "ICMP Flood Indicator",
            "severity": "MEDIUM",
            "confidence": confidence,
            "detail": (f"ICMP rate of {pps:.0f} pps over {duration:.1f}s "
                       f"— potential ping flood."),
            "nvd_keywords": ["icmp flood denial of service",
                             "ping flood vulnerability"],
        }]
    return []
