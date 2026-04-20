"""
Active Network Monitor
──────────────────────
Performs extended TCP probing of a target over a configurable duration
to gather timing patterns, detect behavioral anomalies, and build a
comprehensive monitoring report.

Does NOT require root — uses standard TCP connect probes.
"""

import socket
import time
import statistics


def _probe_port(ip, port, timeout=3):
    """Single TCP connect probe.  Returns connect time in ms or None."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    start = time.perf_counter()
    try:
        sock.connect((ip, port))
        elapsed = (time.perf_counter() - start) * 1000
        sock.close()
        return round(elapsed, 2)
    except (socket.timeout, ConnectionRefusedError, OSError):
        return None


def monitor_target(ip, ports, duration=30, interval=5):
    """Probe target ports repeatedly over *duration* seconds.

    Parameters
    ----------
    ip : str
        Target IP address.
    ports : list[int]
        List of open ports to monitor.
    duration : int
        Total monitoring time in seconds.
    interval : int
        Seconds between probe rounds.

    Returns
    -------
    dict  with keys: ip, duration, rounds, port_data, anomalies, summary
    """
    rounds = []
    start_time = time.time()
    round_num = 0

    while (time.time() - start_time) < duration:
        round_num += 1
        round_data = {"round": round_num, "timestamp": time.time(), "probes": {}}

        for port in ports:
            latency = _probe_port(ip, port)
            round_data["probes"][port] = {
                "latency_ms": latency,
                "reachable": latency is not None,
            }

        rounds.append(round_data)

        # Wait for next round (but don't exceed duration)
        remaining = duration - (time.time() - start_time)
        if remaining > interval:
            time.sleep(interval)
        elif remaining > 0:
            time.sleep(remaining)
            break
        else:
            break

    # ── Aggregate per-port statistics ────────────────────────────────
    port_data = {}
    for port in ports:
        latencies = []
        drop_count = 0
        for r in rounds:
            probe = r["probes"].get(port, {})
            if probe.get("reachable"):
                latencies.append(probe["latency_ms"])
            else:
                drop_count += 1

        port_data[port] = {
            "total_probes": len(rounds),
            "successful": len(latencies),
            "dropped": drop_count,
            "drop_rate": round(drop_count / len(rounds) * 100, 1) if rounds else 0,
            "latencies": latencies,
            "avg_ms": round(statistics.mean(latencies), 2) if latencies else None,
            "min_ms": round(min(latencies), 2) if latencies else None,
            "max_ms": round(max(latencies), 2) if latencies else None,
            "stdev_ms": round(statistics.stdev(latencies), 2) if len(latencies) >= 2 else 0,
        }

    # ── Detect anomalies from monitoring data ────────────────────────
    anomalies = _detect_monitoring_anomalies(port_data, rounds)

    # ── Build human-readable summary ─────────────────────────────────
    summary_lines = []
    for port, pd in port_data.items():
        if pd["drop_rate"] > 0:
            summary_lines.append(
                f"Port {port}: {pd['drop_rate']}% packet loss, "
                f"avg {pd['avg_ms'] or 'N/A'} ms")
        elif pd["avg_ms"]:
            summary_lines.append(
                f"Port {port}: stable, avg {pd['avg_ms']} ms "
                f"(±{pd['stdev_ms']} ms)")

    return {
        "ip": ip,
        "duration_secs": round(time.time() - start_time, 1),
        "total_rounds": round_num,
        "port_data": port_data,
        "anomalies": anomalies,
        "summary": summary_lines,
    }


def _detect_monitoring_anomalies(port_data, rounds):
    """Analyze monitoring data for behavioral anomalies."""
    anomalies = []

    for port, pd in port_data.items():
        # ── Intermittent drops → possible rate limiting ──────────────
        if 0 < pd["drop_rate"] < 100:
            anomalies.append({
                "type": "intermittent_drops",
                "port": port,
                "severity": "HIGH" if pd["drop_rate"] > 30 else "MEDIUM",
                "detail": (f"Port {port} dropped {pd['dropped']}/{pd['total_probes']} "
                           f"connections ({pd['drop_rate']}%) — possible rate limiting "
                           f"or unstable service"),
            })

        # ── Complete port death → service went down ──────────────────
        if pd["drop_rate"] == 100 and pd["total_probes"] > 1:
            anomalies.append({
                "type": "port_death",
                "port": port,
                "severity": "CRITICAL",
                "detail": (f"Port {port} became completely unreachable during "
                           f"monitoring — service may have crashed or been blocked"),
            })

        # ── Latency escalation → progressive rate limiting ───────────
        lats = pd["latencies"]
        if len(lats) >= 4:
            first_half = statistics.mean(lats[:len(lats) // 2])
            second_half = statistics.mean(lats[len(lats) // 2:])
            if second_half > first_half * 1.5 and (second_half - first_half) > 10:
                anomalies.append({
                    "type": "latency_escalation",
                    "port": port,
                    "severity": "MEDIUM",
                    "detail": (f"Port {port} latency increased from "
                               f"{first_half:.1f} ms → {second_half:.1f} ms "
                               f"during monitoring — possible progressive throttling"),
                })

        # ── Latency spikes → intermittent deep inspection ────────────
        if len(lats) >= 3 and pd["stdev_ms"] > pd["avg_ms"] * 0.5:
            anomalies.append({
                "type": "latency_jitter",
                "port": port,
                "severity": "LOW",
                "detail": (f"Port {port} shows high latency variance "
                           f"(stdev {pd['stdev_ms']} ms vs avg {pd['avg_ms']} ms) "
                           f"— possible intermittent packet inspection"),
            })

    # ── Cross-port pattern: synchronized drops ───────────────────────
    if len(rounds) >= 3:
        for r in rounds:
            all_dropped = all(
                not r["probes"].get(p, {}).get("reachable", True)
                for p in port_data
            )
            if all_dropped and len(port_data) > 1:
                anomalies.append({
                    "type": "synchronized_drop",
                    "port": "all",
                    "severity": "HIGH",
                    "detail": (f"All ports became unreachable simultaneously in "
                               f"round {r['round']} — possible firewall block or "
                               f"IDS response triggered by scanning activity"),
                })
                break  # Only report once

    return anomalies
