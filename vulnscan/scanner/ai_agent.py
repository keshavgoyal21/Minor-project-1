"""
AI Security Agent — Google Gemini
──────────────────────────────────
Sends structured scan context to Google Gemini and parses JSON responses
for precise mitigations, exploit-chain analysis, network anomaly detection,
and zero-day risk assessment.

If neither ``google-genai`` nor ``google-generativeai`` is installed, or the
``GEMINI_API_KEY`` environment variable is unset, the module exposes
``GEMINI_AVAILABLE = False`` and every public function returns ``None``.
"""

import hashlib
import json
import os
import random
import sys
import time as _time

# ── Lazy / optional Gemini import ────────────────────────────────────
# Try the new SDK first, fall back to deprecated package
_USE_NEW_SDK = False
_GEMINI_SDK = False

try:
    from google import genai  # type: ignore
    _GEMINI_SDK = True
    _USE_NEW_SDK = True
except ImportError:
    try:
        import google.generativeai as genai_legacy  # type: ignore
        _GEMINI_SDK = True
    except ImportError:
        pass

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
GEMINI_AVAILABLE = bool(_GEMINI_SDK and GEMINI_API_KEY)

_client = None
_model_legacy = None

_MODEL_ID = "gemini-2.5-flash-lite"
_FALLBACK_MODELS = ["gemini-2.5-flash", "gemini-2.0-flash"]
_GEN_CONFIG = {
    "temperature": 0.3,
    "top_p": 0.9,
    "max_output_tokens": 4096,
}

_MAX_AI_ATTEMPTS = 3  # initial attempt + up to 2 retries
_BACKOFF_BASE = 2
_BACKOFF_MAX = 8
_BACKOFF_JITTER = 0.5
_CACHE = {}


def _make_cache_key(prompt, model_id=None):
    key = prompt if model_id is None else f"{model_id}|{prompt}"
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def _is_rate_limit_error(text):
    if not text:
        return False
    lower = text.lower()
    return any(token in lower for token in ["429", "resource_exhausted", "rate limit", "quota", "too many requests", "requests exceeded", "try again later"])


def _refresh_availability():
    """Re-check SDK availability and GEMINI_API_KEY (in case load_dotenv ran after initial import)."""
    global GEMINI_API_KEY, GEMINI_AVAILABLE, _GEMINI_SDK, _USE_NEW_SDK, genai, genai_legacy
    GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")

    if not _GEMINI_SDK:
        try:
            from google import genai  # type: ignore
            _GEMINI_SDK = True
            _USE_NEW_SDK = True
            globals()["genai"] = genai
        except ImportError:
            try:
                import google.generativeai as genai_legacy  # type: ignore
                _GEMINI_SDK = True
                _USE_NEW_SDK = False
                globals()["genai_legacy"] = genai_legacy
            except ImportError:
                _GEMINI_SDK = False

    GEMINI_AVAILABLE = bool(_GEMINI_SDK and GEMINI_API_KEY)
    return GEMINI_AVAILABLE


def _call_gemini_once(prompt, model_id):
    """Single attempt to call Gemini with the specified model."""
    global _client, _model_legacy

    if _USE_NEW_SDK:
        if _client is None:
            _client = genai.Client(api_key=GEMINI_API_KEY)
        response = _client.models.generate_content(
            model=model_id,
            contents=prompt,
            config={
                "temperature": _GEN_CONFIG["temperature"],
                "top_p": _GEN_CONFIG["top_p"],
                "max_output_tokens": _GEN_CONFIG["max_output_tokens"],
                "response_mime_type": "application/json",
            },
        )
        return response.text
    else:
        if _model_legacy is None or True:  # Re-create for different models
            genai_legacy.configure(api_key=GEMINI_API_KEY)
            _model_legacy = genai_legacy.GenerativeModel(
                model_id,
                generation_config={
                    **_GEN_CONFIG,
                    "response_mime_type": "application/json",
                },
            )
        response = _model_legacy.generate_content(prompt)
        return response.text


def _call_gemini(prompt):
    """Send a prompt to Gemini with retry and model fallback on rate limits."""

    if not GEMINI_AVAILABLE:
        _refresh_availability()
    if not GEMINI_AVAILABLE:
        return None

    cache_key = _make_cache_key(prompt)
    if cache_key in _CACHE:
        return _CACHE[cache_key]

    models_to_try = [_MODEL_ID] + _FALLBACK_MODELS

    for model_id in models_to_try:
        for attempt in range(_MAX_AI_ATTEMPTS):
            if attempt > 0:
                wait = min(_BACKOFF_BASE ** attempt, _BACKOFF_MAX) + random.random() * _BACKOFF_JITTER
                _time.sleep(wait)

            try:
                text = _call_gemini_once(prompt, model_id)
                if text:
                    _CACHE[cache_key] = text
                    return text
                break
            except Exception as e:
                err_str = str(e)
                if _is_rate_limit_error(err_str) and attempt < _MAX_AI_ATTEMPTS - 1:
                    continue
                if _is_rate_limit_error(err_str):
                    break
                break

    return None


def _safe_json(text):
    """Best-effort JSON parse from Gemini response text."""
    try:
        return json.loads(text)
    except (json.JSONDecodeError, TypeError):
        # Try to extract JSON block from markdown fences
        if text and "```" in text:
            start = text.find("{")
            end = text.rfind("}") + 1
            if start != -1 and end > start:
                try:
                    return json.loads(text[start:end])
                except json.JSONDecodeError:
                    pass
    return None


def _vuln_ai_fallback(reason="AI unavailable"):
    return {
        "severity": "INFO",
        "finding": "AI unavailable",
        "reason": reason,
        "recommendation": "Retry later",
        "mitigation": {
            "summary": "Apply patches and secure exposed services.",
            "steps": ["Update software", "Close unused ports"],
        },
    }


def _build_vulnerability_prompt(vuln, host=None, port=None, behavior_data=None, monitoring_data=None):
    host_context = {
        "ip": host.get("ip") if isinstance(host, dict) else None,
        "open_port": port.get("port") if isinstance(port, dict) else None,
        "service": port.get("service") if isinstance(port, dict) else None,
        "version": port.get("version") if isinstance(port, dict) else None,
        "banner": (port.get("banner") or "")[:200] if isinstance(port, dict) else None,
    }
    vuln_context = {
        "cve_id": vuln.get("cve_id"),
        "severity": vuln.get("severity"),
        "cvss_score": vuln.get("cvss_score"),
        "cwe": vuln.get("cwe"),
        "description": vuln.get("description"),
        "published": vuln.get("published"),
    }

    context_obj = {
        "host": host_context,
        "vulnerability": vuln_context,
    }

    if behavior_data:
        context_obj["behavior_summary"] = {
            "risk_score": behavior_data.get("risk_score"),
            "risk_level": behavior_data.get("risk_level"),
            "findings": [f.get("title") for f in behavior_data.get("findings", []) if isinstance(f, dict)],
        }

    if monitoring_data:
        context_obj["monitoring_summary"] = {
            "duration_secs": monitoring_data.get("duration_secs"),
            "total_rounds": monitoring_data.get("total_rounds"),
            "summary": monitoring_data.get("summary", []),
        }

    context = json.dumps(context_obj, indent=2)
    return f"""You are an expert cybersecurity analyst. Analyze the vulnerability below and provide a structured JSON response.

CONTEXT:
{context}

Respond with JSON only, no markdown, no explanation, and no surrounding text. The JSON object must contain exactly these keys:
{{
  "severity": "",              // CRITICAL/HIGH/MEDIUM/LOW/INFO
  "finding": "",               // short finding title
  "reason": "",                // why this vulnerability is important
  "recommendation": "",        // what to fix or investigate
  "mitigation": {{
    "summary": "",
    "steps": []
  }}
}}

Rules:
- Return JSON only. Do not include any extra prose.
- Use the CVE description and host context to provide accurate remediation.
- Provide concrete mitigation steps, not generic phrases.
- If the AI cannot produce detailed output, return a valid JSON fallback object.
"""


def _normalize_vuln_ai_output(parsed):
    if not isinstance(parsed, dict):
        return None
    mitigation = parsed.get("mitigation") or {}
    if not isinstance(mitigation, dict):
        mitigation = {"summary": str(mitigation), "steps": []}

    return {
        "severity": str(parsed.get("severity") or "INFO").upper(),
        "finding": str(parsed.get("finding") or parsed.get("title") or "AI unavailable"),
        "reason": str(parsed.get("reason") or parsed.get("explanation") or "AI did not return a reason."),
        "recommendation": str(parsed.get("recommendation") or parsed.get("fix") or "Retry later."),
        "mitigation": {
            "summary": str(mitigation.get("summary") or mitigation.get("text") or "Apply patches and secure services."),
            "steps": [str(step) for step in mitigation.get("steps") or mitigation.get("actions") or [] if step],
        },
    }


def generate_vulnerability_ai(vuln, host=None, port=None, behavior_data=None, monitoring_data=None, delay_seconds=1):
    if not GEMINI_AVAILABLE:
        return _vuln_ai_fallback("Gemini unavailable")

    prompt = _build_vulnerability_prompt(vuln, host=host, port=port, behavior_data=behavior_data, monitoring_data=monitoring_data)
    text = _call_gemini(prompt)
    parsed = _safe_json(text)
    if parsed:
        normalized = _normalize_vuln_ai_output(parsed)
        if normalized and normalized.get("finding") and normalized.get("mitigation"):
            if delay_seconds and delay_seconds > 0:
                _time.sleep(delay_seconds)
            return normalized

    if delay_seconds and delay_seconds > 0:
        _time.sleep(delay_seconds)
    return _vuln_ai_fallback("Rate limited or API failed")


# =====================================================================
#  Prompt builders  (private)
# =====================================================================

def _build_vuln_prompt(scan_data, behavior_data, monitoring_data=None):
    """Build the vulnerability-analysis prompt."""
    # Summarise open ports + CVEs
    port_summary = []
    for host in scan_data.get("hosts", []):
        for p in host.get("open_ports", []):
            entry = {
                "port": p["port"],
                "service": p.get("service"),
                "version": p.get("version"),
                "banner": (p.get("banner") or "")[:200],
                "cves": [],
            }
            for v in p.get("vulnerabilities", [])[:5]:
                entry["cves"].append({
                    "id": v["cve_id"],
                    "score": v["cvss_score"],
                    "severity": v["severity"],
                    "cwe": v["cwe"],
                    "description": v["description"][:200],
                })
            port_summary.append(entry)

    # Summarise behavior
    behavior_summary = []
    for hp in behavior_data.get("host_profiles", []):
        behavior_summary.append({
            "ip": hp["ip"],
            "risk_score": hp["risk_score"],
            "risk_level": hp["risk_level"],
            "findings": [f["title"] for f in hp.get("findings", [])],
            "anomalies": hp.get("anomalies", {}),
        })

    context_obj = {
        "ports_and_cves": port_summary,
        "behavior_profiles": behavior_summary,
    }

    # Include monitoring data if available
    if monitoring_data:
        context_obj["active_monitoring"] = {
            "duration_secs": monitoring_data.get("duration_secs"),
            "total_rounds": monitoring_data.get("total_rounds"),
            "anomalies": monitoring_data.get("anomalies", []),
            "summary": monitoring_data.get("summary", []),
        }

    context = json.dumps(context_obj, indent=2)

    return f"""You are an expert cybersecurity analyst AI agent. Analyze the following vulnerability scan results and provide actionable security intelligence.

SCAN DATA:
{context}

Respond with a JSON object containing exactly these keys:

{{
  "overall_risk_summary": "Executive summary of the host's security posture (2-3 sentences)",
  "cve_mitigations": {{
    "CVE-ID-HERE": "Specific, actionable mitigation for this exact CVE — include exact commands, config changes, patch versions, or URLs. Must be tailored to the service version found."
  }},
  "exploit_chains": [
    {{
      "chain_name": "Short name for the attack chain",
      "severity": "CRITICAL/HIGH/MEDIUM/LOW",
      "likelihood": "HIGH/MEDIUM/LOW",
      "steps": ["Step 1: ...", "Step 2: ...", "Step 3: ..."],
      "explanation": "How these vulnerabilities can be combined for an attack"
    }}
  ],
  "priority_actions": ["Ranked list of top 5 immediate actions to take"]
}}

Rules:
- cve_mitigations MUST have an entry for EVERY CVE ID found in the scan data
- Each mitigation must be SPECIFIC to the exact CVE, service version, and configuration found
- Include exact commands (e.g., "apt upgrade openssh-server"), config paths, or patch URLs
- NEVER use generic advice like "Apply vendor patches" — be precise and actionable
- Exploit chains should reference actual CVEs from the scan data
- If no meaningful chains exist, return an empty exploit_chains array
- Limit to top 5 priority actions"""


def _build_behavior_prompt(behavior_data, packet_data):
    """Build the network-behavior-analysis prompt."""
    context_parts = {
        "behavior_profiles": [],
        "packet_analysis": None,
    }

    for hp in behavior_data.get("host_profiles", []):
        profile = hp.get("profile", {})
        context_parts["behavior_profiles"].append({
            "ip": hp["ip"],
            "risk_score": hp["risk_score"],
            "open_port_count": profile.get("open_port_count", 0),
            "high_risk_ports": profile.get("high_risk_ports", []),
            "avg_latency_ms": profile.get("avg_connect_latency_ms", 0),
            "banner_disclosures": profile.get("banner_disclosure_count", 0),
            "cleartext_services": profile.get("cleartext_services", []),
            "findings": [f["title"] for f in hp.get("findings", [])],
            "anomalies": hp.get("anomalies", {}),
        })

    if packet_data:
        context_parts["packet_analysis"] = {
            "total_packets": packet_data.get("total_packets", 0),
            "duration_secs": packet_data.get("duration_secs", 0),
            "protocol_distribution": packet_data.get("protocol_distribution", {}),
            "patterns": [{
                "name": p["name"],
                "severity": p["severity"],
                "confidence": p["confidence"],
                "detail": p["detail"],
            } for p in packet_data.get("patterns", [])],
        }

    context = json.dumps(context_parts, indent=2)

    return f"""You are an expert network security analyst AI agent. Analyze host network behavior and packet patterns to detect security anomalies.

BEHAVIOR AND PACKET DATA:
{context}

Respond with a JSON object containing exactly these keys:

{{
  "anomaly_assessment": "Overall assessment of network behavior anomalies (2-3 sentences)",
  "firewall_detection": {{
    "detected": true/false,
    "confidence": 0-100,
    "firewall_type": "stateful/stateless/WAF/cloud-based/unknown",
    "evidence": ["Evidence point 1", "Evidence point 2"]
  }},
  "ids_ips_detection": {{
    "detected": true/false,
    "confidence": 0-100,
    "evidence": ["Evidence point 1"],
    "evasion_notes": "How the IDS/IPS might be evaded (for defensive awareness)"
  }},
  "honeypot_indicators": {{
    "detected": true/false,
    "confidence": 0-100,
    "indicators": ["Indicator 1", "Indicator 2"]
  }},
  "zero_day_risks": [
    {{
      "risk_level": "CRITICAL/HIGH/MEDIUM/LOW",
      "service": "Affected service",
      "suspicious_behavior": "What behavior looks unusual",
      "reasoning": "Why this could indicate an unknown vulnerability",
      "recommended_monitoring": "What to watch for"
    }}
  ]
}}

Rules:
- Base firewall detection on timing patterns, filtered vs closed ports, and connection behaviors
- Honeypot detection: look for too-many open ports, unusual service combinations, too-fast responses
- Zero-day risks: identify services with anomalous behavior that don't match known vulnerability patterns
- Be conservative with confidence scores — only report high confidence when evidence is strong
- If no packet data is available, base analysis solely on connection behavior"""


def _build_zeroday_prompt(host_profile, findings, packet_patterns):
    """Build a focused zero-day risk assessment prompt."""
    context = json.dumps({
        "host_profile": {
            "ip": host_profile.get("ip"),
            "open_port_count": host_profile.get("open_port_count", 0),
            "high_risk_ports": host_profile.get("high_risk_ports", []),
            "avg_latency_ms": host_profile.get("avg_connect_latency_ms", 0),
            "banner_disclosures": host_profile.get("banner_disclosure_count", 0),
            "cleartext_services": host_profile.get("cleartext_services", []),
        },
        "findings": [{"title": f["title"], "severity": f["severity"],
                       "reason": f["reason"]} for f in findings],
        "packet_patterns": [{"name": p["name"], "severity": p["severity"],
                             "detail": p["detail"]} for p in (packet_patterns or [])],
    }, indent=2)

    return f"""You are a zero-day vulnerability research analyst. Based on the host behavior profile and detected patterns, assess the risk of unknown/zero-day vulnerabilities.

HOST DATA:
{context}

Respond with a JSON object containing exactly these keys:

{{
  "risk_level": "CRITICAL/HIGH/MEDIUM/LOW",
  "confidence": 0-100,
  "assessment_summary": "2-3 sentence assessment of zero-day risk",
  "suspicious_indicators": [
    {{
      "indicator": "What looks unusual",
      "severity": "HIGH/MEDIUM/LOW",
      "explanation": "Why this is suspicious from a zero-day perspective"
    }}
  ],
  "potential_attack_vectors": [
    {{
      "vector": "Name of theoretical attack vector",
      "target_service": "Which service could be targeted",
      "description": "How a zero-day could theoretically be exploited here",
      "prerequisite": "What conditions must be met"
    }}
  ],
  "recommended_monitoring": [
    "Specific monitoring action to detect potential exploitation"
  ]
}}

Rules:
- Be realistic — don't fabricate zero-day scenarios without justification
- Base risk on actual anomalous behaviors, not speculation
- Consider: unusual banners, non-standard responses, timing anomalies, service versions near end-of-life
- If the host shows standard behavior with no anomalies, rate risk as LOW with explanation"""


# =====================================================================
#  Public API
# =====================================================================

def analyze_vulnerabilities(scan_data, behavior_data, monitoring_data=None):
    """Send scan + behavior + monitoring context to Gemini for vulnerability intelligence.

    Returns
    -------
    dict | None
        Parsed JSON with keys: overall_risk_summary, cve_mitigations,
        exploit_chains, priority_actions.  ``None`` if Gemini unavailable.
    """
    _refresh_availability()
    if not GEMINI_AVAILABLE:
        return None

    try:
        prompt = _build_vuln_prompt(scan_data, behavior_data, monitoring_data)
        text = _call_gemini(prompt)
        return _safe_json(text)
    except Exception:
        return None


def analyze_network_behavior(behavior_data, packet_data=None):
    """Send behavior + packet context to Gemini for anomaly intelligence.

    Returns
    -------
    dict | None
        Parsed JSON with keys: anomaly_assessment, firewall_detection,
        ids_ips_detection, honeypot_indicators, zero_day_risks.
    """
    _refresh_availability()
    if not GEMINI_AVAILABLE:
        return None

    try:
        prompt = _build_behavior_prompt(behavior_data, packet_data)
        text = _call_gemini(prompt)
        return _safe_json(text)
    except Exception:
        return None


def assess_zero_day_risk(host_profile, findings, packet_patterns=None):
    """Focused zero-day risk assessment for a single host.

    Returns
    -------
    dict | None
        Parsed JSON with keys: risk_level, confidence, assessment_summary,
        suspicious_indicators, potential_attack_vectors, recommended_monitoring.
    """
    _refresh_availability()
    if not GEMINI_AVAILABLE:
        return None

    try:
        prompt = _build_zeroday_prompt(host_profile, findings, packet_patterns)
        text = _call_gemini(prompt)
        return _safe_json(text)
    except Exception:
        return None

