import os
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
TIMEOUT = 15
RETRY_ATTEMPTS = 3
_QUERY_CACHE = {}

retry_strategy = Retry(
    total=RETRY_ATTEMPTS,
    backoff_factor=1,
    status_forcelist=[429, 500, 502, 503, 504],
    allowed_methods=["GET"],
    raise_on_status=False,
)

session = requests.Session()
session.mount("https://", HTTPAdapter(max_retries=retry_strategy))
session.mount("http://", HTTPAdapter(max_retries=retry_strategy))


def _current_api_key():
    return os.getenv("NVD_API_KEY", "").strip() or None


def _cache_key(keyword, cpe, limit):
    return f"{keyword or ''}|{cpe or ''}|{limit}"


def query_nvd(keyword=None, cpe=None, limit=5, stop_requested=None):
    if stop_requested and callable(stop_requested) and stop_requested():
        return []

    params = {"resultsPerPage": limit}
    if cpe:
        params["cpeName"] = cpe
    elif keyword:
        params["keywordSearch"] = keyword
    else:
        return []

    cache_key = _cache_key(keyword, cpe, limit)
    if cache_key in _QUERY_CACHE:
        return _QUERY_CACHE[cache_key]

    api_key = _current_api_key()
    if not api_key:
        print("\033[33m  [!] NVD_API_KEY is not configured. Skipping NVD lookup.\033[0m")
        return []

    headers = {"apiKey": api_key}

    try:
        response = session.get(BASE_URL, headers=headers, params=params, timeout=TIMEOUT)
    except (requests.exceptions.SSLError, requests.exceptions.ConnectionError,
            requests.exceptions.Timeout) as e:
        print(f"\033[33m  [!] NVD API error: {type(e).__name__} — skipping this query\033[0m")
        return []

    if response.status_code != 200:
        status = response.status_code
        reason = response.reason or "unknown"
        print(f"\033[33m  [!] NVD API returned {status} {reason} — skipping this query\033[0m")
        return []

    results = response.json().get("vulnerabilities", []) or []
    _QUERY_CACHE[cache_key] = results
    return results
