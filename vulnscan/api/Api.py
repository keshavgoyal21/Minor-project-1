import os
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

API_KEY = os.getenv("NVD_API_KEY")
BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
TIMEOUT = 15
RETRY_ATTEMPTS = 3

if not API_KEY:
    raise RuntimeError("NVD_API_KEY environment variable not set")

headers = {"apiKey": API_KEY}

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


def query_nvd(keyword=None, cpe=None, limit=5):
    params = {"resultsPerPage": limit}

    if cpe:
        params["cpeName"] = cpe
    elif keyword:
        params["keywordSearch"] = keyword
    else:
        return []

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

    return response.json().get("vulnerabilities", [])
