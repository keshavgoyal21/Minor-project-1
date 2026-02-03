import os
import requests

API_KEY = os.getenv("NVD_API_KEY")
BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

if not API_KEY:
    raise RuntimeError("NVD_API_KEY environment variable not set")

headers = {
    "apiKey": API_KEY
}


def query_nvd(keyword=None, cpe=None, limit=5):
    params = {"resultsPerPage": limit}

    if cpe:
        params["cpeName"] = cpe
    elif keyword:
        params["keywordSearch"] = keyword
    else:
        return []

    response = requests.get(BASE_URL, headers=headers, params=params)
    if response.status_code != 200:
        return []

    return response.json().get("vulnerabilities", [])
