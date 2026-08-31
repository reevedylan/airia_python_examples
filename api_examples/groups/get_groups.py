"""
Airia Group Listing

How to use:
1. Set your API key
2. Adjust PAGE_NUMBER / PAGE_SIZE / SORT_BY / SORT_DIRECTION below if needed
3. Run the script — it fetches the group list and prints each group
"""

import os
import requests
from dotenv import load_dotenv

load_dotenv()

# UPDATE THESE VALUES
BASE_URL = "https://prodaus.api.airia.ai"
API_KEY = os.environ.get("AIRIA_API_KEY", "ak-YOUR_API_KEY_HERE")
PAGE_NUMBER = 1
PAGE_SIZE = 50
SORT_BY = "name"
SORT_DIRECTION = "ASC"

HEADERS = {
    "accept": "application/json",
    "X-API-Key": API_KEY,
}


def get_groups():
    response = requests.get(
        f"{BASE_URL}/v1/Groups",
        params={
            "PageNumber": PAGE_NUMBER,
            "PageSize": PAGE_SIZE,
            "SortBy": SORT_BY,
            "SortDirection": SORT_DIRECTION,
        },
        headers=HEADERS,
    )
    try:
        response.raise_for_status()
    except requests.HTTPError:
        print(f"Request failed ({response.status_code}): {response.text}")
        raise
    return response.json()


# EXECUTION
result = get_groups()
for group in result.get("items", []):
    print(f"{group['id']}  {group['name']}")
