"""
Airia Permission Listing

How to use:
1. Set your API key
2. Adjust SEARCH / SORT_BY / SORT_DIRECTION / PAGE_NUMBER / PAGE_SIZE below if needed
3. Run the script — it fetches the available permissions (~290 in the platform) and prints each one

Useful for building the PERMISSIONS list passed to create_role.py.
"""

import os

import requests

# UPDATE THESE VALUES
BASE_URL = "https://prodaus.api.airia.ai"
API_KEY = os.environ.get("AIRIA_API_KEY", "ak-YOUR_API_KEY_HERE")
SEARCH = None
SORT_BY = "name"
SORT_DIRECTION = "ASC"
PAGE_NUMBER = 1
PAGE_SIZE = 300

HEADERS = {
    "accept": "application/json",
    "X-API-Key": API_KEY,
}


def get_permissions():
    response = requests.get(
        f"{BASE_URL}/v1/custom-roles/permissions",
        params={
            "search": SEARCH,
            "sortBy": SORT_BY,
            "sortDirection": SORT_DIRECTION,
            "pageNumber": PAGE_NUMBER,
            "pageSize": PAGE_SIZE,
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
result = get_permissions()
for permission in result.get("items", []):
    print(permission)
