"""
Airia Group Deletion

How to use:
1. Set your API key
2. Update GROUP_ID with the group you want to delete
3. Run the script — it DELETEs the group and prints the response status
"""

import os

import requests

# UPDATE THESE VALUES
BASE_URL = "https://prodaus.api.airia.ai"
API_KEY = os.environ.get("AIRIA_API_KEY", "ak-YOUR_API_KEY_HERE")
GROUP_ID = "your-group-id"

HEADERS = {
    "accept": "application/json",
    "X-API-Key": API_KEY,
}


def delete_group():
    response = requests.delete(
        f"{BASE_URL}/v1/Groups/{GROUP_ID}",
        headers=HEADERS,
    )
    try:
        response.raise_for_status()
    except requests.HTTPError:
        print(f"Request failed ({response.status_code}): {response.text}")
        raise
    return response.status_code


# EXECUTION
status = delete_group()
print(f"Deleted group {GROUP_ID}, status code: {status}")
