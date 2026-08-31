"""
Airia Group/Role Creator

How to use:
1. Set your API key
2. Update GROUP_ID, GROUP_NAME, and ROLE_IDS below
3. Run the script — it PUTs the group definition and prints the response
"""

import os
import requests
from dotenv import load_dotenv

load_dotenv()

# UPDATE THESE VALUES
BASE_URL = "https://prodaus.api.airia.ai"
API_KEY = os.environ.get("AIRIA_API_KEY", "ak-YOUR_API_KEY_HERE")
GROUP_ID = "your-group-id"
GROUP_NAME = "your-group-name"
ROLE_IDS = ["your-role-id"]
USER_IDS = []
PROJECT_IDS = []

HEADERS = {
    "accept": "application/json",
    "content-type": "application/json",
    "X-API-Key": API_KEY,
}


def upsert_group():
    payload = {
        "id": GROUP_ID,
        "name": GROUP_NAME,
        "roleIds": ROLE_IDS,
        "userIds": USER_IDS,
        "projectIds": PROJECT_IDS,
    }
    response = requests.put(
        f"{BASE_URL}/v1/Groups/{GROUP_ID}",
        headers=HEADERS,
        json=payload,
    )
    try:
        response.raise_for_status()
    except requests.HTTPError:
        print(f"Request failed ({response.status_code}): {response.text}")
        raise
    return response.json()


# EXECUTION
result = upsert_group()
print(result)
