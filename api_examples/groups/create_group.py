"""
Airia Group Creator

How to use:
1. Set your API key
2. Update GROUP_NAME, ROLE_IDS, USER_IDS, PROJECT_IDS below
3. Run the script — it POSTs a new group and prints the response
"""

import os
import requests
from dotenv import load_dotenv

load_dotenv()

# UPDATE THESE VALUES
BASE_URL = "https://prodaus.api.airia.ai"
API_KEY = os.environ.get("AIRIA_API_KEY", "ak-YOUR_API_KEY_HERE")
GROUP_NAME = "your-group-name"
ROLE_IDS = []
USER_IDS = []
PROJECT_IDS = []

HEADERS = {
    "accept": "application/json",
    "content-type": "application/json",
    "X-API-Key": API_KEY,
}


def create_group():
    payload = {
        "name": GROUP_NAME,
        "roleIds": ROLE_IDS,
        "userIds": USER_IDS,
        "projectIds": PROJECT_IDS,
    }
    response = requests.post(
        f"{BASE_URL}/v1/Groups",
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
result = create_group()
print(result)
