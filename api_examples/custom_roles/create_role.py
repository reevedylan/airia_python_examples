"""
Airia Custom Role Creator

How to use:
1. Set your API key
2. Update ROLE_NAME and PERMISSIONS below
3. Run the script — it validates the permission list, then creates the custom role and prints the response

The resulting role's id can then be added to a group's roleIds (see api_examples/groups/update_group.py).
"""

import os

import requests

# UPDATE THESE VALUES
BASE_URL = "https://prodaus.api.airia.ai"
API_KEY = os.environ.get("AIRIA_API_KEY", "ak-YOUR_API_KEY_HERE")
ROLE_NAME = "your-role-name"
PERMISSIONS = [
    "marketplace:tenant:read",
    "settings:user:read",
    "common:artifact:read",
    "settings:permission:read",
    "studio:project:read",
    "settings:workspace:read",
    "common:agent:execute",
]

HEADERS = {
    "accept": "application/json",
    "content-type": "application/json",
    "X-API-Key": API_KEY,
}


def validate_permissions():
    response = requests.post(
        f"{BASE_URL}/v1/custom-roles/validate-permissions",
        headers=HEADERS,
        json={"permissions": PERMISSIONS},
    )
    try:
        response.raise_for_status()
    except requests.HTTPError:
        print(f"Request failed ({response.status_code}): {response.text}")
        raise
    return response.json()


def create_custom_role():
    payload = {
        "displayName": ROLE_NAME,
        "permissions": PERMISSIONS,
    }
    response = requests.post(
        f"{BASE_URL}/v1/custom-roles",
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
validation = validate_permissions()
print(f"Validation result: {validation}")

result = create_custom_role()
print(f"Created role: {result}")
