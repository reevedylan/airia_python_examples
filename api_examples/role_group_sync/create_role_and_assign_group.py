"""
Airia Role/Group Sync

How to use:
1. Set your API key
2. Update ROLE_NAME, PERMISSIONS, and GROUP_NAME below (GROUP_NAME must match
   an existing group)
3. Run the script — it validates the permission list, creates the custom
   role, finds the target group by name, merges the new role into that
   group's *existing* roles (leaving its users/projects untouched), and PUTs
   the update.

Two undocumented API quirks this script exists to handle (details in
api_examples/custom_roles/README.md and api_examples/groups/README.md):
- GET /v1/Groups[/{id}] nests roles/users as objects (`rolesList[].id`,
  `users[].id`), but PUT /v1/Groups/{id} takes flat id arrays (`roleIds`,
  `userIds`) instead.
- PUT /v1/Groups/{id} REPLACES roleIds/userIds/projectIds — it does not
  merge. That's why this script fetches the group's current membership and
  merges the new role id in before PUTting, rather than PUTting ROLE_IDS
  alone.
"""

import os
import sys

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
]
GROUP_NAME = "your-group-name"

HEADERS = {
    "accept": "application/json",
    "content-type": "application/json",
    "X-API-Key": API_KEY,
}


def _raise_with_body(response):
    try:
        response.raise_for_status()
    except requests.HTTPError:
        print(f"Request failed ({response.status_code}): {response.text}")
        raise


def validate_permissions():
    response = requests.post(
        f"{BASE_URL}/v1/custom-roles/validate-permissions",
        headers=HEADERS,
        json={"permissions": PERMISSIONS},
    )
    _raise_with_body(response)
    return response.json()


def create_custom_role():
    response = requests.post(
        f"{BASE_URL}/v1/custom-roles",
        headers=HEADERS,
        json={"displayName": ROLE_NAME, "permissions": PERMISSIONS},
    )
    _raise_with_body(response)
    return response.json()


def find_group_by_name(name):
    response = requests.get(
        f"{BASE_URL}/v1/Groups",
        headers=HEADERS,
        params={
            "PageNumber": 1,
            "PageSize": 300,
            "SortBy": "name",
            "SortDirection": "ASC",
        },
    )
    _raise_with_body(response)
    for group in response.json().get("items", []):
        if group["name"] == name:
            return group
    return None


def get_group(group_id):
    response = requests.get(f"{BASE_URL}/v1/Groups/{group_id}", headers=HEADERS)
    _raise_with_body(response)
    return response.json()


def update_group(group_id, name, role_ids, user_ids, project_ids):
    payload = {
        "id": group_id,
        "name": name,
        "roleIds": role_ids,
        "userIds": user_ids,
        "projectIds": project_ids,
    }
    response = requests.put(
        f"{BASE_URL}/v1/Groups/{group_id}",
        headers=HEADERS,
        json=payload,
    )
    _raise_with_body(response)
    return response.json()


# EXECUTION
validation = validate_permissions()
print(f"Validation result: {validation}")

role = create_custom_role()
role_id = role["roleId"]
print(f"Created role: {role}")

group_summary = find_group_by_name(GROUP_NAME)
if group_summary is None:
    print(f"No group named {GROUP_NAME!r} found — leaving the new role unassigned.")
    sys.exit(1)

group = get_group(group_summary["id"])
print(f"Group detail: {group}")

existing_role_ids = [role["id"] for role in (group.get("rolesList") or [])]
existing_user_ids = [user["id"] for user in (group.get("users") or [])]
existing_project_ids = group.get("projectIds") or []

merged_role_ids = list(dict.fromkeys(existing_role_ids + [role_id]))
print(f"Existing role ids on group: {existing_role_ids}")
print(f"Merged role ids to write: {merged_role_ids}")

result = update_group(
    group["id"],
    group["name"],
    merged_role_ids,
    existing_user_ids,
    existing_project_ids,
)
print(f"Updated group: {result}")
