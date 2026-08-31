"""
Airia Agent Version Promoter

How to use:
1. Set your API key
2. Update AGENT_ID below
3. Run the script — it lists the agent's pipeline versions and marks the active one
4. To promote a different version, set TARGET_VERSION_ID and run again
"""

import os
import requests
from dotenv import load_dotenv

load_dotenv()

# UPDATE THESE VALUES
BASE_URL = "https://prodaus.api.airia.ai"
API_KEY = os.environ.get("AIRIA_API_KEY", "ak-YOUR_API_KEY_HERE")
AGENT_ID = "your-agent-id"
TARGET_VERSION_ID = ""

HEADERS = {
    "accept": "application/json",
    "content-type": "application/json",
    "X-API-Key": API_KEY,
}


def list_versions():
    response = requests.get(f"{BASE_URL}/v1/PipelinesConfig/{AGENT_ID}", headers=HEADERS)
    try:
        response.raise_for_status()
    except requests.HTTPError:
        print(f"Request failed ({response.status_code}): {response.text}")
        raise
    return response.json()


def promote_version(config, target_version_id):
    payload = {
        "id": AGENT_ID,
        "activeVersionId": target_version_id,
        "projectId": config["projectId"],
    }
    response = requests.put(f"{BASE_URL}/v1/PipelinesConfig/{AGENT_ID}", headers=HEADERS, json=payload)
    try:
        response.raise_for_status()
    except requests.HTTPError:
        print(f"Request failed ({response.status_code}): {response.text}")
        raise
    return response.json()


# EXECUTION
config = list_versions()
for version in config["versions"]:
    active = "<-- ACTIVE" if version.get("id") == config.get("activeVersionId") else ""
    print(version.get("versionNumber"), version.get("id"), active)

if TARGET_VERSION_ID:
    result = promote_version(config, TARGET_VERSION_ID)
    print(f"Promoted version: {result}")
