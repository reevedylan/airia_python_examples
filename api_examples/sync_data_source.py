"""
Airia Data Source Sync Script

How to use:
1. Find your data source URL: https://prodaus.airia.ai/{project-id}/dataConnectors/dcAssetsList/{data-source-id}
2. Update PROJECT_ID and DATA_SOURCE_ID below with your values
3. Run the script — it triggers a reprocess of the data source and prints the response
"""

import os

import requests

# UPDATE THESE VALUES
BASE_URL = "https://prodaus.api.airia.ai"
API_KEY = os.environ.get("AIRIA_API_KEY", "ak-YOUR_API_KEY_HERE")
PROJECT_ID = "your-project-id"
DATA_SOURCE_ID = "your-data-source-id"

HEADERS = {
    "X-API-Key": API_KEY,
}


def sync_data_source():
    response = requests.post(
        f"{BASE_URL}/datastore/v1/store/connector/{DATA_SOURCE_ID}/{PROJECT_ID}/reprocess",
        headers=HEADERS,
    )
    try:
        response.raise_for_status()
    except requests.HTTPError:
        print(f"Request failed ({response.status_code}): {response.text}")
        raise
    return response.status_code


# EXECUTION
status = sync_data_source()
print(f"Synced data source {DATA_SOURCE_ID}, status code: {status}")
