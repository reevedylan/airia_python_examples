"""
Airia File Upload + Pipeline Execution Script

How to use:
1. Set your API key
2. Set your pipeline ID
3. Update FILE_PATH with the file you want to process
4. Run the script — it uploads the file, runs the pipeline against it, and prints the response
"""

import os

import requests

# UPDATE THESE VALUES
BASE_URL = "https://prodaus.api.airia.ai"
API_KEY = os.environ.get("AIRIA_API_KEY", "ak-YOUR_API_KEY_HERE")
PIPELINE_ID = "your-pipeline-id"
FILE_PATH = "your-file-path"

HEADERS = {
    "accept": "application/json",
    "X-API-Key": API_KEY,
}


def upload_file():
    with open(FILE_PATH, "rb") as f:
        files = {"file": (os.path.basename(FILE_PATH), f)}
        response = requests.post(f"{BASE_URL}/v1/upload", headers=HEADERS, files=files)
    try:
        response.raise_for_status()
    except requests.HTTPError:
        print(f"Request failed ({response.status_code}): {response.text}")
        raise
    data = response.json()
    return data.get("imageUrl") or data.get("fileUrl")


def run_pipeline(file_url):
    if FILE_PATH.lower().endswith((".jpg", ".jpeg", ".png")):
        payload = {"images": [file_url]}
    else:
        payload = {"files": [file_url]}

    response = requests.post(
        f"{BASE_URL}/v2/PipelineExecution/{PIPELINE_ID}",
        headers={**HEADERS, "content-type": "application/json"},
        json=payload,
    )
    try:
        response.raise_for_status()
    except requests.HTTPError:
        print(f"Request failed ({response.status_code}): {response.text}")
        raise
    return response


# EXECUTION
file_url = upload_file()
response = run_pipeline(file_url)

print(f"Status: {response.status_code}")
print(f"Response: {response.text}")
