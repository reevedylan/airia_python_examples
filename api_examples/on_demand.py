"""
Airia OnDemand Processing Upload Script

How to use:
1. Set your API key
2. Update FILE_PATH with the file you want to process
3. Run the script — it uploads the file for OnDemand processing and prints the signed URL
"""

import os
import requests
from dotenv import load_dotenv

load_dotenv()

# UPDATE THESE VALUES
BASE_URL = "https://prodaus.api.airia.ai"
API_KEY = os.environ.get("AIRIA_API_KEY", "ak-YOUR_API_KEY_HERE")
FILE_PATH = "your-file-path"

MIME_TYPES = {
    ".pdf": "application/pdf",
    ".doc": "application/msword",
    ".docx": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    ".txt": "text/plain",
    ".xls": "application/vnd.ms-excel",
    ".xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
}

HEADERS = {
    "accept": "application/json",
    "X-API-Key": API_KEY,
}


def process_file_on_demand():
    file_name = os.path.basename(FILE_PATH)
    file_ext = os.path.splitext(FILE_PATH)[1].lower()
    mime_type = MIME_TYPES.get(file_ext)

    with open(FILE_PATH, "rb") as f:
        response = requests.post(
            f"{BASE_URL}/v1/upload/onDemandProcessing",
            headers=HEADERS,
            files={"file": (file_name, f, mime_type)},
        )
    try:
        response.raise_for_status()
    except requests.HTTPError:
        print(f"Request failed ({response.status_code}): {response.text}")
        raise
    return response.json().get("signedURL")


# EXECUTION
signed_url = process_file_on_demand()
print(f"Signed URL: {signed_url}")
