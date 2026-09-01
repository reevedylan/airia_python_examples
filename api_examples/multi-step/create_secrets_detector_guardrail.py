"""
Airia Secrets Detector Guardrail Creator

How to use:
1. Set your API key
2. Update GATEWAY_ID below
3. Run the script — it POSTs a new custom-detector guardrail (regex-based
   secrets/credential detection) and prints the response
"""

import os
import requests
from dotenv import load_dotenv

load_dotenv()

# UPDATE THESE VALUES
BASE_URL = "https://prodaus.api.airia.ai"
API_KEY = os.environ.get("AIRIA_API_KEY", "ak-YOUR_API_KEY_HERE")
GATEWAY_ID = "your-gateway-id"

HEADERS = {
    "accept": "application/json",
    "content-type": "application/json",
    "X-API-Key": API_KEY,
}


def create_guardrail():
    payload = {
        "id": "",
        "name": "custom_secrets_detector",
        "description": "Regex-based secrets detection (strict prefixes + contextual heuristics)",
        "enabled": True,
        "applyDatasource": False,
        "applyToTools": False,
        "applyToToolCalls": False,
        "applyToBrowserExtension": False,
        "filters": [
            {
                "filterType": "CustomDetector",
                "enabled": True,
                "customDetectorRecords": [
                    {
                        "enabled": True,
                        "name": "Secrets (Strict)",
                        "uniqueId": "custom_secret_strict",
                        "description": "Vendor-prefixed API keys, tokens, and private keys",
                        "filterActionType": "Audit",
                        "filterActionMessage": "This request contains a credential or API key and was blocked.",
                        "score": 0.7,
                        "context": [],
                        "regexPatterns": [
                            {
                                "name": "anthropic_api_key",
                                "score": 0.95,
                                "regexPattern": r"(?-i:sk-ant-(?:api03|admin01)-[A-Za-z0-9_\-]{93}AA)",
                            },
                            {
                                "name": "openai_api_key_project",
                                "score": 0.95,
                                "regexPattern": r"\b(?-i:sk-proj-[A-Za-z0-9_\-]{20,})\b",
                            },
                            {
                                "name": "openai_api_key_legacy",
                                "score": 0.9,
                                "regexPattern": r"\b(?-i:sk-)[A-Za-z0-9]{48}\b",
                            },
                            {
                                "name": "google_api_key",
                                "score": 0.95,
                                "regexPattern": r"\b(?-i:AIza)[0-9A-Za-z_\-]{35}\b",
                            },
                            {
                                "name": "google_api_key_auth",
                                "score": 0.75,
                                "regexPattern": r"\b(?-i:AQ\.)[A-Za-z0-9_\-.]{20,}\b",
                            },
                            {
                                "name": "aws_access_key_id",
                                "score": 0.95,
                                "regexPattern": r"\b(?-i:(?:A3T[A-Z0-9]|AKIA|ASIA)[A-Z0-9]{16}|(?:ABIA|ACCA|AGPA|AIDA|AIPA|ANPA|ANVA|APKA|AROA|ASCA)[A-Z0-9]{17})\b",
                            },
                            {
                                "name": "github_pat_classic",
                                "score": 0.95,
                                "regexPattern": r"\b(?-i:ghp_[A-Za-z0-9]{36})\b",
                            },
                            {
                                "name": "github_pat_fine_grained",
                                "score": 0.95,
                                "regexPattern": r"\b(?-i:github_pat_[A-Za-z0-9_]{82})\b",
                            },
                            {
                                "name": "github_oauth_app_token",
                                "score": 0.9,
                                "regexPattern": r"\b(?-i:gh[our]_[A-Za-z0-9]{36,255})\b",
                            },
                            {
                                "name": "github_app_installation_token",
                                "score": 0.9,
                                "regexPattern": r"\b(?-i:ghs_[A-Za-z0-9._\-]{36,600})\b",
                            },
                            {
                                "name": "gitlab_pat",
                                "score": 0.95,
                                "regexPattern": r"\b(?-i:glpat-[0-9A-Za-z_\-]{20})\b|\b(?-i:glpat-[0-9A-Za-z_\-]{27,300}\.[0-9a-z]{2}[0-9a-z]{7})\b",
                            },
                            {
                                "name": "npm_token",
                                "score": 0.95,
                                "regexPattern": r"\b(?-i:npm_[A-Za-z0-9]{36})\b",
                            },
                            {
                                "name": "pypi_token",
                                "score": 0.95,
                                "regexPattern": r"\b(?-i:pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,1000})\b",
                            },
                            {
                                "name": "docker_hub_pat",
                                "score": 0.95,
                                "regexPattern": r"\b(?-i:dckr_pat_[A-Za-z0-9_\-]{27})\b",
                            },
                            {
                                "name": "jwt",
                                "score": 0.9,
                                "regexPattern": r"\b(?-i:eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{0,})(?![A-Za-z0-9_\-])",
                            },
                            {
                                "name": "pem_private_key",
                                "score": 0.95,
                                "regexPattern": r"-----BEGIN (?:(?:RSA|EC|DSA|OPENSSH|ENCRYPTED) )?PRIVATE KEY-----(?:[\s\S]{0,32768}?-----END (?:(?:RSA|EC|DSA|OPENSSH|ENCRYPTED) )?PRIVATE KEY-----)?|-----BEGIN PGP PRIVATE KEY BLOCK-----(?:[\s\S]{0,32768}?-----END PGP PRIVATE KEY BLOCK-----)?",
                            },
                        ],
                    },
                    {
                        "enabled": True,
                        "name": "Secrets (Heuristic)",
                        "uniqueId": "custom_secret_heuristic",
                        "description": "Keyword- and context-dependent credential detection",
                        "filterActionType": "Audit",
                        "filterActionMessage": "",
                        "score": 0.5,
                        "context": [],
                        "regexPatterns": [
                            {
                                "name": "aws_secret_access_key",
                                "score": 0.8,
                                "regexPattern": r"""(?<=aws[\s\S]{0,20}["'])[0-9a-zA-Z/+]{40}(?=["'])""",
                            },
                            {
                                "name": "basic_auth_in_url",
                                "score": 0.8,
                                "regexPattern": r"[a-zA-Z][a-zA-Z0-9+.\-]{1,20}://(?P<user>[^/\s:@]{1,64}):(?!<[^>]*>@|\{\{[^}]*\}\}@|\$\{[^}]*\}@|(?:pass|password|pwd|passwd)@)(?!(?P=user)@)[^/\s:@]{1,64}@(?!localhost|127\.|10\.|192\.168\.|172\.(?:1[6-9]|2[0-9]|3[01])\.)[^/\s:@]{1,253}",
                            },
                            {
                                "name": "bearer_auth_header",
                                "score": 0.7,
                                "regexPattern": r"(?<=authorization\s{0,4}:\s{0,4}bearer\s{1,4})[A-Za-z0-9._~+/\-]{20,}=*",
                            },
                            {
                                "name": "basic_auth_header",
                                "score": 0.7,
                                "regexPattern": r"(?<=authorization\s{0,4}:\s{0,4}basic\s{1,4})[A-Za-z0-9+/]{12,}=*",
                            },
                            {
                                "name": "generic_api_key_header",
                                "score": 0.65,
                                "regexPattern": r"""(?<=\b(?:x-api-key|x-auth-token|x-access-token|api-key)\s{0,4}:\s{0,4}['"]?)[A-Za-z0-9_\-./+=]{16,}""",
                            },
                            {
                                "name": "generic_labeled_token",
                                "score": 0.5,
                                "regexPattern": r"""(?<=\b(?:api[_\-]?key|api[_\-]?token|access[_\-]?token)['"]?\s{0,4}[:=]\s{0,4}['"]?)[A-Za-z0-9_\-/+=]{24,}(?=[\s'"`,;]|$)""",
                            },
                        ],
                    },
                ],
            }
        ],
        "guardrailAssignments": [
            {"entityType": "Gateway", "entityId": GATEWAY_ID, "targetEntityType": "Gateway"}
        ],
        "guardrailTargets": [{"entityType": "Gateway", "targetType": "Both"}],
    }
    response = requests.post(
        f"{BASE_URL}/v1/Guardrail",
        headers=HEADERS,
        json=payload,
    )
    try:
        response.raise_for_status()
    except requests.HTTPError:
        if response.status_code == 409:
            print(
                f"A guardrail named '{payload['name']}' already exists for this "
                "tenant. Delete it in the Airia console before re-running this "
                "script — this script only creates, it never deletes or updates."
            )
        else:
            print(f"Request failed ({response.status_code}): {response.text}")
        raise
    return response.json()


# EXECUTION
result = create_guardrail()
print(result)
