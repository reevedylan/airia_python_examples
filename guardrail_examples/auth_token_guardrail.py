"""
Custom Python Filter for Content Guardrails

IMPORTANT: Your script can return multiple violations per message. Each sensitive item
detected should be a separate violation with its own start/end offsets for redaction.

Input Structure:
    input: List[Dict] - A list of messages to process
        [
            {
                "content_type": "text",     # Type: "text" or "image"
                "value": "Content string"   # The actual content to analyze
            }
        ]

Output Structure (AUDIT/BLOCK mode):
    output: List[Dict] - One or more violations detected
        [
            {
                "content_type": "text",
                "value": "Content string",
                "message_index": 0,                     # Which input message (0-based)
                "is_violation": True,                   # Must be True for violations
                "violation_message": "Reason for violation",
                "confidence_score": 0.95                # Optional: 0.0-1.0
            }
        ]

Output Structure (REDACT mode - REQUIRED FIELDS):
    output: List[Dict] - One or more violations with redaction offsets
        [
            {
                "content_type": "text",
                "value": "Content string",
                "message_index": 0,                     # Which input message (0-based)
                "is_violation": True,                   # Must be True for violations
                "violation_message": "Reason for violation",
                "confidence_score": 0.95,               # Optional: 0.0-1.0
                "start": 15,                            # REQUIRED: Start offset (inclusive)
                "end": 30                               # REQUIRED: End offset (exclusive)
            }
        ]
"""

import re

# ============================================================================
# YOUR CUSTOM FILTER CODE HERE
# ============================================================================

# ----------------------------------------------------------------------------
# Named token patterns.
#
# Each entry documents the EXACT token shape it matches (prefix, length,
# charset) so the pattern list doubles as a reference for what's covered.
# "group" selects which regex group to redact -- 0 (default) redacts the
# whole match; "secret" is used where the useful match includes a keyword
# prefix (e.g. "Authorization: Bearer <token>") and we only want to redact
# the token itself.
# ----------------------------------------------------------------------------
TOKEN_PATTERNS = [

    # --- LLM / AI provider keys ---------------------------------------------
    dict(
        name="anthropic_api_key",
        message="Anthropic API key: 'sk-ant-api03-' or 'sk-ant-admin01-' followed by "
                "93 base64url chars and a trailing 'AA'",
        regex=re.compile(r"sk-ant-(?:api03|admin01)-[A-Za-z0-9_\-]{93}AA"),
        confidence=0.99,
    ),
    dict(
        name="openai_api_key_project",
        message="OpenAI project-scoped API key: 'sk-proj-' followed by 20+ base64url chars",
        regex=re.compile(r"\bsk-proj-[A-Za-z0-9_\-]{20,}\b"),
        confidence=0.9,
    ),
    dict(
        name="openai_api_key_legacy",
        message="OpenAI legacy API key: 'sk-' followed by exactly 48 alphanumeric chars",
        regex=re.compile(r"\bsk-[A-Za-z0-9]{48}\b"),
        confidence=0.85,
    ),
    dict(
        name="google_api_key",
        message="Google API key: 'AIza' followed by 35 alphanumeric/underscore/hyphen chars",
        regex=re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
        confidence=0.95,
    ),

    # --- Cloud providers ------------------------------------------------------
    dict(
        name="aws_access_key_id",
        message="AWS Access Key ID: known prefix (AKIA/ASIA/AROA/AIDA/etc.) + 16 uppercase alphanumeric chars",
        regex=re.compile(r"\b(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b"),
        confidence=0.95,
    ),
    dict(
        name="aws_secret_access_key",
        message="AWS Secret Access Key: 40-char base64-ish string, only flagged when the "
                "word 'aws' appears within 20 chars beforehand (bare 40-char strings are too common)",
        regex=re.compile(r"(?i)aws.{0,20}?[\"'](?P<secret>[0-9a-zA-Z/+]{40})[\"']"),
        confidence=0.6,
        group="secret",
    ),
    dict(
        name="gcp_service_account_key",
        message="GCP service account JSON key: '\"type\": \"service_account\"' near a '\"private_key\"' field",
        regex=re.compile(
            r"\"type\"\s*:\s*\"service_account\""
            r"[\s\S]{0,500}?"
            r"\"private_key\"\s*:\s*\"(?P<secret>[^\"]{20,})\""
        ),
        confidence=0.9,
        group="secret",
    ),
    # --- Source control / package registries -----------------------------------
    dict(
        name="github_pat_classic",
        message="GitHub classic personal access token: 'ghp_' + 36 alphanumeric chars",
        regex=re.compile(r"\bghp_[A-Za-z0-9]{36}\b"),
        confidence=0.95,
    ),
    dict(
        name="github_pat_fine_grained",
        message="GitHub fine-grained personal access token: 'github_pat_' + 82 alphanumeric/underscore chars",
        regex=re.compile(r"\bgithub_pat_[A-Za-z0-9_]{82}\b"),
        confidence=0.95,
    ),
    dict(
        name="github_oauth_app_token",
        message="GitHub OAuth/App/User/Refresh token: 'gho_'/'ghu_'/'ghs_'/'ghr_' + 36-255 alphanumeric chars",
        regex=re.compile(r"\bgh[ousr]_[A-Za-z0-9]{36,255}\b"),
        confidence=0.9,
    ),
    dict(
        name="gitlab_pat",
        message="GitLab personal access token: 'glpat-' + 20 alphanumeric/underscore/hyphen chars",
        regex=re.compile(r"\bglpat-[A-Za-z0-9_\-]{20}\b"),
        confidence=0.95,
    ),
    dict(
        name="npm_token",
        message="npm access token: 'npm_' + 36 alphanumeric chars",
        regex=re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"),
        confidence=0.95,
    ),
    dict(
        name="pypi_token",
        message="PyPI API token: 'pypi-AgEIcHlwaS5vcmc' fixed prefix + 50+ alphanumeric/underscore/hyphen chars",
        regex=re.compile(r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,1000}\b"),
        confidence=0.95,
    ),
    dict(
        name="docker_hub_pat",
        message="Docker Hub personal access token: 'dckr_pat_' + 27 alphanumeric/underscore/hyphen chars",
        regex=re.compile(r"\bdckr_pat_[A-Za-z0-9_\-]{27}\b"),
        confidence=0.95,
    ),

    # --- Generic / structural formats ---------------------------------------------
    dict(
        name="jwt",
        message="JSON Web Token: three base64url segments separated by '.', header starting with 'eyJ'",
        regex=re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{10,}\b"),
        confidence=0.85,
    ),
    dict(
        name="bearer_auth_header",
        message="HTTP 'Authorization: Bearer <token>' header value (20+ chars)",
        regex=re.compile(r"(?i)authorization\s*:\s*bearer\s+(?P<secret>[A-Za-z0-9._~+/-]{20,}=*)"),
        confidence=0.8,
        group="secret",
    ),
    dict(
        name="basic_auth_in_url",
        message="Credentials embedded directly in a URL: scheme://user:password@host",
        regex=re.compile(r"[a-zA-Z][a-zA-Z0-9+.\-]{2,9}://[^/\s:@]{1,64}:[^/\s:@]{1,64}@"),
        confidence=0.85,
    ),
    dict(
        name="pem_private_key",
        message="PEM-encoded private key block: '-----BEGIN ... PRIVATE KEY-----'",
        regex=re.compile(r"-----BEGIN\s?(?:RSA|EC|DSA|OPENSSH|PGP)?\s?PRIVATE KEY-----"),
        confidence=0.99,
    ),
    dict(
        name="generic_labeled_token",
        message="A variable literally named api_key/secret/token assigned a 24+ char value "
                "(generated tokens/keys are almost always 24+ chars)",
        regex=re.compile(
            r"(?i)(?:api[_-]?key|secret|token)"
            r"['\"]?\s*[:=]\s*['\"](?P<secret>[A-Za-z0-9_\-/+=]{24,})['\"]"
        ),
        confidence=0.5,
        group="secret",
    ),
    dict(
        name="generic_labeled_password",
        message="A variable literally named passwd/password assigned an 8+ char value "
                "(real passwords are often short, so kept as a separate, lower bar)",
        regex=re.compile(
            r"(?i)(?:passwd|password)"
            r"['\"]?\s*[:=]\s*['\"](?P<secret>[A-Za-z0-9_\-/+=]{8,})['\"]"
        ),
        confidence=0.5,
        group="secret",
    ),

    # --- HTTP auth headers (vendor-agnostic) ------------------------------------
    dict(
        name="basic_auth_header",
        message="HTTP 'Authorization: Basic <base64>' header value (12+ chars)",
        regex=re.compile(r"(?i)authorization\s*:\s*basic\s+(?P<secret>[A-Za-z0-9+/]{12,}=*)"),
        confidence=0.8,
        group="secret",
    ),
    dict(
        name="generic_api_key_header",
        message="A custom API-key style header (X-Api-Key, X-Auth-Token, X-Access-Token, Api-Key) "
                "with a 16+ char value",
        regex=re.compile(
            r"(?i)\b(?:x-api-key|x-auth-token|x-access-token|api-key)\s*:\s*"
            r"['\"]?(?P<secret>[A-Za-z0-9_\-./+=]{16,})['\"]?"
        ),
        confidence=0.6,
        group="secret",
    ),

    # --- Kubernetes --------------------------------------------------------------
    dict(
        name="kubeconfig_client_key_data",
        message="kubeconfig 'client-key-data' field: base64-encoded client private key",
        regex=re.compile(r"client-key-data\s*:\s*(?P<secret>[A-Za-z0-9+/]{40,}=*)"),
        confidence=0.85,
        group="secret",
    ),
    dict(
        name="kubeconfig_bearer_token",
        message="A 'token:' field near kubeconfig/kubectl/serviceaccount context, "
                "typically a cluster bearer token",
        regex=re.compile(
            r"(?i)(?:kubeconfig|kubectl|serviceaccount|k8s)[\s\S]{0,60}?"
            r"token['\"]?\s*:\s*['\"]?(?P<secret>[A-Za-z0-9._\-]{20,})['\"]?"
        ),
        confidence=0.65,
        group="secret",
    ),
]


def _span_overlaps(start: int, end: int, claimed: list) -> bool:
    return any(start < c_end and end > c_start for c_start, c_end in claimed)


def _scan_text(text: str, message_index: int) -> list:
    violations = []
    claimed_spans = []  # spans already matched by a named pattern, to avoid double-counting

    for pattern in TOKEN_PATTERNS:
        group = pattern.get("group", 0)
        for match in pattern["regex"].finditer(text):
            full_start, full_end = match.span(0)
            redact_start, redact_end = match.span(group)
            if redact_start == -1 or _span_overlaps(full_start, full_end, claimed_spans):
                continue
            claimed_spans.append((full_start, full_end))
            violations.append({
                "content_type": "text",
                "value": text[redact_start:redact_end],
                "message_index": message_index,
                "is_violation": True,
                "violation_message": f"Detected {pattern['message']}",
                "confidence_score": pattern["confidence"],
                "start": redact_start,
                "end": redact_end,
            })

    violations.sort(key=lambda v: v["start"])
    return violations


output = []
for message_index, item in enumerate(input):
    if item.get("content_type") != "text":
        continue

    item_violations = _scan_text(item.get("value", ""), message_index)
    if item_violations:
        output.extend(item_violations)
