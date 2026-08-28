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
                "violation_message": "Reason for violation"
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
                "start": 15,                            # REQUIRED: Start offset (inclusive)
                "end": 30                               # REQUIRED: End offset (exclusive)
            }
        ]
"""

import ipaddress
import re

# ============================================================================
# YOUR CUSTOM FILTER CODE HERE
# ============================================================================


def _is_loopback_or_private_host(host: str) -> bool:
    hostname = host.strip().lower()
    if hostname == "localhost":
        return True
    try:
        return ipaddress.ip_address(hostname).is_private
    except ValueError:
        return False


def _validate_basic_auth_in_url(match: re.Match) -> bool:
    if _is_loopback_or_private_host(match.group("host")):
        return False
    if match.group("user") == match.group("password"):
        return False
    return True

# ----------------------------------------------------------------------------
# Named token patterns.
#
# Every field here is surfaced in the violation output, so nothing in this
# table is prose that can quietly drift from the regex beside it:
#   "name"   -- stable rule id, for triaging/tuning which rule fired
#   "label"  -- short human name for the credential type
#   "shape"  -- the EXACT token shape matched (prefix, length, charset), so the
#               pattern list doubles as a reference for what's covered
#   "group"  -- which regex group to redact. 0 (default) redacts the whole
#               match; "secret" is used where the useful match includes a
#               keyword prefix (e.g. "Authorization: Bearer <token>") and we
#               only want to redact the token itself.
#
# ORDER MATTERS: _scan_text claims spans in list order and skips later
# overlapping matches, so specific patterns must precede generic ones.
# Keep the keyword-only heuristics at the bottom of this list.
# ----------------------------------------------------------------------------
TOKEN_PATTERNS = [

    # --- LLM / AI provider keys ---------------------------------------------
    dict(
        name="anthropic_api_key",
        label="Anthropic API key",
        shape="'sk-ant-api03-' or 'sk-ant-admin01-' followed by 93 base64url chars "
              "and a trailing 'AA'",
        regex=re.compile(r"sk-ant-(?:api03|admin01)-[A-Za-z0-9_\-]{93}AA"),
    ),
    dict(
        name="openai_api_key_project",
        label="OpenAI project API key",
        shape="'sk-proj-' followed by 20 or more base64url chars (real project keys "
              "have grown to 130+; the open floor still matches them)",
        regex=re.compile(r"\bsk-proj-[A-Za-z0-9_\-]{20,}\b"),
    ),
    dict(
        name="openai_api_key_legacy",
        label="OpenAI API key",
        shape="'sk-' followed by exactly 48 alphanumeric chars",
        regex=re.compile(r"\bsk-[A-Za-z0-9]{48}\b"),
    ),
    dict(
        name="google_api_key",
        label="Google API key",
        shape="'AIza' followed by 35 alphanumeric/underscore/hyphen chars",
        regex=re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    ),
    dict(
        name="google_api_key_auth",
        label="Google AI auth key",
        shape="'AQ.' followed by 20 or more base64url/dot chars (new AI Studio/Gemini "
              "format; provisional -- Google hasn't published an exact spec yet)",
        regex=re.compile(r"\bAQ\.[A-Za-z0-9_\-.]{20,}\b"),
    ),

    # --- Cloud providers ------------------------------------------------------
    dict(
        name="aws_access_key_id",
        label="AWS access key ID",
        shape="'AKIA'/'ASIA'/'A3T?' + 16 uppercase alphanumeric chars, or a non-access-key "
              "identifier prefix (ABIA/ACCA/AGPA/AIDA/AIPA/ANPA/ANVA/APKA/AROA/ASCA) "
              "+ 17 uppercase alphanumeric chars",
        regex=re.compile(
            r"\b(?:A3T[A-Z0-9]|AKIA|ASIA)[A-Z0-9]{16}\b"
            r"|\b(?:ABIA|ACCA|AGPA|AIDA|AIPA|ANPA|ANVA|APKA|AROA|ASCA)[A-Z0-9]{17}\b"
        ),
    ),
    dict(
        name="aws_secret_access_key",
        label="AWS secret access key",
        shape="quoted 40-char base64-ish string, only flagged when the word 'aws' appears "
              "within 20 chars beforehand (bare 40-char strings are too common)",
        regex=re.compile(r"(?i)aws[\s\S]{0,20}?[\"'](?P<secret>[0-9a-zA-Z/+]{40})[\"']"),
        group="secret",
    ),
    # --- Source control / package registries -----------------------------------
    dict(
        name="github_pat_classic",
        label="GitHub personal access token",
        shape="'ghp_' + 36 alphanumeric chars",
        regex=re.compile(r"\bghp_[A-Za-z0-9]{36}\b"),
    ),
    dict(
        name="github_pat_fine_grained",
        label="GitHub fine-grained personal access token",
        shape="'github_pat_' + 82 alphanumeric/underscore chars",
        regex=re.compile(r"\bgithub_pat_[A-Za-z0-9_]{82}\b"),
    ),
    dict(
        name="github_oauth_app_token",
        label="GitHub OAuth/user/refresh token",
        shape="'gho_'/'ghu_'/'ghr_' + 36-255 alphanumeric chars",
        regex=re.compile(r"\bgh[our]_[A-Za-z0-9]{36,255}\b"),
    ),
    dict(
        name="github_app_installation_token",
        label="GitHub App installation token",
        shape="'ghs_' + 36-600 alphanumeric/dot/underscore/hyphen chars (current stateless "
              "JWT format, rolled out through mid-2026)",
        regex=re.compile(r"\bghs_[A-Za-z0-9._-]{36,600}\b"),
    ),
    dict(
        name="gitlab_pat",
        label="GitLab personal access token",
        shape="legacy 'glpat-' + 20 alphanumeric/underscore/hyphen chars, or routable format "
              "'glpat-' + 27-300 chars + '.' + 2-char version + 7-char CRC32 suffix",
        regex=re.compile(
            r"\bglpat-[0-9A-Za-z_-]{20}\b"
            r"|\bglpat-[0-9A-Za-z_-]{27,300}\.[0-9a-z]{2}[0-9a-z]{7}\b"
        ),
    ),
    dict(
        name="npm_token",
        label="npm access token",
        shape="'npm_' + 36 alphanumeric chars",
        regex=re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"),
    ),
    dict(
        name="pypi_token",
        label="PyPI API token",
        shape="'pypi-AgEIcHlwaS5vcmc' fixed prefix + 50-1000 alphanumeric/underscore/hyphen chars",
        regex=re.compile(r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,1000}\b"),
    ),
    dict(
        name="docker_hub_pat",
        label="Docker Hub personal access token",
        shape="'dckr_pat_' + 27 alphanumeric/underscore/hyphen chars",
        regex=re.compile(r"\bdckr_pat_[A-Za-z0-9_\-]{27}\b"),
    ),

    # --- Generic / structural formats ---------------------------------------------
    dict(
        name="jwt",
        label="JSON Web Token",
        shape="three base64url segments of 20+ chars separated by '.', with both the header "
              "and payload segments starting with 'eyJ'",
        regex=re.compile(r"\beyJ[A-Za-z0-9_-]{20,}\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\b"),
    ),
    dict(
        name="bearer_auth_header",
        label="Bearer authorization header",
        shape="HTTP 'Authorization: Bearer <token>' header value (20+ chars)",
        regex=re.compile(r"(?i)authorization\s*:\s*bearer\s+(?P<secret>[A-Za-z0-9._~+/-]{20,}=*)"),
        group="secret",
    ),
    dict(
        name="basic_auth_in_url",
        label="Credentials embedded in URL",
        shape="scheme://user:password@host (skipped when the password is a template "
              "placeholder like <pass>, {{password}}, or ${DB_PASSWORD}; the host is "
              "loopback/private, e.g. 127.0.0.1, localhost, or an RFC1918 address; or "
              "the username equals the password, e.g. a throwaway test credential)",
        regex=re.compile(
            r"(?P<creds>[a-zA-Z][a-zA-Z0-9+.\-]{1,20}://"
            r"(?P<user>[^/\s:@]{1,64}):"
            r"(?!<[^>]*>@|\{\{[^}]*\}\}@|\$\{[^}]*\}@)"
            r"(?P<password>[^/\s:@]{1,64})@)"
            r"(?P<host>[^/\s:@]{1,253})"
        ),
        group="creds",
        validate=_validate_basic_auth_in_url,
    ),
    dict(
        name="pem_private_key",
        label="PEM private key",
        shape="'-----BEGIN PRIVATE KEY-----', optionally typed "
              "(RSA/EC/DSA/OPENSSH/ENCRYPTED), or '-----BEGIN PGP PRIVATE KEY BLOCK-----'",
        regex=re.compile(
            r"-----BEGIN (?:(?:RSA|EC|DSA|OPENSSH|ENCRYPTED) )?PRIVATE KEY-----"
            r"|-----BEGIN PGP PRIVATE KEY BLOCK-----"
        ),
    ),

    # --- HTTP auth headers (vendor-agnostic) ------------------------------------
    dict(
        name="basic_auth_header",
        label="Basic authorization header",
        shape="HTTP 'Authorization: Basic <base64>' header value (12+ chars)",
        regex=re.compile(r"(?i)authorization\s*:\s*basic\s+(?P<secret>[A-Za-z0-9+/]{12,}=*)"),
        group="secret",
    ),
    dict(
        name="generic_api_key_header",
        label="API key header",
        shape="a custom API-key style header (X-Api-Key, X-Auth-Token, X-Access-Token, "
              "Api-Key) with a 16+ char value",
        regex=re.compile(
            r"(?i)\b(?:x-api-key|x-auth-token|x-access-token|api-key)\s*:\s*"
            r"['\"]?(?P<secret>[A-Za-z0-9_\-./+=]{16,})['\"]?"
        ),
        group="secret",
    ),

    # --- Keyword-only heuristics (MUST STAY LAST) -------------------------------
    # This alternation contains "api[_-]?key" and "access[_-]?token", which are
    # substrings of the X-Api-Key / X-Access-Token header names above. Listed
    # earlier, it would claim those spans first and mislabel real header hits as
    # bare variable assignments.
    dict(
        name="generic_labeled_token",
        label="API key/token variable",
        shape="a variable literally named api_key/api_token/access_token assigned a 24+ "
              "char value (generated tokens/keys are almost always 24+ chars)",
        regex=re.compile(
            r"(?i)(?:api[_-]?key|api[_-]?token|access[_-]?token)"
            r"['\"]?\s*[:=]\s*['\"]?(?P<secret>[A-Za-z0-9_\-/+=]{24,})['\"]?(?=[\s'\"`,;]|$)"
        ),
        group="secret",
    ),
]


def _mask_secret(value: str, edge: int = 4, mask: str = "****") -> str:
    """Reveal `edge` chars at each end only if that leaves most of the value hidden."""
    if len(value) < edge * 4:  # require at least ~50% of the value to stay hidden
        return mask
    return f"{value[:edge]}{mask}{value[-edge:]}"


def _span_overlaps(start: int, end: int, claimed: list) -> bool:
    return any(start < c_end and end > c_start for c_start, c_end in claimed)


def _scan_text(text: str, message_index: int) -> list:
    violations = []
    claimed_spans = []  # spans already matched by a named pattern, to avoid double-counting

    for pattern in TOKEN_PATTERNS:
        group = pattern.get("group", 0)
        validate = pattern.get("validate")
        for match in pattern["regex"].finditer(text):
            if validate is not None and not validate(match):
                continue
            try:
                redact_start, redact_end = match.span(group)
            except (IndexError, re.error):
                continue
            if redact_start == -1 or _span_overlaps(redact_start, redact_end, claimed_spans):
                continue
            claimed_spans.append((redact_start, redact_end))
            masked_value = _mask_secret(text[redact_start:redact_end])
            violations.append({
                "content_type": "text",
                # The full message content, NOT just the matched secret -- start/end
                # below are offsets into this string, so redaction slices it directly.
                "value": text,
                "message_index": message_index,
                "is_violation": True,
                "violation_message": (
                    f"[{pattern['name']}] {pattern['label']} -- matched: {masked_value} "
                    f"(expected shape: {pattern['shape']})"
                ),
                "start": redact_start,
                "end": redact_end,
            })

    violations.sort(key=lambda v: v["start"])
    return violations


output = []
for message_index, item in enumerate(input):
    if not isinstance(item, dict) or item.get("content_type") != "text":
        continue

    value = item.get("value", "")
    if not isinstance(value, str) or not value:
        continue

    item_violations = _scan_text(value, message_index)
    if item_violations:
        output.extend(item_violations)
