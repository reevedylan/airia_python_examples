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

Two properties of the output that the structure above does not state:

  * start/end are Python CODE-POINT offsets, and `end` is widened where a
    UTF-16 host would read them differently -- see _utf16_safe_end.
  * violations are sorted by ascending `start`, and every offset is relative to
    the ORIGINAL text. A host that applies them front-to-back with a
    replacement of a different length will corrupt every offset after the
    first; it must either work backwards or splice in one pass.
"""

import bisect
import ipaddress
import re

# ============================================================================
# Output size caps
#
# Each violation must repeat the FULL message in "value" (start/end index into
# it), so n violations on an m-char message cost n*m on the wire. Left
# unbounded that amplifies its input by two orders of magnitude on exactly the
# input people paste -- a .env file, `kubectl get secret -o yaml`, terraform
# output. Measured before these caps: 500 keys in 30 KB of text produced 15 MB
# of JSON; 8000 in 320 KB produced 2.5 GB.
#
# A message over either cap collapses to ONE violation spanning the first match
# to the last. That over-redacts the filler between matches, which is the
# deliberate trade: on secret-dense input the filler is cheap to lose and an
# un-redacted key is not.
# ============================================================================
MAX_VIOLATIONS_PER_MESSAGE = 50
MAX_DUPLICATED_CHARS_PER_MESSAGE = 1_000_000

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
# Named token patterns. Fields:
#   "name"     -- stable rule id. This is what appears in violation_message, so
#                 it is the string you grep for when tuning a noisy rule.
#   "regex"    -- the pattern. Above each one is a comment describing the shape
#                 it matches (prefix, length, charset). Those comments are
#                 documentation only, NOT behaviour -- when you change a regex,
#                 the comment above it will not complain if you forget it.
#   "group"    -- which regex group to redact. 0 (default) redacts the whole
#                 match; "secret" is used where the useful match includes a
#                 keyword prefix (e.g. "Authorization: Bearer <token>") and we
#                 only want to redact the token itself.
#   "validate" -- optional callable(match) -> bool, to suppress known-benign
#                 matches that the regex alone cannot exclude.
#
# ORDER MATTERS: _scan_text claims spans in list order and skips later
# overlapping matches, so specific patterns must precede generic ones.
# Keep the keyword-only heuristics at the bottom of this list.
# ----------------------------------------------------------------------------
TOKEN_PATTERNS = [

    # --- LLM / AI provider keys ---------------------------------------------
    dict(
        name="anthropic_api_key",
        # 'sk-ant-api03-' or 'sk-ant-admin01-' followed by 93 base64url chars and a
        # trailing 'AA'
        regex=re.compile(r"sk-ant-(?:api03|admin01)-[A-Za-z0-9_\-]{93}AA"),
    ),
    dict(
        name="openai_api_key_project",
        # 'sk-proj-' followed by 20 or more base64url chars (real project keys have
        # grown to 130+; the open floor still matches them)
        regex=re.compile(r"\bsk-proj-[A-Za-z0-9_\-]{20,}\b"),
    ),
    dict(
        name="openai_api_key_legacy",
        # 'sk-' followed by exactly 48 alphanumeric chars
        regex=re.compile(r"\bsk-[A-Za-z0-9]{48}\b"),
    ),
    dict(
        name="google_api_key",
        # 'AIza' followed by 35 alphanumeric/underscore/hyphen chars
        regex=re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    ),
    dict(
        name="google_api_key_auth",
        # 'AQ.' followed by 20 or more base64url/dot chars (new AI Studio/Gemini
        # format; provisional -- Google hasn't published an exact spec yet)
        regex=re.compile(r"\bAQ\.[A-Za-z0-9_\-.]{20,}\b"),
    ),

    # --- Cloud providers ------------------------------------------------------
    dict(
        name="aws_access_key_id",
        # 'AKIA'/'ASIA'/'A3T?' + 16 uppercase alphanumeric chars, or a
        # non-access-key identifier prefix
        # (ABIA/ACCA/AGPA/AIDA/AIPA/ANPA/ANVA/APKA/AROA/ASCA) + 17 uppercase
        # alphanumeric chars
        regex=re.compile(
            r"\b(?:A3T[A-Z0-9]|AKIA|ASIA)[A-Z0-9]{16}\b"
            r"|\b(?:ABIA|ACCA|AGPA|AIDA|AIPA|ANPA|ANVA|APKA|AROA|ASCA)[A-Z0-9]{17}\b"
        ),
    ),
    dict(
        name="aws_secret_access_key",
        # quoted 40-char base64-ish string, only flagged when the word 'aws' appears
        # within 20 chars beforehand (bare 40-char strings are too common)
        regex=re.compile(r"(?i)aws[\s\S]{0,20}?[\"'](?P<secret>[0-9a-zA-Z/+]{40})[\"']"),
        group="secret",
    ),
    # --- Source control / package registries -----------------------------------
    dict(
        name="github_pat_classic",
        # 'ghp_' + 36 alphanumeric chars
        regex=re.compile(r"\bghp_[A-Za-z0-9]{36}\b"),
    ),
    dict(
        name="github_pat_fine_grained",
        # 'github_pat_' + 82 alphanumeric/underscore chars
        regex=re.compile(r"\bgithub_pat_[A-Za-z0-9_]{82}\b"),
    ),
    dict(
        name="github_oauth_app_token",
        # 'gho_'/'ghu_'/'ghr_' + 36-255 alphanumeric chars
        regex=re.compile(r"\bgh[our]_[A-Za-z0-9]{36,255}\b"),
    ),
    dict(
        name="github_app_installation_token",
        # 'ghs_' + 36-600 alphanumeric/dot/underscore/hyphen chars (current
        # stateless JWT format, rolled out through mid-2026)
        regex=re.compile(r"\bghs_[A-Za-z0-9._-]{36,600}\b"),
    ),
    dict(
        name="gitlab_pat",
        # legacy 'glpat-' + 20 alphanumeric/underscore/hyphen chars, or routable
        # format 'glpat-' + 27-300 chars + '.' + 2-char version + 7-char CRC32
        # suffix
        regex=re.compile(
            r"\bglpat-[0-9A-Za-z_-]{20}\b"
            r"|\bglpat-[0-9A-Za-z_-]{27,300}\.[0-9a-z]{2}[0-9a-z]{7}\b"
        ),
    ),
    dict(
        name="npm_token",
        # 'npm_' + 36 alphanumeric chars
        regex=re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"),
    ),
    dict(
        name="pypi_token",
        # 'pypi-AgEIcHlwaS5vcmc' fixed prefix + 50-1000
        # alphanumeric/underscore/hyphen chars
        regex=re.compile(r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,1000}\b"),
    ),
    dict(
        name="docker_hub_pat",
        # 'dckr_pat_' + 27 alphanumeric/underscore/hyphen chars
        regex=re.compile(r"\bdckr_pat_[A-Za-z0-9_\-]{27}\b"),
    ),

    # --- Generic / structural formats ---------------------------------------------
    dict(
        name="jwt",
        # three base64url segments of 20+ chars separated by '.', with both the
        # header and payload segments starting with 'eyJ'
        regex=re.compile(r"\beyJ[A-Za-z0-9_-]{20,}\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\b"),
    ),
    dict(
        name="bearer_auth_header",
        # HTTP 'Authorization: Bearer <token>' header value (20+ chars)
        regex=re.compile(r"(?i)authorization\s*:\s*bearer\s+(?P<secret>[A-Za-z0-9._~+/-]{20,}=*)"),
        group="secret",
    ),
    dict(
        name="basic_auth_in_url",
        # scheme://user:password@host (skipped when the password is a template
        # placeholder like <pass>, {{password}}, or ${DB_PASSWORD}; the host is
        # loopback/private, e.g. 127.0.0.1, localhost, or an RFC1918 address; or the
        # username equals the password, e.g. a throwaway test credential)
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
        # '-----BEGIN PRIVATE KEY-----', optionally typed
        # (RSA/EC/DSA/OPENSSH/ENCRYPTED), or '-----BEGIN PGP PRIVATE KEY BLOCK-----',
        # THROUGH the matching END line. Matching the header alone leaves the
        # base64 key body -- the actual secret -- in the text after redaction.
        # The trailing block is optional so a truncated paste with no END line
        # still flags, and its span is bounded so a BEGIN with no END costs a
        # bounded scan rather than one to end-of-message.
        regex=re.compile(
            r"-----BEGIN (?:(?:RSA|EC|DSA|OPENSSH|ENCRYPTED) )?PRIVATE KEY-----"
            r"(?:[\s\S]{0,32768}?-----END (?:(?:RSA|EC|DSA|OPENSSH|ENCRYPTED) )?PRIVATE KEY-----)?"
            r"|-----BEGIN PGP PRIVATE KEY BLOCK-----"
            r"(?:[\s\S]{0,32768}?-----END PGP PRIVATE KEY BLOCK-----)?"
        ),
    ),

    # --- HTTP auth headers (vendor-agnostic) ------------------------------------
    dict(
        name="basic_auth_header",
        # HTTP 'Authorization: Basic <base64>' header value (12+ chars)
        regex=re.compile(r"(?i)authorization\s*:\s*basic\s+(?P<secret>[A-Za-z0-9+/]{12,}=*)"),
        group="secret",
    ),
    dict(
        name="generic_api_key_header",
        # a custom API-key style header (X-Api-Key, X-Auth-Token, X-Access-Token,
        # Api-Key) with a 16+ char value
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
        # a variable literally named api_key/api_token/access_token assigned a 24+
        # char value (generated tokens/keys are almost always 24+ chars)
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


def _claim_span(start: int, end: int, claimed: list) -> bool:
    """Claim [start, end) unless it overlaps a span already claimed.

    `claimed` is kept sorted and, by construction, non-overlapping -- so only
    the two neighbours either side of the insertion point can overlap. Scanning
    every prior claim instead makes this O(matches^2), which is felt on the
    secret-dense input the caps above exist for.
    """
    index = bisect.bisect_left(claimed, (start, end))
    if index > 0 and claimed[index - 1][1] > start:
        return False
    if index < len(claimed) and end > claimed[index][0]:
        return False
    claimed.insert(index, (start, end))
    return True


# Astral characters: one code point to Python, a surrogate PAIR (two units) to
# UTF-16. Everything else costs one unit in both.
_ASTRAL = re.compile(r"[\U00010000-\U0010FFFF]")


def _utf16_safe_end(end: int, astral_starts: list) -> int:
    """Widen `end` so the span still covers the secret under UTF-16 indexing.

    Our offsets count code points. A host whose strings are UTF-16 (.NET, Java,
    JavaScript) reads the same integers as UTF-16 unit offsets, which run ahead
    of code points by one per astral character seen so far -- so its window
    lands short and leaves the tail of the secret in the text.

    Pairing a code-point `start` with a UTF-16 `end` covers the secret under
    both readings: a code-point host over-redacts a few trailing characters, a
    UTF-16 host a few leading ones. With no astral characters in the text --
    the overwhelmingly common case -- this returns `end` unchanged.

    A UTF-8 BYTE-offset host is not covered: matching it would mean widening by
    the encoded length of everything before the secret, which on CJK text means
    redacting most of the message on every hit.

    Callers clamp the result to len(text) (and to the next match), because an
    offset past the end of the value risks the host rejecting the violation
    outright -- failing open. So a secret that ENDS the message, with astral
    characters before it, stays short by one unit per astral character on a
    UTF-16 host. See test_utf16_widening_is_clamped_at_end_of_message.

    `astral_starts` is the sorted offsets of every astral character in the
    text, computed once per message: counting them per violation instead
    re-scans the whole message on every hit.
    """
    return end + bisect.bisect_left(astral_starts, end)


def _exceeds_output_budget(match_count: int, text_length: int) -> bool:
    return (match_count > MAX_VIOLATIONS_PER_MESSAGE
            or match_count * max(text_length, 1) > MAX_DUPLICATED_CHARS_PER_MESSAGE)


def _collapsed_violation(text: str, message_index: int, matches: list,
                         astral_starts: list) -> dict:
    """One violation covering every match, for messages over the output caps."""
    names = sorted({name for _, _, name in matches})
    shown = ", ".join(names[:5]) + (", ..." if len(names) > 5 else "")
    return {
        "content_type": "text",
        "value": text,
        "message_index": message_index,
        "is_violation": True,
        "violation_message": (
            f"[multiple_secrets] {len(matches)} secrets detected ({shown}); "
            "collapsed to one span to bound the response size"
        ),
        "start": matches[0][0],
        "end": min(_utf16_safe_end(max(end for _, end, _ in matches), astral_starts),
                   len(text)),
    }


def _scan_text(text: str, message_index: int) -> list:
    matches = []  # (start, end, rule name) for spans claimed by a named pattern
    claimed = []  # the same spans, sorted, to avoid double-counting

    for pattern in TOKEN_PATTERNS:
        group = pattern.get("group", 0)
        validate = pattern.get("validate")
        for match in pattern["regex"].finditer(text):
            try:
                if validate is not None and not validate(match):
                    continue
                redact_start, redact_end = match.span(group)
            except (IndexError, ValueError, re.error):
                continue
            if redact_start == -1 or not _claim_span(redact_start, redact_end, claimed):
                continue
            matches.append((redact_start, redact_end, pattern["name"]))

    if not matches:
        return []

    matches.sort()
    # Astral characters are absent from all but a sliver of real traffic, so
    # skip the scan entirely rather than pay for it on every message.
    astral_starts = ([m.start() for m in _ASTRAL.finditer(text)]
                     if _ASTRAL.search(text) else [])

    if _exceeds_output_budget(len(matches), len(text)):
        return [_collapsed_violation(text, message_index, matches, astral_starts)]

    violations = []
    for index, (start, end, name) in enumerate(matches):
        # Widening for UTF-16 hosts must stop short of the next match: spans
        # that overlap each other are ambiguous for whoever applies them.
        limit = matches[index + 1][0] if index + 1 < len(matches) else len(text)
        violations.append({
            "content_type": "text",
            # The full message content, NOT just the matched secret -- start/end
            # below are offsets into this string, so redaction slices it directly.
            "value": text,
            "message_index": message_index,
            "is_violation": True,
            "violation_message": f"[{name}] Matched: {_mask_secret(text[start:end])}",
            "start": start,
            "end": min(_utf16_safe_end(end, astral_starts), limit),
        })
    return violations


# Keys an envelope might carry the message list under, tried in order.
_ENVELOPE_KEYS = ("messages", "input", "items", "contents", "data")


def _as_message_list(raw) -> list:
    """Coerce the host-injected `input` into a list of message dicts.

    Iterating `input` directly fails the wrong way in two cases seen in
    practice:

      * `input` never injected. The name still resolves -- to the BUILTIN
        `input` function -- so the loop raises "'builtin_function_or_method'
        object is not iterable", which reads like a platform fault rather than
        a contract mismatch.
      * `input` handed over as an envelope, e.g. {"messages": [...]}. Iterating
        a dict yields its KEYS, so every message is skipped and the guardrail
        reports a clean bill of health for content it never read.

    The second is the dangerous one, and the reason the fallback here raises
    rather than returning []: a content filter that silently passes everything
    is worse than one that errors.
    """
    if isinstance(raw, (list, tuple)):
        return list(raw)
    if isinstance(raw, dict):
        if "value" in raw:  # a single message, not a collection of them
            return [raw]
        for key in _ENVELOPE_KEYS:
            nested = raw.get(key)
            if isinstance(nested, (list, tuple)):
                return list(nested)
    elif not isinstance(raw, (str, bytes, bytearray)) and hasattr(raw, "__iter__"):
        return list(raw)  # generators and other one-shot iterables
    raise TypeError(
        "content guardrail: expected `input` to be a list of "
        "{'content_type': ..., 'value': ...} messages, got "
        f"{type(raw).__name__}. If the host wraps them in an envelope, add its "
        "key to _ENVELOPE_KEYS."
    )


output = []
for message_index, item in enumerate(_as_message_list(input)):
    if not isinstance(item, dict):
        continue

    # Skip other modalities, but only where the host says so explicitly and in
    # a form we recognise. Requiring content_type == "text" exactly meant a
    # missing, differently-cased, or camelCased key ("TEXT", "contentType")
    # skipped the message silently -- a naming mismatch turning into a pass.
    content_type = item.get("content_type", item.get("contentType"))
    if isinstance(content_type, str) and content_type.strip().lower() != "text":
        continue

    value = item.get("value", "")
    if not isinstance(value, str) or not value:
        continue

    output.extend(_scan_text(value, message_index))
