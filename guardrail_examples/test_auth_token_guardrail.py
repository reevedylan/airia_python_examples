"""
Regression tests for auth_token_guardrail.py

Run standalone (no dependencies):   python3 test_auth_token_guardrail.py
Or under pytest, if you have it:    pytest test_auth_token_guardrail.py

The guardrail is a platform script, not an importable module: it reads a
module-level `input` injected by the host and assigns a module-level `output`.
So these tests exec its source with a namespace we control, which is also
exactly how the platform runs it.

Secrets below are synthetic -- fixed prefixes plus filler of the exact length
each pattern requires. Filler is built with "a" * N rather than typed out, so
the length a test asserts is the length the regex sees.
"""

import re
from pathlib import Path

GUARDRAIL = Path(__file__).with_name("auth_token_guardrail.py")
_CODE = compile(GUARDRAIL.read_text(), str(GUARDRAIL), "exec")

# Parsing the rule name back out of violation_message deliberately pins its
# format ("[name] Matched: <masked>") -- if that changes, these tests say so.
_RULE = re.compile(r"^\[([^\]]+)\] Matched: \S+$")


def scan(*messages):
    """Run the guardrail over messages. Strings are wrapped as text items;
    anything else is passed through as-is, to test malformed input."""
    items = [
        {"content_type": "text", "value": m} if isinstance(m, str) else m
        for m in messages
    ]
    namespace = {"input": items}
    exec(_CODE, namespace)
    return namespace["output"]


def rules(violations):
    """The rule names that fired, in output order."""
    names = []
    for v in violations:
        matched = _RULE.match(v["violation_message"])
        assert matched, f"unexpected violation_message format: {v['violation_message']!r}"
        names.append(matched.group(1))
    return names


def token_patterns():
    namespace = {"input": []}
    exec(_CODE, namespace)
    return namespace["TOKEN_PATTERNS"]


# ---------------------------------------------------------------------------
# One positive sample per pattern. Every pattern in TOKEN_PATTERNS must appear
# here -- test_every_pattern_is_covered fails if a new pattern is added without
# a sample, so this table can't silently fall behind the guardrail.
# ---------------------------------------------------------------------------
JWT = "eyJ" + "a" * 20 + ".eyJ" + "a" * 20 + "." + "a" * 20

POSITIVE = [
    ("anthropic_api_key", "sk-ant-api03-" + "a" * 93 + "AA"),
    ("anthropic_api_key", "sk-ant-admin01-" + "a" * 93 + "AA"),
    ("openai_api_key_project", "sk-proj-" + "a" * 130),
    ("openai_api_key_legacy", "sk-" + "a" * 48),
    ("google_api_key", "AIza" + "a" * 35),
    ("google_api_key_auth", "AQ." + "a" * 24),
    ("aws_access_key_id", "AKIA" + "A" * 16),
    ("aws_access_key_id", "ASIA" + "A" * 16),
    ("aws_access_key_id", "A3TX" + "A" * 16),
    ("aws_access_key_id", "AROA" + "A" * 17),  # 17, not 16, for these prefixes
    ("aws_access_key_id", "ASCA" + "A" * 17),
    ("aws_secret_access_key", 'aws_secret_key = "' + "a" * 40 + '"'),
    # keyword may sit up to 20 chars back, across a newline
    ("aws_secret_access_key", 'aws_secret_key =\n  "' + "a" * 40 + '"'),
    ("github_pat_classic", "ghp_" + "a" * 36),
    ("github_pat_fine_grained", "github_pat_" + "a" * 82),
    ("github_oauth_app_token", "gho_" + "a" * 36),
    ("github_oauth_app_token", "ghu_" + "a" * 36),
    ("github_oauth_app_token", "ghr_" + "a" * 36),
    ("github_app_installation_token", "ghs_" + "a" * 36),
    ("gitlab_pat", "glpat-" + "a" * 20),
    ("gitlab_pat", "glpat-" + "a" * 27 + ".ab1234567"),  # routable format
    ("npm_token", "npm_" + "a" * 36),
    ("pypi_token", "pypi-AgEIcHlwaS5vcmc" + "a" * 50),
    ("docker_hub_pat", "dckr_pat_" + "a" * 27),
    ("jwt", JWT),
    ("jwt", "the token is " + JWT + " -- rotate it"),
    ("bearer_auth_header", "Authorization: Bearer " + "a" * 32),
    ("basic_auth_header", "Authorization: Basic " + "a" * 16),
    ("basic_auth_in_url", "https://svc_user:" + "a" * 16 + "@db.example.com:5432/prod"),
    ("basic_auth_in_url", "mongodb+srv://admin:" + "a" * 16 + "@cluster0.example.net/db"),
    ("pem_private_key", "-----BEGIN PRIVATE KEY-----"),  # plain PKCS#8
    ("pem_private_key", "-----BEGIN RSA PRIVATE KEY-----"),
    ("pem_private_key", "-----BEGIN EC PRIVATE KEY-----"),
    ("pem_private_key", "-----BEGIN DSA PRIVATE KEY-----"),
    ("pem_private_key", "-----BEGIN OPENSSH PRIVATE KEY-----"),
    ("pem_private_key", "-----BEGIN ENCRYPTED PRIVATE KEY-----"),
    ("pem_private_key", "-----BEGIN PGP PRIVATE KEY BLOCK-----"),
    ("generic_api_key_header", "X-Api-Key: " + "a" * 16),
    ("generic_api_key_header", "X-Auth-Token: " + "a" * 16),
    ("generic_labeled_token", 'api_key = "' + "a" * 30 + '"'),
    ("generic_labeled_token", "API_TOKEN=" + "a" * 30),  # unquoted .env style
    ("generic_labeled_token", "access_token: " + "a" * 30),
]

# ---------------------------------------------------------------------------
# Inputs that must produce NO violations.
# ---------------------------------------------------------------------------
NEGATIVE = [
    # --- ordinary prose and config that must stay quiet ---
    "Rotate the api key after 30 days.",  # "api key" with a space is not api_key
    "See https://api.example.com/v1/docs for the endpoint list.",
    "http://localhost:8080/health",
    'SECRET_KEY = "' + "a" * 40 + '"',  # Django-style; `secret` is deliberately not a keyword
    "a" * 40,  # bare 40-char string, no `aws` nearby
    'password = "' + "a" * 12 + '"',  # generic_labeled_password was removed on purpose
    # --- right prefix, wrong length ---
    "ghp_" + "a" * 20,
    "ghp_" + "a" * 50,
    "sk-" + "a" * 47,
    "AIza" + "a" * 20,
    "npm_" + "a" * 20,
    "dckr_pat_" + "a" * 20,
    "sk-ant-api03-" + "a" * 93,  # missing the trailing AA
    # --- right shape, wrong charset ---
    "akia" + "a" * 16,  # AWS key IDs are uppercase
    "AKIA" + "a" * 16,
    # --- PEM look-alikes that are not private keys ---
    "-----BEGIN CERTIFICATE-----",
    "-----BEGIN PUBLIC KEY-----",
    "-----BEGIN OPENSSH PUBLIC KEY-----",
    # --- below the length floors that suppress placeholder noise ---
    'api_key = "short"',
    "X-Api-Key: abc",
    "Authorization: Basic abc",
    # --- documented basic_auth_in_url skips ---
    "postgres://user:" + "a" * 12 + "@127.0.0.1:5432/db",  # loopback
    "postgres://user:" + "a" * 12 + "@10.0.0.5:5432/db",  # RFC1918
    "postgres://user:" + "a" * 12 + "@localhost/db",
    "postgres://user:${DB_PASSWORD}@db.example.com/prod",  # ${...} placeholder
    "postgres://user:{{password}}@db.example.com/prod",  # {{...}} placeholder
    "postgres://user:<pass>@db.example.com/prod",  # <...> placeholder
    # Known deliberate gap, not an accident: user == password is treated as a
    # throwaway test credential, so this is also a one-character bypass of the
    # pattern. Pinned here so the tradeoff is visible rather than forgotten.
    "https://tok:tok@attacker.example.com/exfil",
]


# ---------------------------------------------------------------------------
# Coverage
# ---------------------------------------------------------------------------

def test_positive_samples_fire_with_the_right_rule():
    for expected, text in POSITIVE:
        fired = rules(scan(text))
        assert fired, f"no violation for {expected}: {text[:60]!r}"
        assert expected in fired, f"{text[:60]!r} -> {fired}, expected {expected}"


def test_negative_samples_stay_quiet():
    for text in NEGATIVE:
        found = scan(text)
        assert not found, f"false positive on {text[:60]!r} -> {rules(found)}"


def test_every_pattern_is_covered():
    covered = {name for name, _ in POSITIVE}
    declared = {p["name"] for p in token_patterns()}
    assert not declared - covered, f"patterns with no positive sample: {declared - covered}"
    assert not covered - declared, f"samples for patterns that no longer exist: {covered - declared}"


# ---------------------------------------------------------------------------
# Output contract: value is the FULL message, start/end index into it
# ---------------------------------------------------------------------------

def test_offsets_index_into_the_returned_value():
    for _, text in POSITIVE:
        for v in scan(text):
            assert v["value"] == text, "value must be the whole message, not the match"
            assert 0 <= v["start"] < v["end"] <= len(text)
            # the slice the platform will redact must be inside the original text
            assert v["value"][v["start"]:v["end"]] in text


def test_required_fields_present():
    for _, text in POSITIVE:
        for v in scan(text):
            assert v["content_type"] == "text"
            assert v["is_violation"] is True
            assert isinstance(v["message_index"], int)
            assert v["violation_message"]


def test_spans_are_sorted_and_non_overlapping():
    text = " ".join(["ghp_" + "a" * 36, "AKIA" + "A" * 16, "npm_" + "b" * 36, JWT])
    found = scan(text)
    assert len(found) == 4, rules(found)
    spans = [(v["start"], v["end"]) for v in found]
    assert spans == sorted(spans), spans
    for (_, prev_end), (next_start, _) in zip(spans, spans[1:]):
        assert prev_end <= next_start, spans


def test_secret_is_masked_in_the_violation_message():
    secret = "ghp_" + "a" * 36
    message = scan(secret)[0]["violation_message"]
    assert secret not in message, "full secret leaked into violation_message"
    assert "****" in message


# ---------------------------------------------------------------------------
# Precedence between overlapping patterns
# ---------------------------------------------------------------------------

def test_nested_match_does_not_shorten_the_redaction():
    """A ghs_ installation token embeds a JWT. If the JWT pattern wins the
    overlap, the redaction covers only the inner JWT and leaves the `ghs_<appid>.`
    prefix -- part of a live credential -- in the text."""
    ghs = ("ghs_12345.eyJhbGciOiJSUzI1NiJ9" + "A" * 8
           + ".eyJpc3MiOiIxMjM0NTYifQ" + "B" * 8 + "." + "C" * 24)
    found = scan(ghs)
    assert rules(found) == ["github_app_installation_token"], rules(found)
    assert (found[0]["start"], found[0]["end"]) == (0, len(ghs))


def test_header_hits_are_not_attributed_to_the_keyword_heuristic():
    """generic_labeled_token's keywords are substrings of these header names, so
    it must not claim their spans first."""
    for header in ("X-Api-Key", "X-Access-Token", "Api-Key", "X-Auth-Token"):
        text = f"{header}: " + "a" * 30  # 30 chars clears both length floors
        assert rules(scan(text)) == ["generic_api_key_header"], f"{header}: {rules(scan(text))}"


def test_keyword_heuristic_is_listed_last():
    """The reason is structural, not stylistic: spans are claimed in list order,
    so a keyword heuristic placed above a specific pattern silently steals its
    matches. See test_header_hits_are_not_attributed_to_the_keyword_heuristic."""
    assert token_patterns()[-1]["name"] == "generic_labeled_token"


def test_overlapping_patterns_yield_one_violation():
    for text in ("Authorization: Bearer " + JWT, "Authorization: Bearer ghp_" + "a" * 36):
        found = scan(text)
        assert len(found) == 1, f"{text[:40]!r} -> {rules(found)}"


def test_specific_pattern_wins_over_generic():
    assert rules(scan("Authorization: Bearer " + JWT)) == ["jwt"]
    assert rules(scan("Authorization: Bearer ghp_" + "a" * 36)) == ["github_pat_classic"]
    assert rules(scan('api_key = "ghp_' + "a" * 36 + '"')) == ["github_pat_classic"]


# ---------------------------------------------------------------------------
# Pattern table hygiene
# ---------------------------------------------------------------------------

KNOWN_FIELDS = {"name", "regex", "group", "validate"}


def test_pattern_metadata_is_complete_and_used():
    seen = set()
    for p in token_patterns():
        for field in ("name", "regex"):
            assert p.get(field), f"{p.get('name')} is missing {field}"
        # No free-text field describing the regex. Prose that lives in the table
        # but is never read drifts from the pattern beside it silently -- that is
        # how three shape descriptions ended up wrong. Shape notes belong in a
        # comment above the regex, where they read as documentation.
        assert not set(p) - KNOWN_FIELDS, (
            f"{p['name']} has unread field(s) {sorted(set(p) - KNOWN_FIELDS)}"
        )
        assert p["name"] not in seen, f"duplicate pattern name {p['name']}"
        seen.add(p["name"])


def test_rule_name_is_the_only_identifier_in_the_output():
    """violation_message carries the name and nothing else identifying, so names
    have to be distinct enough to act on -- see test_pattern_metadata for that."""
    name = "github_pat_classic"
    message = scan("ghp_" + "a" * 36)[0]["violation_message"]
    assert message.startswith(f"[{name}] "), message


# ---------------------------------------------------------------------------
# Message indexing and malformed input
# ---------------------------------------------------------------------------

def test_message_index_points_at_the_offending_message():
    found = scan("nothing here", "also nothing", "ghp_" + "a" * 36)
    assert len(found) == 1
    assert found[0]["message_index"] == 2


def test_offsets_are_relative_to_their_own_message():
    secret = "ghp_" + "a" * 36
    found = scan("padding padding padding", "x " + secret)
    assert len(found) == 1
    v = found[0]
    assert v["message_index"] == 1
    assert v["value"][v["start"]:v["end"]] == secret


def test_malformed_items_are_skipped():
    secret = "ghp_" + "a" * 36
    found = scan(
        None,
        "not a dict",
        {"content_type": "text"},  # no value
        {"content_type": "text", "value": None},
        {"content_type": "text", "value": ""},
        {"content_type": "image", "value": secret},  # images are not scanned
        {"content_type": "text", "value": secret},
    )
    assert len(found) == 1, rules(found)
    assert found[0]["message_index"] == 6


def test_no_violations_means_empty_output():
    assert scan("perfectly ordinary text") == []
    assert scan() == []


# ---------------------------------------------------------------------------

def main():
    tests = sorted(
        ((name, fn) for name, fn in globals().items()
         if name.startswith("test_") and callable(fn)),
        key=lambda pair: pair[1].__code__.co_firstlineno,
    )
    failures = []
    for name, fn in tests:
        try:
            fn()
        except AssertionError as exc:
            failures.append((name, exc))
            print(f"FAIL {name}\n       {exc}")
        else:
            print(f"ok   {name}")
    print(f"\n{len(tests) - len(failures)}/{len(tests)} passed")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
