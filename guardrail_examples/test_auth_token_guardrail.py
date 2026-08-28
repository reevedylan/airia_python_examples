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


def scan_raw(raw):
    """Run the guardrail with `input` bound to exactly `raw`, to test envelopes."""
    namespace = {"input": raw}
    exec(_CODE, namespace)
    return namespace["output"]


def constant(name):
    namespace = {"input": []}
    exec(_CODE, namespace)
    return namespace[name]


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
# Input envelope. Iterating `input` directly failed the wrong way: a dict
# envelope yielded its KEYS, so nothing was scanned and nothing was reported.
# ---------------------------------------------------------------------------

SECRET = "ghp_" + "a" * 36
MESSAGE = {"content_type": "text", "value": SECRET}


def test_envelope_shapes_are_unwrapped():
    for label, raw in [
        ("list", [MESSAGE]),
        ("tuple", (MESSAGE,)),
        ("generator", iter([MESSAGE])),
        ("{'messages': [...]}", {"messages": [MESSAGE]}),
        ("{'items': [...]}", {"items": [MESSAGE]}),
        ("{'data': [...]}", {"data": [MESSAGE]}),
        ("a single message dict", MESSAGE),
    ]:
        found = scan_raw(raw)
        assert len(found) == 1, f"{label} -> {rules(found)}"


def test_unrecognised_input_raises_rather_than_passing_silently():
    """A content filter that reports nothing because it read nothing is worse
    than one that errors, so the fallback raises and names the shape it got."""
    for raw in (None, "a bare string", 42, {"unexpected": "envelope"}, input):
        try:
            scan_raw(raw)
        except TypeError as exc:
            assert "expected `input`" in str(exc), exc
            assert type(raw).__name__ in str(exc), exc
        else:
            assert False, f"{type(raw).__name__} was accepted and scanned nothing"


def test_missing_input_names_the_real_problem():
    """With `input` never injected the name still resolves -- to the builtin --
    so the old loop raised a TypeError that read like a platform fault."""
    try:
        exec(_CODE, {})
    except TypeError as exc:
        assert "expected `input`" in str(exc), exc
    else:
        assert False, "scanning with no `input` bound should raise"


# ---------------------------------------------------------------------------
# content_type tolerance. Requiring == "text" exactly turned a naming mismatch
# into a silent pass.
# ---------------------------------------------------------------------------

def test_content_type_variants_are_still_scanned():
    for item in (
        {"content_type": "text", "value": SECRET},
        {"content_type": "TEXT", "value": SECRET},
        {"content_type": " Text ", "value": SECRET},
        {"contentType": "text", "value": SECRET},
        {"content_type": None, "value": SECRET},
        {"value": SECRET},  # no content_type at all
    ):
        assert len(scan(item)) == 1, item


def test_non_text_modalities_are_still_skipped():
    for item in (
        {"content_type": "image", "value": SECRET},
        {"content_type": "IMAGE", "value": SECRET},
        {"contentType": "audio", "value": SECRET},
    ):
        assert scan(item) == [], item


# ---------------------------------------------------------------------------
# PEM keys: the header alone is not the secret.
# ---------------------------------------------------------------------------

PEM_BODY = "\n".join(["MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7"] * 20)


def test_pem_redaction_covers_the_key_body():
    pem = "-----BEGIN RSA PRIVATE KEY-----\n" + PEM_BODY + "\n-----END RSA PRIVATE KEY-----"
    text = "here you go:\n" + pem + "\nrotate it"
    found = scan(text)
    assert rules(found) == ["pem_private_key"], rules(found)
    v = found[0]
    assert v["value"][v["start"]:v["end"]] == pem
    redacted = text[:v["start"]] + "[REDACTED]" + text[v["end"]:]
    assert "MIIEvQ" not in redacted, "key body survived redaction"


def test_pgp_block_redaction_covers_the_body():
    block = ("-----BEGIN PGP PRIVATE KEY BLOCK-----\n" + PEM_BODY
             + "\n-----END PGP PRIVATE KEY BLOCK-----")
    v = scan(block)[0]
    assert block[v["start"]:v["end"]] == block


def test_truncated_pem_still_flags_the_header():
    """No END line (a clipped paste) must still fire, or bounding the body
    would have traded a partial redaction for no detection at all."""
    for text in ("-----BEGIN PRIVATE KEY-----",
                 "-----BEGIN PRIVATE KEY-----\n" + PEM_BODY):
        assert rules(scan(text)) == ["pem_private_key"], text[:40]


def test_pem_lookalikes_still_stay_quiet():
    body = "-----BEGIN CERTIFICATE-----\n" + PEM_BODY + "\n-----END CERTIFICATE-----"
    assert scan(body) == [], rules(scan(body))


# ---------------------------------------------------------------------------
# Output size. Each violation repeats the whole message in "value", so an
# uncapped scan of a secret-dense paste amplifies its input ~250x.
# ---------------------------------------------------------------------------

def dense(n):
    return "\n".join("SERVICE_%d_API_KEY=%s" % (i, "ghp_" + "%036d" % i) for i in range(n))


def test_dense_input_collapses_to_one_covering_violation():
    text = dense(500)
    found = scan(text)
    assert len(found) == 1, f"{len(found)} violations, expected a collapse"
    v = found[0]
    assert v["is_violation"] is True
    assert v["violation_message"].startswith("[multiple_secrets] 500 secrets"), v["violation_message"]
    redacted = text[:v["start"]] + "[REDACTED]" + text[v["end"]:]
    assert "ghp_" not in redacted, "the collapsed span left a secret behind"


def test_char_budget_collapses_below_the_count_cap():
    """20 secrets is under MAX_VIOLATIONS_PER_MESSAGE, but 20 copies of a
    120 KB message is not under the character budget."""
    text = "x " * 60000 + " ".join("ghp_" + "%036d" % i for i in range(20))
    found = scan(text)
    assert len(found) == 1, len(found)
    assert "multiple_secrets" in found[0]["violation_message"]


def test_duplicated_text_stays_within_budget():
    max_chars = constant("MAX_DUPLICATED_CHARS_PER_MESSAGE")
    max_violations = constant("MAX_VIOLATIONS_PER_MESSAGE")
    for n in (10, 60, 500, 4000):
        text = dense(n)
        found = scan(text)
        assert len(found) == 1 or len(found) <= max_violations, (n, len(found))
        duplicated = sum(len(v["value"]) for v in found)
        # one full copy is unavoidable -- the contract requires it
        assert duplicated <= max_chars + len(text), (n, duplicated)


def test_sparse_secrets_in_a_large_message_are_still_itemised():
    """The caps must not collapse ordinary messages: two secrets in 80 KB of
    prose is well inside the budget and should redact precisely."""
    filler = "x " * 20000
    text = filler + "ghp_" + "a" * 36 + " " + filler + "npm_" + "b" * 36
    assert rules(scan(text)) == ["github_pat_classic", "npm_token"], rules(scan(text))


# ---------------------------------------------------------------------------
# Offset semantics across string representations.
# ---------------------------------------------------------------------------

def utf16_window(text, start, end):
    """What a host with UTF-16 strings cuts when it reads our integers as
    UTF-16 unit offsets (.NET, Java, JavaScript)."""
    units = text.encode("utf-16-le", "surrogatepass")
    return units[start * 2:end * 2].decode("utf-16-le", "surrogatepass")


def test_offsets_cover_the_secret_under_both_indexings():
    for prefix in ("", "key: ", "\U0001f511 key: ", "\U0001f511\U0001f511\U0001f512 "):
        text = prefix + SECRET + " -- rotate it"
        v = scan(text)[0]
        assert SECRET in text[v["start"]:v["end"]], (prefix, "code-point host")
        assert SECRET in utf16_window(text, v["start"], v["end"]), (prefix, "utf-16 host")


def test_widening_never_produces_overlapping_spans():
    text = "\U0001f511\U0001f511 " + SECRET + " " + "npm_" + "b" * 36 + " tail"
    found = scan(text)
    assert len(found) == 2, rules(found)
    assert found[0]["end"] <= found[1]["start"], [(v["start"], v["end"]) for v in found]


def test_utf16_widening_is_clamped_at_end_of_message():
    """Known, deliberate gap. `end` is never reported past len(value), because
    an out-of-range offset risks the host rejecting the violation outright --
    which would fail open. So a secret that ENDS the message, with astral
    characters before it, is covered one UTF-16 unit short per astral
    character. Pinned here so the tradeoff stays visible."""
    text = "\U0001f511 " + SECRET  # secret runs to the end, one astral char before
    v = scan(text)[0]
    assert v["end"] == len(text)
    assert SECRET in text[v["start"]:v["end"]], "code-point host is unaffected"
    assert SECRET not in utf16_window(text, v["start"], v["end"])


def test_non_ascii_that_is_not_astral_needs_no_widening():
    for prefix in ("clé café: ", "鍵は: "):
        text = prefix + SECRET
        v = scan(text)[0]
        assert text[v["start"]:v["end"]] == SECRET
        assert utf16_window(text, v["start"], v["end"]) == SECRET


# ---------------------------------------------------------------------------
# Robustness: no input should raise out of the scan itself.
# ---------------------------------------------------------------------------

def test_odd_characters_do_not_raise():
    for text in ("a\ud800b " + SECRET, "a\x00b " + SECRET, "﻿" + SECRET,
                 "\U0001f511" * 50 + SECRET, "\r\n\t" + SECRET):
        assert len(scan(text)) == 1, repr(text[:20])


def test_no_pathological_backtracking():
    import time
    baits = [
        "eyJ" + "A" * 40000,
        "api_key=" + "A" * 40000 + "!",
        "-----BEGIN PRIVATE KEY-----" + "A" * 40000,
        ("-----BEGIN PRIVATE KEY-----" + "A" * 200) * 100,
        "authorization: bearer " + "A" * 40000,
        "http://a:b@x.com " * 4000,
    ]
    for text in baits:
        started = time.perf_counter()
        scan(text)
        elapsed = time.perf_counter() - started
        assert elapsed < 2.0, f"{elapsed:.2f}s on {text[:30]!r}"


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
