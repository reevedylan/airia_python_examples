# Auth Token Guardrail — Overview

Custom content filter (`auth_token_guardrail.py`) that scans message text for leaked
credentials — API keys, access tokens, private keys, embedded passwords — and flags
each hit as a separate violation with redaction offsets. 24 named patterns cover
known formats. There is no entropy/heuristic backstop for unrecognized formats —
it was removed because it generated too many false-positive flags on non-sensitive
high-entropy strings (hashes, UUIDs, session IDs, etc.).

Confidence tracks **format specificity**: a fixed prefix + fixed length + checksum
is hard to produce by accident (0.85–0.99). A keyword sitting near a generic-looking
value is a weaker signal (0.50–0.70) — it narrows things, but the value itself
could be anything.

---

## LLM / AI provider keys

**`anthropic_api_key`** — confidence **0.99**
Matches `sk-ant-api03-` or `sk-ant-admin01-` + 93 base64url chars + trailing `AA`.
Why: long fixed prefix, fixed length, fixed suffix — effectively unique to this format.
```
sk-ant-api03-bipwDKRY5ahovCJQX4-gnuBIPW3+fmtAHOV29elszGNU18dkryFMT07cjqxELSZ6bipwDKRY5ahovCJQX4-gnuAA
```

**`openai_api_key_project`** — confidence **0.90**
Matches `sk-proj-` + 20 or more base64url chars.
Why: distinctive prefix, but the open-ended length leaves a little room for coincidence.
```
sk-proj-cjqxELSZ6bipwDKRY5ahovCJQX4-gnuBIPW3+fmtAHOV29
```

**`openai_api_key_legacy`** — confidence **0.85**
Matches `sk-` + exactly 48 alphanumeric chars.
Why: `sk-` alone is a short, generic prefix shared by other schemes; the fixed length helps but doesn't fully offset that.
```
sk-dkryFMT07elszGNU18fmtAHOV29gnuBIPW3cjqxELSZ6bipwDKR
```

**`google_api_key`** — confidence **0.95**
Matches `AIza` + 35 alphanumeric/underscore/hyphen chars.
Why: fixed prefix plus fixed length is distinctive to Google-issued keys.
```
AIzaelszGNU18dkryFMT07cjqxELSZ6bipwDKRY5ahovCJQX4-gnu
```

## Cloud providers

**`aws_access_key_id`** — confidence **0.95**
Matches a known AWS prefix (`AKIA`, `ASIA`, `AROA`, `AIDA`, etc.) + 16 uppercase alphanumeric chars.
Why: enumerated, AWS-owned key-type prefixes plus fixed length give low collision risk.
```
AKIAFMT07ELSZ6DKRY5C
```

**`aws_secret_access_key`** — confidence **0.60**
Matches a 40-char base64-ish string, only when `aws` appears within 20 chars beforehand.
Why: the bare 40-char value is too generic on its own; keyword proximity narrows it but doesn't eliminate false positives.
```
aws_secret_key = "gnuBIPW3+fmtAHOV29elszGNU18dkryFMT07cjqxELS"
```

**`gcp_service_account_key`** — confidence **0.90**
Matches `"type": "service_account"` appearing near a `"private_key"` field.
Why: two semantically specific JSON fields co-occurring is very unlikely outside a real service-account key.
```
{"type": "service_account", "project_id": "demo-project", "private_key_id": "abc123", "private_key": "-----BEGIN PRIVATE KEY-----\nMIIEvQ...\n-----END PRIVATE KEY-----\n", "client_email": "svc@demo-project.iam.gserviceaccount.com"}
```

## Source control & package registries

**`github_pat_classic`** — confidence **0.95**
Matches `ghp_` + 36 alphanumeric chars.
Why: GitHub-unique prefix plus fixed length.
```
ghp_hovCJQX4bipwDKRY5cjqxELSZ6dkryFMT07elszGNU1
```

**`github_pat_fine_grained`** — confidence **0.95**
Matches `github_pat_` + 82 alphanumeric/underscore chars.
Why: long unique prefix plus fixed length.
```
github_pat_ipwDKRY5bipwDKRY5bipwDKRY5bipwDKRY5bipwDKRY5bipwDKRY5bipwDKRY5bipwDKRY5bi
```

**`github_oauth_app_token`** — confidence **0.90**
Matches `gho_`/`ghu_`/`ghs_`/`ghr_` + 36–255 alphanumeric chars.
Why: unique prefixes, but the wide length range is looser than GitHub's fixed-length formats.
```
ghs_jqxELSZ6dkryFMT07elszGNU18fmtAHOV29gnuBIPW3+f
```

**`gitlab_pat`** — confidence **0.95**
Matches `glpat-` + 20 alphanumeric/underscore/hyphen chars.
Why: unique prefix plus fixed length.
```
glpat-kryFMT07cjqxELSZ6bip
```

**`npm_token`** — confidence **0.95**
Matches `npm_` + 36 alphanumeric chars.
Why: unique prefix plus fixed length.
```
npm_lszGNU18fmtAHOV29gnuBIPW3aelszGNU18dkryFMT07
```

**`pypi_token`** — confidence **0.95**
Matches the fixed `pypi-AgEIcHlwaS5vcmc` prefix + 50 or more chars.
Why: the prefix itself is a base64-encoded constant unique to PyPI tokens.
```
pypi-AgEIcHlwaS5vcmcmtAHOV29elszGNU18dkryFMT07cjqxELSZ6bipwDKRY5ahovCJQX4gnuBIPW3fmtAH
```

**`docker_hub_pat`** — confidence **0.95**
Matches `dckr_pat_` + 27 alphanumeric/underscore/hyphen chars.
Why: unique prefix plus fixed length.
```
dckr_pat_nuBIPW3_fmtAHOV29elszGNU18dk
```

## Generic / structural formats

**`jwt`** — confidence **0.85**
Matches three base64url segments separated by `.`, header starting with `eyJ`.
Why: structurally distinctive, but not every JWT is sensitive (some are non-secret identity tokens), hence a small discount.
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.4pcPyMD09olPSyXnrXCjTwXyr4BsezdI1AVTmud2fU4
```

**`bearer_auth_header`** — confidence **0.80**
Matches an HTTP `Authorization: Bearer <token>` header value (20+ chars).
Why: keyword-anchored, but the token itself is just a generic long string with no unique shape of its own.
```
Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.ovCJQX4-gnuBIPW3+fmtAHOV29elszGNU18dk
```

**`basic_auth_in_url`** — confidence **0.85**
Matches credentials embedded directly in a URL: `scheme://user:password@host`.
Why: a clear structural pattern — credentials sitting directly in a URL — with low ambiguity.
```
postgres://admin:Sup3rSecretPW9@db.internal.example.com:5432/mydb
```

**`pem_private_key`** — confidence **0.99**
Matches a PEM-encoded private key block: `-----BEGIN … PRIVATE KEY-----`.
Why: exact, standardized header string — essentially no false-positive surface.
```
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA3T3v5nJ8gAvOsQeUwnr8fVXtaB0v2SUFXAqk3v6M6b1n9YsL
rK9m5f1cX8Jv2wQxNc7bY0dR1s8pV4tK9yE2LcQzF3rG8hN0mB6uP1wS5xJ9qA7C
-----END RSA PRIVATE KEY-----
```

**`generic_labeled_token`** — confidence **0.50**
Matches a variable literally named `api_key`/`secret`/`token` assigned a 24+ char value
(generated tokens/keys are almost always 24+ chars, so the bar is set there to cut
placeholder/example noise without missing real ones).
Why: still a keyword-only heuristic, but the raised length bar filters out most
doc/tutorial placeholders (`your_key_here`, etc.) while real generated secrets stay well above it.
```
token: "bipwDKRY5ahovCJQX4gnuBIPW3fmt"
```

**`generic_labeled_password`** — confidence **0.50**
Matches a variable literally named `passwd`/`password` assigned an 8+ char value.
Why: split out from the token/key case because real passwords are commonly short
(8–16 chars) — raising the bar the way `generic_labeled_token` did would miss most
actual leaked passwords, so this keeps a lower threshold and accepts more noise in exchange.
```
password: "Tr0ub4dor3xampleKey9"
```

## HTTP auth headers (vendor-agnostic)

**`basic_auth_header`** — confidence **0.80**
Matches an HTTP `Authorization: Basic <base64>` header value (12+ chars).
Why: same reasoning as `bearer_auth_header` — keyword-anchored, generic payload underneath.
```
Authorization: Basic YWRtaW46U3VwZXJTZWNyZXQxMjM=
```

**`generic_api_key_header`** — confidence **0.60**
Matches a custom API-key style header (`X-Api-Key`, `X-Auth-Token`, `X-Access-Token`, `Api-Key`) with a 16+ char value.
Why: header names in this family vary a lot across services, so it's a broader, weaker heuristic than a vendor-fixed prefix.
```
X-Api-Key: 8f3ac9d2e1b74a0f9c22bb7
```

## Kubernetes

**`kubeconfig_client_key_data`** — confidence **0.85**
Matches a kubeconfig `client-key-data` field: a base64-encoded client private key.
Why: the field name is unique to kubeconfig's YAML schema, so this is nearly as specific as spotting a raw PEM key.
```
client-key-data: pwDKRY5ahovCJQX4/gnuBIPW3+fmtAHOV29elszGNU18dkryFMT07cjqxELSZ6bipwDKRY5ahovCJQX4/gn==
```

**`kubeconfig_bearer_token`** — confidence **0.65**
Matches a `token:` field appearing near `kubeconfig`/`kubectl`/`serviceaccount`/`k8s` context — typically a cluster bearer token.
Why: keyword-proximity heuristic like `aws_secret_access_key` — the keyword narrows it, but the value itself is just an opaque or JWT-shaped string.
```
kubeconfig user context: token: eyJhbGciOiJSUzI1NiJ9.abcdefghijklmnopqrstuvwxyz
```

## Design notes

- Named patterns are matched independently against the full text; each match's
  span is "claimed" so later patterns don't double-count the same substring.
- Patterns like `aws_secret_access_key`, `bearer_auth_header`,
  `basic_auth_header`, `generic_api_key_header`, `generic_labeled_token`, and
  `generic_labeled_password` redact only the captured secret value, not the
  surrounding keyword/prefix.
- Confidence tracks format specificity: fixed-length, uniquely-prefixed formats
  score highest (0.85–0.99); keyword-proximity or generic-shape heuristics
  score lowest (0.50–0.70).
- There is deliberately no entropy-based catch-all anymore. It flagged
  non-sensitive high-entropy strings (hashes, UUIDs without dashes, session
  IDs, encoded binary data) far more often than real unrecognized secrets,
  which was driving excessive log noise for at least one customer.
- All example values above are synthetic/fabricated and verified to match the
  live regex in `auth_token_guardrail.py` — safe to use as test input.
