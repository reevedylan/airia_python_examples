# Auth Token Guardrail — Overview

Custom content filter (`auth_token_guardrail.py`) that scans message text for leaked
credentials — API keys, access tokens, private keys, embedded passwords — and flags
each hit as a separate violation with redaction offsets.

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
sk-ant-api03-<93 base64url characters>AA
```
Demo trigger (synthetic, non-functional):
```
sk-ant-api03-odJFCrnl2edlBDdz1C5Jau2RJtBRnlWmTSHf6pWkLUyifDLkDmWJ6UuVTAIjvFu7WICPhDeOZIiBOB-Y6sHrFH2ZUCr-lAA
```

**`openai_api_key_project`** — confidence **0.90**
Matches `sk-proj-` + 20 or more base64url chars.
Why: distinctive prefix, but the open-ended length leaves a little room for coincidence.
```
sk-proj-<20+ base64url characters>
```
Demo trigger (synthetic, non-functional):
```
sk-proj-gotu2iXW7GboIRoL3u6aHwnMztVuaP_coUNEhEkk
```

**`openai_api_key_legacy`** — confidence **0.85**
Matches `sk-` + exactly 48 alphanumeric chars.
Why: `sk-` alone is a short, generic prefix shared by other schemes; the fixed length helps but doesn't fully offset that.
```
sk-<48 alphanumeric characters>
```
Demo trigger (synthetic, non-functional):
```
sk-UF0eWIXiiQE8JkqH3MB9n7IWUSmTtzQPxC5HChpoevbLJoLo
```

**`google_api_key`** — confidence **0.95**
Matches `AIza` + 35 alphanumeric/underscore/hyphen chars.
Why: fixed prefix plus fixed length is distinctive to Google-issued keys.
```
AIza<35 alphanumeric/underscore/hyphen characters>
```
Demo trigger (synthetic, non-functional):
```
AIzaajhDieQjEJ_Bq8F80ymm3T207gmhZRnFyy5
```

## Cloud providers

**`aws_access_key_id`** — confidence **0.95**
Matches a known AWS prefix (`AKIA`, `ASIA`, `AROA`, `AIDA`, etc.) + 16 uppercase alphanumeric chars.
Why: enumerated, AWS-owned key-type prefixes plus fixed length give low collision risk.
```
AKIA<16 uppercase alphanumeric characters>
```
Demo trigger (synthetic, non-functional):
```
AKIAI1LR3PE29GD8AFPK
```

**`aws_secret_access_key`** — confidence **0.60**
Matches a 40-char base64-ish string, only when `aws` appears within 20 chars beforehand.
Why: the bare 40-char value is too generic on its own; keyword proximity narrows it but doesn't eliminate false positives.
```
aws_secret_key = "<40-char base64-ish string>"
```
Demo trigger (synthetic, non-functional):
```
aws_secret_key = "0/9BZhvWaXH6K2/tyLBhhOhg9uhkxiiEZpFfk1OH"
```

**`gcp_service_account_key`** — confidence **0.90**
Matches `"type": "service_account"` appearing near a `"private_key"` field.
Why: two semantically specific JSON fields co-occurring is very unlikely outside a real service-account key.
```
{"type": "service_account", "project_id": "<project-id>", "private_key_id": "<key-id>", "private_key": "-----BEGIN PRIVATE KEY-----\n<base64-encoded key data>\n-----END PRIVATE KEY-----\n", "client_email": "<name>@<project-id>.iam.gserviceaccount.com"}
```
Demo trigger (synthetic, non-functional):
```
{"type": "service_account", "project_id": "demo-project-123", "private_key_id": "abc123", "private_key": "-----BEGIN PRIVATE KEY-----\nMIIExampleFakeKeyData==\n-----END PRIVATE KEY-----\n", "client_email": "demo@demo-project-123.iam.gserviceaccount.com"}
```

## Source control & package registries

**`github_pat_classic`** — confidence **0.95**
Matches `ghp_` + 36 alphanumeric chars.
Why: GitHub-unique prefix plus fixed length.
```
ghp_<36 alphanumeric characters>
```
Demo trigger (synthetic, non-functional):
```
ghp_nQTupqziQPtDu7W7eaDNKgeInGqi7w4e4pxs
```

**`github_pat_fine_grained`** — confidence **0.95**
Matches `github_pat_` + 82 alphanumeric/underscore chars.
Why: long unique prefix plus fixed length.
```
github_pat_<82 alphanumeric/underscore characters>
```
Demo trigger (synthetic, non-functional):
```
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
```

**`github_oauth_app_token`** — confidence **0.90**
Matches `gho_`/`ghu_`/`ghs_`/`ghr_` + 36–255 alphanumeric chars.
Why: unique prefixes, but the wide length range is looser than GitHub's fixed-length formats.
```
ghs_<36-255 alphanumeric characters>
```
Demo trigger (synthetic, non-functional):
```
ghs_Bictx57Y3c5wnRpQgwXJ43ANVj77p3kZZl4A
```

**`gitlab_pat`** — confidence **0.95**
Matches `glpat-` + 20 alphanumeric/underscore/hyphen chars.
Why: unique prefix plus fixed length.
```
glpat-<20 alphanumeric/underscore/hyphen characters>
```
Demo trigger (synthetic, non-functional):
```
glpat-dwQ0FIunWe8Cz6SNDCdy
```

**`npm_token`** — confidence **0.95**
Matches `npm_` + 36 alphanumeric chars.
Why: unique prefix plus fixed length.
```
npm_<36 alphanumeric characters>
```
Demo trigger (synthetic, non-functional):
```
npm_zvr3e9XrwPGzR1Iv8bh4qlL9qcgMBwUYuBMG
```

**`pypi_token`** — confidence **0.95**
Matches the fixed `pypi-AgEIcHlwaS5vcmc` prefix + 50 or more chars.
Why: the prefix itself is a base64-encoded constant unique to PyPI tokens.
```
<fixed pypi- prefix> + <50+ additional characters>
```
Demo trigger (synthetic, non-functional):
```
pypi-AgEIcHlwaS5vcmcoXyGf3azU3iQOpMN0PZLqy1WwMZaMKA3P744B8vkKQlENCzsdfF8j61
```

**`docker_hub_pat`** — confidence **0.95**
Matches `dckr_pat_` + 27 alphanumeric/underscore/hyphen chars.
Why: unique prefix plus fixed length.
```
dckr_pat_<27 alphanumeric/underscore/hyphen characters>
```
Demo trigger (synthetic, non-functional):
```
dckr_pat_yX-ZFsan2Cw7gFp6r7O425u85HF
```

## Generic / structural formats

**`jwt`** — confidence **0.85**
Matches three base64url segments separated by `.`, header starting with `eyJ`.
Why: structurally distinctive, but not every JWT is sensitive (some are non-secret identity tokens), hence a small discount.
```
<base64url header starting with eyJ>.<base64url payload>.<base64url signature>
```
Demo trigger (synthetic, non-functional):
```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkRlbW8gVXNlciJ9.J_EJ4jKEIQOkrtDXtBi10Q71hA1XcW9aTMX1C_CI3_d
```

**`bearer_auth_header`** — confidence **0.80**
Matches an HTTP `Authorization: Bearer <token>` header value (20+ chars).
Why: keyword-anchored, but the token itself is just a generic long string with no unique shape of its own.
```
Authorization: Bearer <20+ character token>
```
Demo trigger (synthetic, non-functional):
```
Authorization: Bearer XRZv7qdYdk2r7xgHWPB6PRWJ1Gk8cgSC
```

**`basic_auth_in_url`** — confidence **0.85**
Matches credentials embedded directly in a URL: `scheme://user:password@host`.
Why: a clear structural pattern — credentials sitting directly in a URL — with low ambiguity.
```
<scheme>://<user>:<password>@<host>:<port>/<path>
```
Demo trigger (synthetic, non-functional):
```
https://demo_user:SuperSecretPass123@internal-db.example.com:5432/prod
```

**`pem_private_key`** — confidence **0.99**
Matches a PEM-encoded private key block: `-----BEGIN … PRIVATE KEY-----`.
Why: exact, standardized header string — essentially no false-positive surface.
```
-----BEGIN RSA PRIVATE KEY-----
<base64-encoded key data, one or more lines>
-----END RSA PRIVATE KEY-----
```
Demo trigger (synthetic, non-functional):
```
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA1234ExampleFakeKeyMaterialDoNotUseabcdefghijk
-----END RSA PRIVATE KEY-----
```

**`generic_labeled_token`** — confidence **0.50**
Matches a variable literally named `api_key`/`secret`/`token` assigned a 24+ char value
(generated tokens/keys are almost always 24+ chars, so the bar is set there to cut
placeholder/example noise without missing real ones).
Why: still a keyword-only heuristic, but the raised length bar filters out most
doc/tutorial placeholders (`your_key_here`, etc.) while real generated secrets stay well above it.
```
token: "<24+ character value>"
```
Demo trigger (synthetic, non-functional):
```
token: "ifdFzctEq8oB7GVvouNndNWYzjFnMp"
```

**`generic_labeled_password`** — confidence **0.50**
Matches a variable literally named `passwd`/`password` assigned an 8+ char value.
Why: split out from the token/key case because real passwords are commonly short
(8–16 chars) — raising the bar the way `generic_labeled_token` did would miss most
actual leaked passwords, so this keeps a lower threshold and accepts more noise in exchange.
```
password: "<8+ character value>"
```
Demo trigger (synthetic, non-functional):
```
password: "YKYcwIBQxeGP"
```

## HTTP auth headers (vendor-agnostic)

**`basic_auth_header`** — confidence **0.80**
Matches an HTTP `Authorization: Basic <base64>` header value (12+ chars).
Why: same reasoning as `bearer_auth_header` — keyword-anchored, generic payload underneath.
```
Authorization: Basic <base64-encoded "user:password">
```
Demo trigger (synthetic, non-functional):
```
Authorization: Basic ZGVtb191c2VyOlN1cGVyU2VjcmV0UGFzczEyMw==
```

**`generic_api_key_header`** — confidence **0.60**
Matches a custom API-key style header (`X-Api-Key`, `X-Auth-Token`, `X-Access-Token`, `Api-Key`) with a 16+ char value.
Why: header names in this family vary a lot across services, so it's a broader, weaker heuristic than a vendor-fixed prefix.
```
X-Api-Key: <16+ character value>
```
Demo trigger (synthetic, non-functional):
```
X-Api-Key: Rb1_n3U6t3w+I973IPFlJ5F7
```

## Kubernetes

**`kubeconfig_client_key_data`** — confidence **0.85**
Matches a kubeconfig `client-key-data` field: a base64-encoded client private key.
Why: the field name is unique to kubeconfig's YAML schema, so this is nearly as specific as spotting a raw PEM key.
```
client-key-data: <base64-encoded client private key>
```
Demo trigger (synthetic, non-functional):
```
client-key-data: WRd+Px/BTHRJJbykE0/E8/5clLCZFNV8S2QT6INGDpyO==
```

**`kubeconfig_bearer_token`** — confidence **0.65**
Matches a `token:` field appearing near `kubeconfig`/`kubectl`/`serviceaccount`/`k8s` context — typically a cluster bearer token.
Why: keyword-proximity heuristic like `aws_secret_access_key` — the keyword narrows it, but the value itself is just an opaque or JWT-shaped string.
```
kubeconfig user context: token: <opaque or JWT-shaped token>
```
Demo trigger (synthetic, non-functional):
```
kubeconfig user context: token: pxyB9JKmyLDUwMbqJfgLq.nbK894
```

---

## Quick copy-paste test set

All examples above are **synthetic** — generated to match each pattern's exact shape/length,
not real credentials. Safe to paste into a demo chat to trigger each rule. Run
`auth_token_guardrail.py` directly against a batch to sanity-check before a demo:

```python
input = [{"content_type": "text", "value": "aws_secret_key = \"0/9BZhvWaXH6K2/tyLBhhOhg9uhkxiiEZpFfk1OH\" and Authorization: Bearer XRZv7qdYdk2r7xgHWPB6PRWJ1Gk8cgSC"}]
exec(open("auth_token_guardrail.py").read())
print(output)
```