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

**`openai_api_key_legacy`** — confidence **0.65**
Matches `sk-` + exactly 48 alphanumeric chars.
Why: `sk-` alone is a short, generic prefix shared by other schemes — including well beyond OpenAI — so confidence is kept low even with the fixed length.
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
Matches a 40-char base64-ish string, only when `aws` appears within 20 chars beforehand —
the 20-char gap is matched across newlines, so a value on its own line right after a
`aws_secret_access_key =` label still counts.
Why: the bare 40-char value is too generic on its own; keyword proximity narrows it but doesn't eliminate false positives.
```
aws_secret_key =
  "<40-char base64-ish string>"
```
Demo trigger (synthetic, non-functional):
```
aws_secret_key =
  "0/9BZhvWaXH6K2/tyLBhhOhg9uhkxiiEZpFfk1OH"
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

**`jwt`** — confidence **0.60**
Matches three base64url segments (20+ chars each) separated by `.`, header starting with `eyJ`.
Why: `eyJ` is just the base64 encoding of `{"`, so any base64-encoded JSON can start this way; requiring 20+ chars per segment
filters out short coincidental matches, but the pattern still isn't unique to real JWTs (blog posts, docs, and non-secret
identity tokens all fit the shape), hence the low confidence.
```
<base64url header starting with eyJ, 20+ chars>.<base64url payload, 20+ chars>.<base64url signature, 20+ chars>
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
Matches a PEM-encoded private key block: `-----BEGIN [TYPE ]PRIVATE KEY-----`, requiring a
single space before `PRIVATE KEY` (and after an optional type like `RSA`/`EC`/`DSA`/`OPENSSH`/`PGP`)
so malformed headers like `-----BEGINPRIVATE KEY-----` don't match.
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
Matches a variable literally named `api_key`/`api_token`/`access_token` assigned a 24+ char value
(generated tokens/keys are almost always 24+ chars, so the bar is set there to cut
placeholder/example noise without missing real ones).
Why: still a keyword-only heuristic, but restricted to explicit API-key/token naming —
bare `secret` and `token` were dropped because they fire on application-level config
(Django's `SECRET_KEY`, `secret_message`, generic `token:` fields, etc.) that isn't a
credential leak. The raised length bar also filters out most doc/tutorial placeholders
(`your_key_here`, etc.) while real generated secrets stay well above it.
```
api_key: "<24+ character value>"
```
Demo trigger (synthetic, non-functional):
```
api_key: "ifdFzctEq8oB7GVvouNndNWYzjFnMpXXXX"
```

> **Removed:** `generic_labeled_password` (matched `passwd`/`password` + an 8+ char value)
> was removed entirely. `password` is too common a keyword at an 8-char threshold — it fired
> constantly on code snippets, docs, and test fixtures using mock passwords, and the false-positive
> rate wasn't fixable by tuning the threshold without also missing most real short passwords.

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

**`kubeconfig_bearer_token`** — confidence **0.70**
Matches a quoted `token:` field (40+ chars) appearing near `kubeconfig`/`kubectl`/`serviceaccount`/`k8s`
context — typically a cluster bearer token. Quotes around the value are now required (previously optional,
which left the secret boundary ambiguous), and the minimum length was raised from 20 to 40 chars to match
real base64url-encoded service account tokens rather than firing on short mentions of "token" in k8s docs.
```
kubeconfig user context: token: "<40+ character quoted token>"
```
Demo trigger (synthetic, non-functional):
```
kubeconfig user context: token: "pxyB9JKmyLDUwMbqJfgLq0mFPz3Tn5xR8vQeYh2sKdL9"
```
