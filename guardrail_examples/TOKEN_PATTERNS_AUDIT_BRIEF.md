# TOKEN_PATTERNS audit brief

Source: 22-agent parallel research workflow verifying each pattern in `auth_token_guardrail.py` against vendor docs/RFCs as of 2026-08-27. Full per-pattern evidence/sources are in the workflow transcript if deeper citation-checking is needed.

Nothing in this brief has been applied yet — it's a plan for review.

---

## 1. Regex fixes (format has changed or was wrong)

### `pem_private_key` — confidence 0.99, no change
Two branches are broken: missing `ENCRYPTED PRIVATE KEY` (PKCS#8, e.g. `openssl pkcs8 -topk8` output), and the PGP branch requires `PGP PRIVATE KEY-----` but the real OpenPGP armor header is `PGP PRIVATE KEY BLOCK-----` — that branch can never fire.

- Current: `-----BEGIN (?:(?:RSA|EC|DSA|OPENSSH|PGP) )?PRIVATE KEY-----`
- Proposed: `-----BEGIN (?:(?:RSA|EC|DSA|OPENSSH|ENCRYPTED) PRIVATE KEY|PGP PRIVATE KEY BLOCK)-----`

### `aws_access_key_id` — confidence 0.95, no change
Suffix length is wrong for six of the nine covered prefixes: AWS's own IAM docs show non-access-key identifiers (AROA/AIDA/AGPA/AIPA/ANPA/ANVA) are 17 chars after the prefix, not 16 — the regex structurally can't match them. Also missing 4 of AWS's 12 currently-documented prefixes (ABIA, ACCA, APKA, ASCA). Only AKIA/ASIA actually work today.

- Current: `\b(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b`
- Proposed: `\b(?:A3T[A-Z0-9]|AKIA|ASIA)[A-Z0-9]{16}\b|\b(?:ABIA|ACCA|AGPA|AIDA|AIPA|ANPA|ANVA|APKA|AROA|ASCA)[A-Z0-9]{17}\b`

### `gitlab_pat` — confidence 0.95, no change
GitLab's ~2-year-old "routable tokens" rollout changed the body to a variable-length base64url payload + `.` + version/CRC32 suffix (e.g. `glpat-rQxN...YZq2Kfe0BD.01.6z70tqjnm`). Current regex only matches legacy fixed-20-char tokens.

- Current: `\bglpat-[A-Za-z0-9_\-]{20}\b`
- Proposed: `\bglpat-[0-9A-Za-z_-]{20}\b|\bglpat-[0-9A-Za-z_-]{27,300}\.[0-9a-z]{2}[0-9a-z]{7}\b`

### `basic_auth_in_url` — confidence 0.85, no change
Scheme length cap (3–10 total chars) rejects `mongodb+srv://` (11 chars) — a very common MongoDB Atlas connection-string leak shape — and excludes short schemes like `s3://`/`ws://`.

- Current: `[a-zA-Z][a-zA-Z0-9+.\-]{2,9}://[^/\s:@]{1,64}:[^/\s:@]{1,64}@`
- Proposed: `[a-zA-Z][a-zA-Z0-9+.\-]{1,20}://[^/\s:@]{1,64}:[^/\s:@]{1,64}@`

### `google_api_key` — add a new pattern, keep existing
`AIza`+35 is still valid and shouldn't be touched. But Google is actively migrating Gemini/AI Studio to a new `AQ.`-prefixed "Auth key" format — unrestricted Standard (AIza) keys are already rejected there, and **all Standard-key requests get rejected starting September 2026** (days away). Google hasn't published an exact length/charset for the new format yet.

- Add: `google_api_key_auth`, regex `\bAQ\.[A-Za-z0-9_\-\.]{20,}\b`, confidence ~0.5 (provisional — revisit once Google documents the spec)
- Existing `google_api_key` regex/confidence: unchanged

### `github_oauth_app_token` — split into two patterns
`gho_`/`ghu_`/`ghr_` are unaffected. But GitHub's own April 2026 changelog confirms `ghs_` (App installation) tokens moved to a stateless JWT format (`ghs_APPID_JWT`, ~520 chars, contains literal dots) — rollout completed by late June 2026, so current `ghs_` tokens are already outside the old charset/length.

- Current: `\bgh[ousr]_[A-Za-z0-9]{36,255}\b`, confidence 0.9
- Proposed: keep `github_oauth_app_token` as `\bgh[our]_[A-Za-z0-9]{36,255}\b` (gho_/ghu_/ghr_ only), confidence 0.9
- Add: `github_app_installation_token`, regex `\bghs_[A-Za-z0-9._-]{36,600}\b`, confidence ~0.75 (looser shape, less distinctive than the old fixed-alphanumeric form)

### `openai_api_key_project` — decided: leave regex as-is
Real project keys have grown from ~48 chars to ~130–160+ chars with no vendor announcement; modern OpenAI keys embed a fixed watermark `T3BlbkFJ` (base64 of "OpenAI") that mainstream scanners now anchor on for precision. The current loose pattern still matches real keys (no false negative) — the gap is precision, not recall.

- Current regex/confidence: unchanged — `\bsk-proj-[A-Za-z0-9_\-]{20,}\b`, confidence 0.9
- Decision: not worth the risk of anchoring on the `T3BlbkFJ` watermark (regresses to zero matches if OpenAI ever drops it) for a precision gain we don't currently need
- Doc-only fix: update the `message` text to reflect current ~130+ char reality instead of "20+ base64url chars"

---

## 2. Confidence-only adjustments (optional, low priority)

| Pattern | Current | Proposed | Why |
|---|---|---|---|
| `jwt` | 0.6 | ~0.85 | Double `eyJ...eyJ...` fixed-prefix + length-gated 3-segment structure is unusually distinctive; current score undersells it |
| `bearer_auth_header` | 0.8 | ~0.3–0.5 | Generic RFC 6750 wire format with no entropy/uniqueness requirement — fires readily on placeholder tokens, doc examples, test fixtures |
| `openai_api_key_legacy` | 0.65 | ~0.9 | Fixed `sk-` prefix + exact 48-char length is a distinctive, low-collision shape; format itself is confirmed correct and stable |

## 3. Keep and fix — generic, unverifiable patterns

Both were flagged `unverifiable`: no vendor or spec owns these formats (they're arbitrary code/config conventions), so there's nothing to check the regex against. Decided to keep both rather than drop the guardrail's only fallback coverage for credentials that don't match a vendor-specific pattern (custom internal API keys, unlisted vendors, etc.).

### `generic_labeled_token` — fix the quote bug
Matches any variable named `api_key`/`api_token`/`access_token` with a 24+ char value, but the value-side quotes are currently mandatory, so it misses common unquoted `.env`/shell/YAML assignments (e.g. `API_KEY=sk_live_abc123...`). Making both value-side quotes optional (with a trailing lookahead so the match doesn't over-consume into surrounding text) closes that gap — this is corroborated by how Gitleaks/Trivy handle the same generic-secret heuristic, not a vendor spec (none exists).

- Current: `(?i)(?:api[_-]?key|api[_-]?token|access[_-]?token)['"]?\s*[:=]\s*['"](?P<secret>[A-Za-z0-9_\-/+=]{24,})['"]`
- Proposed: `(?i)(?:api[_-]?key|api[_-]?token|access[_-]?token)['"]?\s*[:=]\s*['"]?(?P<secret>[A-Za-z0-9_\-/+=]{24,})['"]?(?=[\s'"`,;]|$)`
- Confidence: unchanged at 0.5 — still an appropriately-hedged heuristic

### `generic_api_key_header` — no change
Matches ad-hoc header names (`X-Api-Key`, `X-Auth-Token`, `X-Access-Token`, `Api-Key`). RFC 6648 explicitly disclaims any standing for `X-`-prefixed headers, so "unverifiable" here means "no spec to grade against," not "structurally broken" — the regex's value-side quotes are already optional, and the audit turned up no concrete defect. Leave as-is.

---

## 4. Remove — out of scope for this client

`kubeconfig_client_key_data` and `kubeconfig_bearer_token` are both being dropped, not because of anything the audit found (`kubeconfig_client_key_data` was confirmed correct; `kubeconfig_bearer_token` was flagged with weak-heuristic issues in an earlier draft of this brief) but because this client has no Kubernetes surface to protect. Removing dead detection surface area is also a net win for false-positive risk, particularly for `kubeconfig_bearer_token`'s generic `token: "..."` shape.

- Delete both `dict(...)` entries from `TOKEN_PATTERNS` in `auth_token_guardrail.py`
- Delete the `# --- Kubernetes --------------------------------------------------------------` section header comment along with them
- Check for any tests/fixtures referencing `kubeconfig_client_key_data` or `kubeconfig_bearer_token` by name and remove those cases too

## 5. No change — confirmed correct

`anthropic_api_key`, `aws_secret_access_key`, `github_pat_classic`, `github_pat_fine_grained`, `npm_token`, `pypi_token`, `docker_hub_pat`, `basic_auth_header`

## 6. Sourcing caveat (no action needed, just context)

A few "confirmed correct" verdicts rest on gitleaks' config or community posts rather than a vendor-published spec, because the vendor doesn't publish one: `anthropic_api_key` (exact 93-char length), `github_pat_fine_grained` (82-char length), `docker_hub_pat` (27-char length), `aws_secret_access_key` (40-char length). Format is very likely right in each case — just noting the evidence is corroboration, not a primary spec, in case any of these ever need re-verification.

---

## Summary of concrete diffs

- **Regex fix, no confidence change:** `pem_private_key`, `aws_access_key_id`, `gitlab_pat`, `basic_auth_in_url`, `generic_labeled_token` (quote bug)
- **New pattern added, existing untouched:** `google_api_key` → add `google_api_key_auth`
- **Split into two patterns:** `github_oauth_app_token` → itself (narrowed to gho_/ghu_/ghr_) + new `github_app_installation_token`
- **Doc-only fix:** `openai_api_key_project` — correct the `message` text, regex/confidence untouched
- **Confidence bump/cut only:** `jwt` (↑), `bearer_auth_header` (↓), `openai_api_key_legacy` (↑, optional)
- **No change:** `generic_api_key_header` — already reasonably built, nothing to fix
- **Removals:** `kubeconfig_client_key_data`, `kubeconfig_bearer_token` — out of scope for this client, drop the whole Kubernetes section
- **Kept (not removed):** `generic_labeled_token`, `generic_api_key_header` — kept both generic patterns after weighing the fallback-coverage trade-off
