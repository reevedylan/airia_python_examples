# Airia Python Examples — script conventions

New API example scripts must follow the structure below. `api_examples/groups/create_group.py`
is the canonical template — when unsure, match it.

## Script structure (in order)

1. **Module docstring** — title line (`Airia <Thing> <Verb>`), blank line, then a numbered
   "How to use:" list (set API key → update the config constants → run, with a one-line
   description of what running it does).
2. **Imports** — stdlib first (`os`, and `sys` only if actually needed), then third-party
   (`requests`, `dotenv`). Any new third-party dependency must be added to `requirements.txt`.
3. **`load_dotenv()`** — call it right after the imports, before any constants are read, so
   `AIRIA_API_KEY` can come from a `.env` file in the repo root instead of a shell export.
4. **`# UPDATE THESE VALUES` section** — module-level constants, in this order:
   `BASE_URL`, then `API_KEY = os.environ.get("AIRIA_API_KEY", "ak-YOUR_API_KEY_HERE")`,
   then the script-specific inputs (ids, names, payload fields) using obvious placeholder
   values like `"your-group-id"`.
5. **`HEADERS` dict** — `accept: application/json`, `content-type: application/json` (omit
   `content-type` for GET/DELETE requests with no body), `X-API-Key`.
6. **One function per API call**, lower_snake_case and verb-first (`create_group`,
   `find_group_by_name`), taking no arguments — read the module-level constants directly.
   Build any `payload` dict inside the function, make the request, then:
   ```python
   try:
       response.raise_for_status()
   except requests.HTTPError:
       print(f"Request failed ({response.status_code}): {response.text}")
       raise
   return response.json()  # or response.status_code for DELETE
   ```
   For multi-step scripts, factor this into a shared `_raise_with_body(response)` helper
   instead of repeating it per function (see `role_group_sync/`).
7. **`# EXECUTION` section** at the bottom — plain module-level code (not
   `if __name__ == "__main__"`) that calls the function(s) in order and prints the result.

## Other conventions

- No CLI args, no config files, no `argparse` — the script *is* the config; the user edits
  the constants directly and reruns.
- Multi-step scripts still follow steps 1–4 above; they just chain several single-purpose
  functions under `# EXECUTION` and document the "why" for the chaining in the docstring
  (see `role_group_sync/role_group_sync.py`).
- Each subdirectory under `api_examples/` has its own `README.md` documenting the endpoints
  used and any non-obvious API behavior discovered while writing the scripts (shape
  mismatches between GET/POST/PUT, inconsistent param casing, replace-vs-merge semantics,
  stale/incomplete response fields, etc). Add to it whenever a script surfaces a new gotcha
  — don't let that knowledge live only in code comments.
- Update the root `README.md`'s script/collection list whenever a new script or
  subdirectory is added.
