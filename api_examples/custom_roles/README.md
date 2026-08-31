# Custom Roles API

Not publicly documented — shapes below were confirmed by calling `https://prodaus.api.airia.ai` directly (2026-08-31).

## Endpoints used by these scripts

| Script | Method | Path |
|---|---|---|
| `get_permissions.py` | GET | `/v1/custom-roles/permissions` |
| `create_role.py` | POST | `/v1/custom-roles/validate-permissions` |
| `create_role.py` | POST | `/v1/custom-roles` |

Also confirmed to exist (no script yet):

| Method | Path | Notes |
|---|---|---|
| GET | `/v1/custom-roles` | Paginated list. Returns `roleId`/`roleName`/`displayName`/`permissionCount`/`userCount`/`isSystemRole`/`isProjectSpecific`/`createdAt` per item, no `permissions` array. |
| GET | `/v1/custom-roles/{roleId}` | Single role, includes the full `permissions` array (flat strings). |
| DELETE | `/v1/custom-roles/{roleId}` | Returns `204` on success, `404` if the id doesn't exist. |

## `GET /v1/custom-roles/permissions`

Query params: `search`, `sortBy`, `sortDirection`, `pageNumber`, `pageSize`.

Response:
```json
{
  "items": ["catalog:enterprise-search:read", "catalog:spaces:manage", "..."],
  "totalCount": 290
}
```
`items` is a flat array of permission strings (`scope:resource:action`), **not** objects — index into it directly, there's no `.name`/`.id` to unwrap. At time of writing there are 290 permissions across ~15 scopes (`catalog`, `common`, `community`, `gateway`, `governance`, `settings`, `studio`, `marketplace`, ...).

## `POST /v1/custom-roles/validate-permissions`

Body: `{"permissions": ["a:b:c", ...]}`

- Empty list → `400` with body `"Permissions list cannot be empty."`
- Non-empty list → `200` with body `[]`, **even when every permission string is garbage** (e.g. `"totally:not:a-real-permission"`). In testing this endpoint never returned anything other than `[]` for a non-empty list — it does not appear to check permission strings against the real permission catalog. Don't rely on it to catch typos; the actual validation happens on `POST /v1/custom-roles` (see below). Its practical purpose in `create_role.py` is only to surface the `400` on an empty list before attempting creation.

## `POST /v1/custom-roles`

Body:
```json
{"displayName": "your-role-name", "permissions": ["a:b:c", ...]}
```

- If any permission string isn't in the real catalog, this call (not `validate-permissions`) is what rejects it: `400` with body like `"Unknown permission(s) requested: totally:not:a-real-permission (Parameter 'permissionNames')"`.
- On success (`200`), response echoes back a full role object:
  ```json
  {
    "roleId": "01a0...",
    "roleName": "your-role-name",
    "displayName": "your-role-name",
    "description": "",
    "isSystemRole": false,
    "isProjectSpecific": false,
    "permissions": ["a:b:c", "..."]
  }
  ```
- `roleName` is server-derived from `displayName` (lowercased/slugified in testing when `displayName` had no spaces/caps; not independently settable via this endpoint).
- There is no dedicated "update role" script here — to change a role's permissions you'd need to find/confirm a PUT/PATCH endpoint yourself; only create/list/get/delete were confirmed above.

## Gotchas

- A role's `id` (from the create response, as `roleId`) is what you pass into a group's `roleIds` / `ROLE_IDS` — see [`../groups/README.md`](../groups/README.md) for how groups reference roles.
- Role names are tenant-global; creating a role with a `displayName` that collides with an existing one was not tested here — check before scripting bulk creation.
