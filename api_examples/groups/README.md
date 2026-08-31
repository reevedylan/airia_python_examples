# Groups API

Not publicly documented — shapes below were confirmed by calling `https://prodaus.api.airia.ai` directly (2026-08-31). This is the identity/access-control notion of "group" (roles + users + project scoping), unrelated to any agent/pipeline grouping.

## Endpoints used by these scripts

| Script | Method | Path |
|---|---|---|
| `get_groups.py` | GET | `/v1/Groups` |
| `create_group.py` | POST | `/v1/Groups` |
| `update_group.py` | PUT | `/v1/Groups/{id}` |
| `delete_group.py` | DELETE | `/v1/Groups/{id}` |

Note the capital `G` in `/v1/Groups` — inconsistent with the lowercase `/v1/custom-roles`.

## The two different shapes: list/write vs. detail

This is the single most important gotcha in this API. There are **two different representations of a group**, and they don't match:

**Request bodies (POST `/v1/Groups`, PUT `/v1/Groups/{id}`)** and the **PUT response** use flat ID arrays:
```json
{"name": "...", "roleIds": ["role-uuid", ...], "userIds": ["user-uuid", ...], "projectIds": ["proj-id", ...]}
```

**GET `/v1/Groups` (list) and GET `/v1/Groups/{id}` (detail)** return nested objects instead:
```json
{
  "id": "...",
  "name": "...",
  "parentId": "...",
  "createdAt": "...",
  "updatedAt": "...",
  "identityServerGroupId": "...",
  "groupType": "Feature",
  "users": [{"id": "...", "...": "..."}] ,
  "totalUsers": 0,
  "rolesList": [{"id": "...", "name": "...", "displayName": "...", "description": "...", "projectId": null}],
  "isIdpProvisioned": false,
  "groupLeader": null,
  "projectIds": []
}
```
So to read a group's role/user IDs you use `.rolesList[].id` / `.users[].id`, but to *write* them back you must send `roleIds` / `userIds` as flat arrays. `projectIds` is the one field that's already flat both ways.

The **POST create response** is a third, half-populated variant: it echoes the nested-detail shape (`rolesList`, `users`, ...) but leaves `rolesList`/`users` as `null` even when you passed non-empty `ROLE_IDS`/`USER_IDS` — the role/user *was* actually attached (confirmed by a follow-up GET), the create response is just stale/incomplete. **Do a GET after create if you need to confirm what was attached.**

## `PUT /v1/Groups/{id}` fully replaces — it does not merge

Confirmed by testing: PUTting a group with `ROLE_IDS = []` on a group that previously had a role attached **removed that role** (subsequent GET showed `rolesList: []`). `USER_IDS` behaves the same way (confirmed separately against the live tenant): to add a user you must resend every existing user id plus the new one, and to remove a user you just leave their id out of the list — there's no separate "remove" call. `PROJECT_IDS` wasn't separately verified but follows the same payload shape, so assume it behaves identically until proven otherwise.

**If you want to add a role/user/project to a group without dropping the existing ones, you must:**
1. `GET /v1/Groups/{id}` first
2. Pull existing ids from `.rolesList[].id`, `.users[].id`, `.projectIds`
3. Merge in the new id(s) yourself (dedupe)
4. `PUT` the full merged set back

`update_group.py` as shipped does **not** do this merge — it PUTs exactly the `ROLE_IDS`/`USER_IDS`/`PROJECT_IDS` you hardcode, so pointing it at a group without first fetching/merging its current membership will silently wipe anything not listed.

Also observed: after a PUT, `createdAt` on the group came back zeroed (`0001-01-01T00:00:00.0000000Z`) even though the original GET had a real creation timestamp — the PUT endpoint appears to not preserve `createdAt`.

## `DELETE /v1/Groups/{id}`

Returns `204` with an empty body on success. A subsequent GET on the same id returns `404`.

## `GET /v1/Groups`

Query params: `PageNumber`, `PageSize`, `SortBy`, `SortDirection` (capitalized, unlike `get_permissions.py`'s lowercase `pageNumber`/`sortBy` — this API is inconsistent about param casing between endpoints). Response:
```json
{"items": [ /* nested-detail shape, see above */ ], "totalCount": 3}
```

## Gotchas summary

- Nested (`rolesList`/`users`) on GET vs. flat (`roleIds`/`userIds`) on POST/PUT — see above.
- PUT replaces, never merges — fetch-then-merge yourself for additive updates.
- POST's response `rolesList`/`users` fields are unreliable (`null`) — GET to confirm.
- PUT doesn't preserve `createdAt`.
- Param casing differs between `/v1/Groups` (`PageNumber`) and `/v1/custom-roles/permissions` (`pageNumber`) — don't copy-paste params between the two without checking case.
