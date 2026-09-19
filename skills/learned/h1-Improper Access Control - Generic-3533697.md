<!-- auto: https://hackerone.com/reports/3533697 -->

# SKILL: Public-Share Write-Policy Bypass (object edit-level policy not enforced on page creation)

## 1 Trigger Conditions
- App with collections/wiki/workspaces (pages, boards, albums) and two permission layers: (a) object policy ("allow editing = admins only"), (b) share link with its own `editable` flag.
- Public/link share usable by a logged-in non-member; token travels in URL and API path.
- UI hides create/edit controls, yet a create endpoint takes `shareToken` + `parentId` from the client.
- Object also set to "default mode = view".

## 2 Root Cause Pattern
Write authz checks share/member permission (`canEdit()` on the share, or synthetic perms `memberPermissions | SHARE`) but never the object-level edit policy (`getEditPermissionLevel()` / `memberCanEdit()`). The frontend enforces the policy; the API function does not. CWE-284 / broken function-level authorization: the same create handler is guarded on the member route and unguarded on the `p/<shareToken>` route. Smell: `verifyEditPermissions()` passes for any "editable" share.

## 3 Recon Checklist
- Fingerprint app/version: `/status.php`, `/ocs/v2.php/cloud/capabilities`, changelog entries tagged 🔒.
- Find routes: `ocs/v2.php/apps/<app>/api/v1.0/`; grep routes for `{shareToken}` and public `p/` prefixes.
- Enumerate every write verb (create, rename, move, copy, tag, upload, delete) on both member and share routes — UI-disabled ≠ API-blocked.
- Note permission settings ("allow editing = admins/members") and default view mode.
- Capture share flags: token, `editable`, page-share vs whole-object share.

## 4 Hunt Methodology
1. Identities: Owner A (edit=admins, default view), Attacker B (logged-in non-member).
2. A creates the object, sets policy, creates an editable public link; record token + a parent page id.
3. As B, baseline: UI read-only; `GET` listing succeeds; member-route write → expect 403.
4. Probe: replay write calls on the `p/<shareToken>` route with B's cookies.
5. Diff baseline vs probe status/body, then confirm persistence in A's listing.
6. Vary share/edit flags, page vs whole-object share, roles (guest, federated), `templateId`, sibling `parentId`s.
7. Test sibling endpoints and adjacent apps for the same omission.

## 5 Payload Patterns
```
POST /ocs/v2.php/apps/<app>/api/v1.0/p/collectives/<shareToken>/pages/<parentId>
OCS-APIRequest: true
Content-Type: application/json

{"title":"canary","parentId":<parentId>,"templateId":null}
```
Variants: same path with PUT/PATCH; `/pages/<id>` rename/tag/move; `/attachments` upload. Member baseline: `.../api/v1.0/collectives/<id>/pages/<parentId>`. Leak `parentId`/fileIds from `GET .../p/collectives/<shareToken>/pages`.

## 6 WAF Bypass Tips
- Mostly authz, not signatures. Reach the same handler despite path rules:
- `/ocs/v2.php/...` vs `/index.php/apps/<app>/...` (keep `OCS-APIRequest: true` for OCS).
- Trailing slash, encoded segments, `?format=json`, `%2f` in tokens.
- Method swap; JSON vs form body; send via the `p/` route authenticated, then unauthenticated.

## 7 Triage Guidance
- Low/Medium: authenticated non-member + owner-enabled editable link → integrity only (content creation, structure defacement, persistence). High if it yields read/delete of private pages or anonymous creation.
- Valid only with two real sessions: baseline 403/404, probe 200, and Owner A sees the injected page.
- Reject: owner seeing buttons; pure UI bug.
- Title: "Public/read-only <object> allows <write> despite <policy>". Fix: enforce object edit-level in every write handler including the share-token path.

## 8 Example
Nextcloud Collectives (H1 #3533697, Low, 2026). Collective set "Allow editing = Admins only" + "default page mode = View"; owner creates an editable public share link. A logged-in non-member is correctly read-only in the UI, but `POST /ocs/v2.php/apps/collectives/api/v1.0/p/collectives/<shareToken>/pages/<parentId>` with `{"title":"hacker"}` returns 200 and creates the page. Share-token create validates share/member permission but not the collective's edit-level policy. Related sibling endpoint: #3530164.
