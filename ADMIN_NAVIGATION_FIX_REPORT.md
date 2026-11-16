# CipherQ Admin Workspace Navigation Fix

## Scope
This patch addresses the administrator UI navigation visibility issue only. It does not change QIRA, backend code, APIs, database schemas, RBAC rules, cryptographic operations, monitoring logic, intent workflows, audit generation, or application business logic.

## Root cause addressed
The sidebar's visibility rules relied on exact role-string comparisons (`user.role === "ADMIN"`) in some places, while the authenticated role is persisted directly from the login response. A casing or whitespace variation could therefore cause the admin-specific navigation treatment to be skipped. Also, the sidebar's collapsed preference could make feature labels appear to have disappeared by rendering the navigation as icon-only.

## Changes
1. `frontend/src/components/layout/Sidebar.jsx`
   - Normalizes the role string using trim + uppercase before applying display rules.
   - Recognizes the existing administrator roles `ADMIN` and `USER_LEVEL_2` for full workspace navigation visibility.
   - Keeps the standard application feature groups visible to administrators even when monitoring re-authentication is pending. This affects navigation visibility only; existing operation-level security gates remain unchanged.
   - Keeps Policy Engine restricted to the existing `ADMIN` display role.
   - Keeps Admin Dashboard as an additional destination rather than replacing the normal CipherQ modules.
2. `frontend/src/components/layout/AppShell.jsx`
   - Starts the admin sidebar expanded so labels such as Audit, Risk Intelligence, Encryption and Decryption are visible immediately.
   - The admin can still manually collapse the sidebar.

## Navigation destinations checked
- Overview / Dashboard
- Identity
- Risk Intelligence
- Audit Trail
- Intent History
- Create Intent
- Encryption
- Decryption
- Secure Share
- Direct Messages
- Quantum Lab
- Admin Dashboard
- Policy Engine (ADMIN only)

Every listed destination has an existing render branch in `frontend/src/App.jsx`.

## Validation performed
- TypeScript JSX transpile/syntax check: PASS for both modified files.
- Static navigation check: PASS; every expected navigation ID exists and has a corresponding App render branch.
- Role-normalization check: PASS.
- Archive integrity check: PASS.
- Files modified: only the two frontend layout/navigation files above. No backend or QIRA files changed.

## Important behavior retained
- Backend RBAC remains the authorization boundary.
- Existing monitoring re-authentication requirements remain in force for protected operations.
- Encryption/decryption ownership, intent, key-session and integrity checks remain unchanged.
- Audit records and risk decisions continue to come from existing backend services; this patch does not fabricate or alter them.

## Test limitation
The full Vite production build and browser end-to-end tests were not run because frontend dependencies are not installed in the supplied project environment. The validation above is limited to syntax/transpile and static navigation checks.
