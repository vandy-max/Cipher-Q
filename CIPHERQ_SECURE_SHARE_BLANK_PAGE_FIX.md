# Secure Share blank-page fix

## Root cause
`ShareCard` rendered both Sent and Received rows using `fmt(...)`, but the function was not defined or imported in `ShareMessagesPage.jsx`. Once a share existed and the Sent/Received list attempted to render a card, React threw a runtime ReferenceError and the page appeared blank.

## Fix
- Added the shared `formatTimestamp` import and a local `fmt` adapter.
- Converts numeric share timestamps from backend Unix seconds to milliseconds before formatting.
- Handles missing/invalid optional timestamps using the shared formatter's safe fallback.
- The existing Sent/Received cards, sender/recipient labels, status badges, validity timestamps, and decrypt navigation remain intact.
- Recipient decryption continues to pass the share ID to the existing Decryption workflow, which uses the approved share record and existing authorization/face-verification checks.

## Validation
- ShareMessagesPage JSX syntax check: passed.
- Existing file/text share payload tests: 5 passed.
- Full browser interaction and MongoDB-backed recipient/sender test still needs to be run in the user's configured environment.
