# Vite dependency-scan JSX parse fix

## Root cause
`frontend/src/components/monitoring/monitoringState.js` contained the Secure Share React page JSX instead of the monitoring-state utility functions. Vite correctly rejected JSX in a `.js` utility module during dependency scanning.

## Fix
- Restored `monitoringState.js` as a plain JavaScript utility module.
- Restored the backend-authoritative monitoring-state labels and `deriveMonitoringState` / `monitoringReason` helpers.
- Kept the actual Secure Share page in `frontend/src/pages/ShareMessagesPage.jsx`.
- No monitoring cadence, authorization, encryption, decryption, sharing, or RBAC workflow was changed by this correction.

## Validation
- Scanned all 91 frontend JS/JSX/TS/TSX source files with the TypeScript parser: passed.
- `monitoringState.js` no longer contains JSX.
- ZIP integrity check: passed.
- A Vite production build was not run in this packaging environment because frontend `node_modules` is not installed. Run `npm ci` then `npm run build` in the frontend folder to validate with the project's exact Vite toolchain.
