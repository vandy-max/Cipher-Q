# QIRA sprite mascot integration

QIRA is a **presentation layer only**. It observes real results (API responses, backend
monitoring snapshots, Qira risk decisions) and shows the matching pose from the supplied 2D
character sheet. It never grants access, never calls a protected API, and never changes a
decision. Hiding a bubble/warning changes nothing in auth, RBAC, face, risk, intent or monitoring.
Backend authorization/RBAC/face/risk/intent logic is **unchanged**. One small backend bug was fixed
(datetime normalisation, see "Working prototype / workflow audit" below) and setup tooling was added.

> This version replaces the earlier 3D `QIRA.glb` avatar with sprites cut from the character
> sheet. Three.js / react-three-fiber / drei, the GLB, and the WebGL canvas are removed.
> The separate SVG `CipherQMascot` owl was not touched.

## Architecture
| Piece | File |
|---|---|
| Reaction catalogue (29 scenarios, exact messages, priority, duration) | `frontend/src/qira/qiraReactions.js` |
| Engine (priority, queue, dedupe, cooldown, sticky warnings, hold/release, dismiss, reset) | `frontend/src/qira/qiraEngine.js` |
| Real-error classification (RBAC / intent / risk / face / unavailable) | `frontend/src/qira/classify.js`, `report.js` |
| Reaction -> pose map, social poses, sprite metadata | `qiraSprites.js`, `spriteMeta.json` |
| Animation plan (tone, glow, body motion) | `qiraAnimator.js` |
| Sprite renderer (stacked cross-faded images, 30 fps DOM transforms) | `components/qira/QiraSprite.jsx` |
| Dock UI (bubble, live region, warning badge, minimize, fallback portrait) | `components/qira/QiraDock.jsx`, `QiraPortrait.jsx` |
| Monitoring/risk observer | `components/qira/QiraEventBridge.jsx` |
| Provider/hooks | `context/QiraReactionContext.jsx` |
| Assets | `frontend/public/qira/sprites/*.webp` (14 transparent sprites, ~0.5 MB total), `frontend/public/qira/qira-portrait.webp` |

Sprites load from `${BASE_URL}qira/sprites/`. If the neutral sprite fails to load, the dock shows the
static portrait and messages still appear. A renderer error is caught by an error boundary and cannot
affect auth or monitoring. The tick loop pauses while the tab is hidden and stops on unmount.

## Reaction -> pose
| Pose (sprite) | Reactions |
|---|---|
| `login` (neutral) | login.page, idle, alert.cleared |
| `loginSuccess` | login.success |
| `loginFailed` | login.failed, face.failed, intent.mismatch, rbac.denied |
| `explaining` | face.requested, policy.updated |
| `success` | face.success |
| `thinking` | intent.entered, api.unavailable |
| `happy` | intent.match, rbac.pass, risk.low |
| `processing` | risk.started, qkd.running, monitoring.starting |
| `surprised` | risk.elevated, intent.drift |
| `riskAlert` | risk.high, suspicious.activity, session.revoked, audit.failed |
| `validation` | encrypt.success, decrypt.success, audit.verified |
| `typing` | monitoring.active |

Tone halo (neutral / ok green / warn amber / critical red) and a small body motion are added in code.
The sheet's sample speech-bubble text is **not** used; the spec-exact messages are kept.

## 29 scenarios — status
Legend: **T-real** = exercised in a real browser against the real backend; **T-comp** = component/integration test with real api layer + engine (transport/camera stubbed);
**T-unit** = unit test; **W** = wired to the real source in code, not covered by an automated test; **X** = not implemented.

| # | Scenario | Real source | Status |
|---|---|---|---|
| 1 | login page | credential screen mounted | T-real, T-comp |
| 2 | login success | `/auth/login` token response | T-real, T-comp |
| 3 | login failed | real 4xx (not 429, not network/5xx) | T-real, T-comp |
| 4 | face requested | verification prompt mounted | T-comp |
| 5 | face success | `/face/verify` → `verified:true` | T-comp (camera/models stubbed) |
| 6 | face failed | `verified:false`, 4xx, or no usable frame in window | T-comp (camera/models stubbed) |
| 7 | intent entered | intent create/resolve dispatch | W |
| 8 | intent match | `validateIntent.valid === true` | W |
| 9 | intent mismatch | backend mismatch response (message regex vs backend source) | T-unit (classifier) + W |
| 10 | RBAC pass | successful privileged admin/transition call | W |
| 11 | RBAC denied | real 403 (verbatim body captured from running backend) | T-unit (classifier) + W |
| 12 | risk started | Qira `assessing` | T-comp (bridge) |
| 13 | risk low | decision `risk_level=low` | T-comp (bridge) |
| 14 | risk elevated | `medium` / reauth `elevated_risk` / step-up error | T-comp (bridge) + W |
| 15 | risk high | `high`/`critical` / backend risk rejection | T-comp (bridge) + W |
| 16 | QKD running | BB84 request in flight (released in `finally`) | W |
| 17 | encrypt success | `/encrypt` success response | W |
| 18 | decrypt success | `/decrypt` success response | W |
| 19 | monitoring starting | monitoring session start | W |
| 20 | monitoring active | first `active` backend snapshot of a session | T-comp (bridge) |
| 21 | intent drift | **no drift detector exists in backend or frontend** | **X (blocked)** — catalogue entry + message ready, nothing emits it (not faked) |
| 22 | suspicious activity | snapshot `identity_mismatch` / `reauth_required` | T-comp (bridge) |
| 23 | session revoked | snapshot `revoked` / `reauthRequired` | T-comp (bridge) |
| 24 | audit verified | `/audit/verify` result (state change) | T-unit/T-comp (api layer) |
| 25 | audit failed | `/audit/verify` result (state change) | T-unit/T-comp (api layer) |
| 26 | policy updated | confirmed create/delete | W |
| 27 | API unavailable | network error / 5xx, distinct from denials | T-real, T-comp |
| 28 | idle | neutral pose + breathing + blink (no message) | visually checked in a real browser |
| 29 | alert cleared | `alert.cleared` after real recovery | T-comp (engine, bridge) |

Messages never contain tokens, embeddings, keys or secrets (enforced by `qiraEngine.test.js`).
Warnings (scenarios 21–23, 25, 27) stay sticky until the real recovery signal; critical
(`risk.high`, `session.revoked`) cannot be replaced by lower-priority reactions.

## Playful layer (cosmetic only)
`frontend/src/qira/qiraSocial.js`. It produces numbers and picks among the sheet's poses; it **never** emits,
clears or reads a reaction, never calls an API, and is switched off (weight -> 0, pokes ignored) whenever a QIRA reaction is
showing or a security warning is unresolved - even after its bubble is dismissed. Reduced-motion users get none of it.

| Behaviour | Trigger | How |
|---|---|---|
| Leans toward cursor / text field | cursor movement (fresh for 6 s), or the field you are typing in | parallax lean + small head-turn rotation (not eye movement) |
| Pet QIRA | click the owl (or the keyboard-reachable "Pet QIRA" button) | `happy` pose, hop, pink halo, floating hearts |
| Flustered | 5 pokes within 3.5 s | `surprised` pose, shake, "!?" puff, 3 s cooldown |
| Politely covers eyes | a password field is focused | eyes-shut pose; restored on blur; no message |
| Idle fidgets | nothing happening for a few seconds | glance lean, curious tilt, hop, wink pose |
| Blink | every 3-6.5 s on the neutral pose | 120 ms swap to the eyes-shut pose |
| Dozes off | 75 s with no activity | eyes-shut pose, droop, slower breathing, "zZ" |
| Wakes with a wave | any activity after dozing, or returning to the tab | `explaining` pose (raised wing) + hop |

## Working prototype / workflow audit
The earlier delivery wired QIRA to the real events but was only exercised for login. This round
audited the **whole app against the real FastAPI backend** and made it runnable out of the box
without changing any workflow.

**What was missing / broken (and fixed)**
| Problem | Fix |
|---|---|
| No way to start the backend: whole-DB encryption key, admin account, config files, MongoDB all had to be hand-made | `backend/scripts/`: `generate_whole_db_encryption_key.py`, `seed_admin.py`, `setup_local_env.py` (writes `.env` files with fresh random secrets, never overwrites), `run_demo.py` (no MongoDB needed: in-memory `mongomock`, ephemeral key, seeded users), `check_setup.py`; `requirements-demo.txt`, `requirements-dev.txt`; README "Quick start (local)" |
| Face flow dead end: after enrollment the same `FaceAuthPanel` instance was reused and stayed on "Identity verified" without ever calling `/face/verify` | distinct `key`s on the enroll / verify panels in `LoginPage.jsx` |
| Face capture could hang forever on a frame the detector could not box | per-frame timeout + try/catch in `FaceAuthPanel.jsx`; detector calls serialised in `faceIdentity.js` |
| Monitoring stop crashed (`can't subtract offset-naive and offset-aware datetimes`) because BSON returns naive UTC | `_aware_utc()` in `backend/api/repositories.py` (monitoring records only) |
| Real 403s on admin screens (users, policies, intent history) were swallowed silently, so QIRA said nothing | `reportApiError(err)` added at those catch sites |
| After a real re-authentication the sticky "session revoked" warning stayed up (the old session is torn down, so the old status was gone when the new active session arrived) | `QiraEventBridge.jsx` remembers a blocked state; unit test added |

New optional build-time knobs (defaults unchanged, documented in `frontend/.env.example`):
`VITE_FACE_VERIFY_WINDOW_MS`, `VITE_FACE_SAMPLE_TIMEOUT_MS`, `VITE_MONITORING_INTERVAL_MS`. They exist only so
slow, software-rendered browsers can finish a face check; the match decision is still made by the backend.

**Run it**
```bash
cd backend && python -m venv venv && . venv/bin/activate && pip install -r requirements-demo.txt
python scripts/run_demo.py --port 8000       # seeds admin + demo users, prints the credentials, no MongoDB needed
cd ../frontend && npm ci && npm run dev      # http://localhost:5173 (proxies /api -> :8000)
```
With a real MongoDB use `python scripts/setup_local_env.py`, then `python scripts/seed_admin.py --random-admin-password`
and `uvicorn api.main:app --port 8000`. An existing encrypted database needs **your own** key file /
`CIPHERQ_WHOLE_DB_ENCRYPTION_KEY`; none is shipped.

## Tests and checks (what was actually run)
* Frontend `npx vitest run`: **107 tests, 12 files, all passing**. `npm run build` passes (no three.js, no `.glb`).
* Backend `python -m pytest` in `backend/`: **5 tests passing** (setup tooling: key generation, admin seeding, env writer, no-overwrite).
* Real browser (Playwright/Chromium, fake camera) against the **real FastAPI backend** (mongomock, application encryption ON), full user journeys, QIRA observed at each step:
  * login (wrong password, success), face enroll (5 poses), face verify, permissions consent, dashboard, continuous monitoring starts/active
  * intent create -> stays draft -> admin approval -> QKD run -> encrypt (201) -> decrypt (200, plaintext shown, `decrypt.success`)
  * real intent-mismatch 403 and RBAC denied/pass; risk assessment started/low; audit verified; policy update; backend down -> `api.unavailable`; idle
  * admin revokes the session -> `session.revoked`; user "Request Access" -> admin approves -> user face re-verify -> backend `/reauthenticate` 200 -> badge returns to SECURE
* Not verified in a real browser (component tests only): `risk.elevated` / `risk.high` from a real backend trigger, `suspicious.activity`, `audit.failed`.
* **Scenario 21 (intent drift) remains blocked**: no detector exists in the app, nothing emits it, and it is not faked.
* The sandbox is 2 CPUs with software WebGL, so face detection took up to ~15 s per frame on the busy dashboard; E2E used long verify windows (env knobs above). On normal hardware detection is fast. No GPU/low-end performance testing was done.
* Nothing was deployed. MongoDB itself was not available in the sandbox; the backend ran on `mongomock`.
* Pose sweep, petting/dozing/wake behaviour and production-preview (root and `--base=/cipherq/`) checks from the previous round still hold.

## Limitations
* QIRA is now a flat 2D mascot; the 3D model is gone. Pose changes are cross-fades with body motion, not skeletal animation.
* Sprite resolution is limited by the sheet (heads ~130-150 px, shown at ~2x for the dock size); sprites were cut out automatically, so a close look may show minor edge softness.
* "Following" the cursor is a lean/tilt, not eye movement. The blink is a quick swap to the eyes-shut pose.
* Scenario 21 (intent drift) is blocked: no detector exists, nothing emits it, and it is not faked.
* Pre-existing gaps, not touched: the README mentions `docs/architecture-design-document.md`, `docs/SECURITY_MONGODB.md` and a whole-DB migration script that are not in the uploaded project; the UI loads Google Fonts / Material Symbols from the web (offline the icon names show as text).
* Only the poses on the sheet exist; several reactions share a pose and are told apart by message, tone halo and motion.

## Commands
```bash
cd backend && pip install -r requirements-dev.txt && python -m pytest     # 5 tests
cd frontend && npm ci && npm test && npm run build                          # 107 tests
```

## Deployment notes
* Sprites ship in `dist/qira/`. A sub-path base works (`vite build --base=/app/`); verified.
* Vercel: `vercel.json` rewrites `/api/*` to the Render backend (unchanged). Set backend `ALLOWED_ORIGINS`, `JWT_SECRET`, `APP_ENV=production`, Mongo URI (auth+TLS) on the host - never in the repo.
* External dependency (pre-existing, unchanged): Google Fonts via `index.html`/`globals.css`. QIRA itself needs no CDN.
* **Secrets**: this ZIP contains no `.env`, key files, tokens or DB credentials. The ZIP you uploaded did contain `backend/.env`, `frontend/.env` and `backend/database/.whole_db_encryption_key` - treat them as exposed and rotate.
