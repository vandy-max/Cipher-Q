import { lazy, Suspense, useEffect, useState } from "react";
import { useAuth } from "./hooks/useAuth";
import { MonitoringProvider } from "./context/MonitoringContext";
import { QiraProvider } from "./context/QiraContext";
import AppShell from "./components/layout/AppShell";
import SecurityTelemetryConsent from "./components/security/SecurityTelemetryConsent";
import QiraWidget from "./components/qira/QiraWidget";
import QiraDock from "./components/qira/QiraDock";
import QiraEventBridge from "./components/qira/QiraEventBridge";
import { QiraReactionProvider, useQiraReactions } from "./context/QiraReactionContext";
import { emitQira, qiraEngine } from "./qira";


const LandingPage = lazy(() => import("./pages/LandingPage"));
const LoginPage = lazy(() => import("./pages/LoginPage"));
const Dashboard = lazy(() => import("./pages/Dashboard"));
const CreateIntentPage = lazy(() => import("./pages/CreateIntentPage"));
const IntentHistoryPage = lazy(() => import("./pages/IntentHistoryPage"));
const BB84SimulationPage = lazy(() => import("./pages/BB84SimulationPage"));
const EncryptionPage = lazy(() => import("./pages/EncryptionPage"));
const DecryptionPage = lazy(() => import("./pages/DecryptionPage"));
const ShareMessagesPage = lazy(() => import("./pages/ShareMessagesPage"));
const DirectMessagesPage = lazy(() => import("./pages/DirectMessagesPage"));
const AuditLogsPage = lazy(() => import("./pages/AuditLogsPage"));
const PolicyManagementPage = lazy(() => import("./pages/PolicyManagementPage"));
const VisualizationPage = lazy(() => import("./pages/VisualizationPage"));
const ProfilePage = lazy(() => import("./pages/ProfilePage"));
const SettingsPage = lazy(() => import("./pages/SettingsPage"));
const FaceAuthTestPage = lazy(() => import("./pages/FaceAuthTestPage"));
const AdminDashboard = lazy(() => import("./pages/AdminDashboard"));

const PUBLIC_PAGES = ["landing", "login", "register"];
// QIRA acknowledges module changes with a contextual pose (never the full welcome again).
const QIRA_PAGE_REACTION = { encrypt: "page.encrypt", decrypt: "page.decrypt", "create-intent": "page.intent", bb84: "page.quantum" };
const AUTH_TOKEN_KEY = "ibqc_token";

// `useAuth`'s `token` (and therefore `isAuthenticated`) is React state: it
// is only guaranteed to be up to date on the render AFTER `saveAuth()` (or
// any other localStorage write) has been applied. `navigate()` and the
// shell-vs-landing decision below can run in the SAME synchronous click
// handler that just established auth (e.g. "Allow & Continue" right after
// face verification), before that state has had a chance to flush to a
// render. Reading the persisted token directly gives protected-route
// navigation an immediate, correct answer during that transition, without
// ever weakening authentication: this flag only ever *widens* what counts
// as "authenticated enough to route past the Landing Page" — it never
// grants access to data. Every protected API call is still authorized
// server-side via `get_current_user`, independent of anything here.
function hasPersistedAuthToken() {
  try {
    return !!localStorage.getItem(AUTH_TOKEN_KEY);
  } catch {
    return false;
  }
}

function AppContent() {
  const { token, user, deviceId, sessionId, saveAuth, logout, isAuthenticated } = useAuth();
  const { reset: resetQira } = useQiraReactions();
  const [page, setPage] = useState("landing");
  // Simple cross-page scratch state so e.g. Encrypt can hand off a
  // record_id to Decrypt, or Create Intent can hand off a CID.
  const [shared, setShared] = useState({});
  const [accessReady, setAccessReady] = useState(
    () => sessionStorage.getItem("ibqc_security_access_consent") === "allow"
  );

  // Combines the React auth state with the persisted-token fallback above.
  // Recomputed on every render, so as soon as `token` itself catches up
  // this collapses back to being exactly `isAuthenticated`.
  const authedForRouting = isAuthenticated || hasPersistedAuthToken();

  // Logout must return to the public landing page and clear cross-page state
  // in the same render cycle. QIRA's presentation state is reset with it.
  const handleLogout = () => {
    logout();
    setShared({});
    setAccessReady(false);
    setPage("landing");
    resetQira();
  };

  useEffect(() => {
    if (!authedForRouting) resetQira();
  }, [authedForRouting, resetQira]);

  const navigate = (p, extra) => {
    const authedNow = isAuthenticated || hasPersistedAuthToken();
    if (!authedNow && !PUBLIC_PAGES.includes(p)) {
      setPage("landing");
      return;
    }
    // LoginPage completes face verification and then grants the
    // application-level access consent. Sync the shell immediately so
    // the consent gate is not shown a second time after navigation.
    if (sessionStorage.getItem("ibqc_security_access_consent") === "allow") {
      setAccessReady(true);
    }
    if (extra) setShared((prev) => ({ ...prev, ...extra }));
    setPage(p);
  };

  const showShell = authedForRouting && !!user && !PUBLIC_PAGES.includes(page);

  // QIRA page context + navigation acknowledgement (presentation only; no routing change).
  const qiraInApp = showShell && accessReady;
  useEffect(() => {
    if (!qiraInApp) return undefined;
    qiraEngine.setContext(page === "bb84" ? "quantum" : null); // Quantum Lab = engineering mode
    emitQira(QIRA_PAGE_REACTION[page] || "nav.page");
    return () => qiraEngine.setContext(null);
  }, [qiraInApp, page]);

  if (!showShell) {
    // A logged-in navigation target (page is not landing/login/register)
    // while `user` hasn't caught up to the persisted token yet is a brief
    // in-flight transition, not an unauthenticated visitor — show a
    // lightweight loading state instead of bouncing back to marketing
    // Landing Page copy (which was the reported "must click Go to
    // Dashboard again" bug). This resolves itself on the very next render
    // once `useAuth`'s state settles; it is never a substitute for real
    // authorization, which the backend enforces on every request.
    if (authedForRouting && !PUBLIC_PAGES.includes(page)) {
      return (
        <div className="app-root min-h-screen flex items-center justify-center cq-matte-obsidian bg-cq-background text-cq-on-surface-variant text-[13.5px]">
          Loading your dashboard…
        </div>
      );
    }

    return (
      <div className="app-root">
        <Suspense fallback={<div className="app-root">Loading page…</div>}>
          {page === "landing" && <LandingPage navigate={navigate} isAuthenticated={authedForRouting} />}
          {(page === "login" || page === "register") && (
            <LoginPage
              mode={page}
              saveAuth={saveAuth}
              logout={handleLogout}
              navigate={navigate}
              deviceId={deviceId}
              sessionId={sessionId}
            />
          )}
        </Suspense>
      </div>
    );
  }

  if (!accessReady) {
    return (
      <SecurityTelemetryConsent
        onDecision={(decision) => {
          if (decision === "allow") {
            setAccessReady(true);
          } else {
            handleLogout();
            setPage("login");
          }
        }}
      />
    );
  }

  return (
    <MonitoringProvider user={user} deviceId={deviceId} sessionId={sessionId}>
      <QiraProvider>
        <QiraEventBridge />
        <AppShell page={page} navigate={navigate} user={user} logout={handleLogout}>
          <Suspense fallback={<div className="flex min-h-[40vh] items-center justify-center">Loading page…</div>}>
            {page === "dashboard" && <Dashboard navigate={navigate} user={user} />}
            {page === "create-intent" && <CreateIntentPage navigate={navigate} shared={shared} user={user} />}
            {page === "intent-history" && <IntentHistoryPage navigate={navigate} shared={shared} user={user} />}
            {page === "bb84" && <BB84SimulationPage navigate={navigate} shared={shared} />}
            {page === "encrypt" && <EncryptionPage navigate={navigate} shared={shared} user={user} />}
            {page === "decrypt" && <DecryptionPage navigate={navigate} shared={shared} user={user} />}
            {page === "sharing" && <ShareMessagesPage user={user} shared={shared} navigate={navigate} />}
            {page === "direct-messages" && <DirectMessagesPage user={user} />}
            {page === "audit" && <AuditLogsPage navigate={navigate} />}
            {page === "policies" && <PolicyManagementPage navigate={navigate} />}
            {page === "visualize" && <VisualizationPage navigate={navigate} />}
            {page === "settings" && <SettingsPage navigate={navigate} user={user} />}
            {page === "profile" && <ProfilePage navigate={navigate} user={user} />}
            {page === "face-test" && <FaceAuthTestPage navigate={navigate} />}
            {page === "admin" && <AdminDashboard user={user} />}
          </Suspense>
        </AppShell>
        {/* Qira floats above every authenticated page — it reads the
            SAME shared QiraContext decision every other consumer
            (topbar badge, dashboard card) reads, so they can never
            contradict each other (Part 4). */}
        <QiraWidget user={user} />
      </QiraProvider>
    </MonitoringProvider>
  );
}


/** QIRA is presentation-only and remains present on public and authenticated pages. */
export default function App() {
  return (
    <QiraReactionProvider>
      <AppContent />
      <QiraDock />
    </QiraReactionProvider>
  );
}
