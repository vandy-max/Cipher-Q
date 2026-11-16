// Presentation-only observer (registered by src/qira/index.js). It only RECEIVES facts about
// transport outcomes; it cannot alter a request or a response, and a failure in it is swallowed.
let apiObserver = null;
export function setApiObserver(fn) { apiObserver = typeof fn === "function" ? fn : null; }
function observe(event) { try { apiObserver?.(event); } catch { /* presentation only */ } }

const BASE = "/api";

class ApiError extends Error {
  constructor(status, detail, body) {
    super(typeof detail === "string" ? detail : JSON.stringify(detail));
    this.status = status;
    this.detail = detail;
    this.body = body;
  }
}

function getToken() {
  return localStorage.getItem("ibqc_token");
}

async function request(path, { method = "GET", body, auth = true, timeoutMs } = {}) {
  const headers = { "Content-Type": "application/json" };
  if (auth) {
    const token = getToken();
    if (token) headers.Authorization = `Bearer ${token}`;
  }

  const controller = timeoutMs ? new AbortController() : null;
  const timeoutId = controller ? setTimeout(() => controller.abort(), timeoutMs) : null;
  try {
    const res = await fetch(`${BASE}${path}`, {
      method,
      headers,
      body: body !== undefined ? JSON.stringify(body) : undefined,
      signal: controller?.signal,
    });

    // QIRA (presentation only): a response proves the backend is reachable; a 5xx or a network
    // failure is "unavailable", never a security denial. Does not alter the request/response.
    observe({ kind: "response", status: res.status });

    if (res.status === 204) return null;

    let data = null;
    const text = await res.text();
    if (text) {
      try {
        data = JSON.parse(text);
      } catch {
        data = text;
      }
    }

    if (!res.ok) {
      throw new ApiError(res.status, data?.detail ?? data ?? res.statusText, data);
    }
    return data;
  } catch (error) {
    observe({ kind: "error", error });
    if (controller?.signal.aborted) {
      throw new ApiError(0, "Key-session request timed out. Check your key-session list before trying again.", {
        code: "REQUEST_TIMEOUT",
      });
    }
    throw error;
  } finally {
    if (timeoutId !== null) clearTimeout(timeoutId);
  }
}

// ---------------------------------------------------------------------
// Auth
// ---------------------------------------------------------------------
// `role` is optional and, when sent, may only be "USER_LEVEL_1" or
// "USER_LEVEL_2" — the backend rejects/ignores anything else (including
// "ADMIN"). Admin accounts are never created through this endpoint.
export const register = (username, email, password, role) =>
  request("/auth/register", {
    method: "POST",
    body: { username, email, password, ...(role ? { role } : {}) },
    auth: false,
  });

export const login = (username, password) =>
  request("/auth/login", { method: "POST", body: { username, password }, auth: false });

// ---------------------------------------------------------------------
// Identity: face enrolment + challenge-bound step-up.
// The server compares descriptors; liveness is NOT established by this
// prototype (similarity only). No client-reported confidence is trusted.
// ---------------------------------------------------------------------
export const enrollFace = (descriptor, password, sessionId) =>
  request("/face/enroll", {
    method: "POST",
    body: { descriptor, password, ...(sessionId ? { session_id: sessionId } : {}) },
  });

export const faceStatus = () => request("/face/status");

export const issueStepUpChallenge = (sessionId) =>
  request("/identity/challenges", { method: "POST", body: { session_id: sessionId } });

export const verifyStepUp = (challengeId, sessionId, descriptor) =>
  request("/identity/verify", {
    method: "POST",
    body: { challenge_id: challengeId, session_id: sessionId, descriptor },
  });

// One call: fetch a single-use challenge, then answer it.
export async function stepUp(sessionId, descriptor) {
  const ch = await issueStepUpChallenge(sessionId);
  return verifyStepUp(ch.challenge_id, sessionId, descriptor);
}

// ---------------------------------------------------------------------
// Key sessions (BB84 SIMULATION — not physical QKD). The raw key never
// leaves the server; the client only receives an opaque key_session_id.
// ---------------------------------------------------------------------
export const createKeySession = (nQubits, simulateEavesdropperProb = 0) =>
  request("/key-sessions", {
    method: "POST",
    timeoutMs: 120_000,
    body: {
      ...(nQubits ? { n_qubits: nQubits } : {}),
      simulate_eavesdropper_prob: simulateEavesdropperProb,
    },
  });
export const listKeySessions = () => request("/key-sessions");
export const getKeySession = (id) => request(`/key-sessions/${id}`);
export const revokeKeySession = (id) => request(`/key-sessions/${id}/revoke`, { method: "POST" });
export const rotateKeySession = (id, nQubits, simulateEavesdropperProb = 0) =>
  request(`/key-sessions/${id}/rotate`, {
    method: "POST",
    body: {
      ...(nQubits ? { n_qubits: nQubits } : {}),
      simulate_eavesdropper_prob: simulateEavesdropperProb,
    },
  });
export const rewrapKeySession = (id, toKeySessionId) =>
  request(`/key-sessions/${id}/rewrap`, { method: "POST", body: { to_key_session_id: toKeySessionId } });

export const quantumBackendInfo = () => request("/quantum/info", { auth: false });

// ---------------------------------------------------------------------
// Intents v2 (structured, versioned, approval-gated)
// ---------------------------------------------------------------------
export const createIntent = (payload) => request("/intents", { method: "POST", body: payload });
export const listIntents = () => request("/intents");
export const getIntent = (id) => request(`/intents/${id}`);
export const createIntentVersion = (id, payload) =>
  request(`/intents/${id}/versions`, { method: "POST", body: payload });
export const validateIntent = (id) => request(`/intents/${id}/validate`, { method: "POST" });
export const approveIntent = (id, version, verdict = "APPROVE", comment = "") =>
  request(`/intents/${id}/approvals`, { method: "POST", body: { version, verdict, comment } });
export const withdrawApproval = (id) => request(`/intents/${id}/withdraw-approval`, { method: "POST" });
export const revokeIntent = (id, reason) =>
  request(`/intents/${id}/revoke`, { method: "POST", body: { reason } });

// ---------------------------------------------------------------------
// Authorization decisions + crypto operations bound to them.
// A decision yields a single-use crypto context; if anything relevant
// changes afterwards the context is rejected (CONTEXT_STALE etc.).
// ---------------------------------------------------------------------
export const requestDecision = (payload) => request("/decisions", { method: "POST", body: payload });
export const getDecision = (id) => request(`/decisions/${id}`);
export const revokeDecision = (id, reason) =>
  request(`/decisions/${id}/revoke`, { method: "POST", body: { reason } });

export const encryptWithContext = (payload) => request("/crypto/encrypt", { method: "POST", body: payload });
export const decryptWithContext = (payload) => request("/crypto/decrypt", { method: "POST", body: payload });
export const listRecords = () => request("/crypto/records");
export const getRecord = (id) => request(`/crypto/records/${id}`);

// ---------------------------------------------------------------------
// Evidence cases (local evidence provider; admin-managed)
// ---------------------------------------------------------------------
export const listCases = (limit = 50, offset = 0) =>
  request(`/evidence/cases?limit=${limit}&offset=${offset}`);
export const getCase = (ref) => request(`/evidence/cases/${encodeURIComponent(ref)}`);
export const putCase = (ref, body) =>
  request(`/evidence/cases/${encodeURIComponent(ref)}`, { method: "PUT", body });
export const closeCase = (ref) => request(`/evidence/cases/${encodeURIComponent(ref)}/close`, { method: "POST" });
export const assignCase = (ref, userId) =>
  request(`/evidence/cases/${encodeURIComponent(ref)}/assign`, { method: "POST", body: { user_id: userId } });
export const unassignCase = (ref, userId) =>
  request(`/evidence/cases/${encodeURIComponent(ref)}/unassign`, { method: "POST", body: { user_id: userId } });

// ---------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------
export const listAuditLogs = () => request("/audit/logs");
export const verifyAuditChain = () => request("/audit/verify");

// ---------------------------------------------------------------------
// Policies
// ---------------------------------------------------------------------
export const listPolicies = () => request("/policies");
export const createPolicy = (name, ruleType, config, active) =>
  request("/policies", { method: "POST", body: { name, rule_type: ruleType, config, active } });
export const updatePolicy = (id, name, ruleType, config, active) =>
  request(`/policies/${id}`, { method: "PUT", body: { name, rule_type: ruleType, config, active } });
export const deletePolicy = (id) => request(`/policies/${id}`, { method: "DELETE" });

// ---------------------------------------------------------------------
// Risk
// ---------------------------------------------------------------------
export const assessRisk = (factors) =>
  request("/risk/assess", { method: "POST", body: factors });

// ---------------------------------------------------------------------
// Authorization (devices / sessions — continuous authorization)
// ---------------------------------------------------------------------
export const getDeviceStatus = (deviceId) => request(`/authorization/devices/${deviceId}`);
export const getDeviceTrust = (deviceId) => request(`/authorization/devices/${deviceId}/trust`);
export const revokeDevice = (deviceId) =>
  request(`/authorization/devices/${deviceId}/revoke`, { method: "POST" });
export const unrevokeDevice = (deviceId) =>
  request(`/authorization/devices/${deviceId}/unrevoke`, { method: "POST" });
export const getSessionStatus = (sessionId) => request(`/authorization/sessions/${sessionId}`);
export const revokeSession = (sessionId) =>
  request(`/authorization/sessions/${sessionId}/revoke`, { method: "POST" });
export const registerDevice = () => request("/authorization/devices", { method: "POST" });
export const createAuthSession = (deviceId, ttlMinutes) =>
  request("/authorization/sessions", {
    method: "POST",
    body: { device_id: deviceId, ...(ttlMinutes ? { ttl_minutes: ttlMinutes } : {}) },
  });
export const refreshSession = (sessionId, deviceId, ttlMinutes = 60) =>
  request(`/authorization/sessions/${sessionId}/refresh`, {
    method: "POST",
    body: { device_id: deviceId, ttl_minutes: ttlMinutes },
  });

// ---------------------------------------------------------------------
// Trusted location / geofence
// ---------------------------------------------------------------------
export const getTrustedLocation = () => request("/location/trust");
export const enrollTrustedLocation = (latitude, longitude, accuracyM) =>
  request("/location/trust", {
    method: "POST",
    body: { latitude, longitude, accuracy_m: accuracyM },
  });
export const clearTrustedLocation = () => request("/location/trust", { method: "DELETE" });
export const checkLocation = (latitude, longitude, accuracyM, radiusM) =>
  request("/location/check", {
    method: "POST",
    body: { latitude, longitude, accuracy_m: accuracyM, radius_m: radiusM },
  });

// The ONLY way to restore a revoked session: a challenge-bound step-up.
export const reauthenticateSession = (
  sessionId,
  deviceId,
  challengeId,
  faceDescriptor,
  ttlMinutes = 60,
  reauthRequestId = null
) =>
  request(`/authorization/sessions/${sessionId}/reauthenticate`, {
    method: "POST",
    body: {
      device_id: deviceId,
      challenge_id: challengeId,
      face_descriptor: faceDescriptor,
      ttl_minutes: ttlMinutes,
      ...(reauthRequestId != null ? { reauth_request_id: reauthRequestId } : {}),
    },
  });

// ---------------------------------------------------------------------
// Continuous monitoring
// ---------------------------------------------------------------------
// Requires a fresh server-side step-up grant; no confidence is sent.
export const startMonitoring = (deviceId, sessionId, intentId) =>
  request("/monitoring/start", {
    method: "POST",
    body: { device_id: deviceId, session_id: sessionId, ...(intentId != null ? { intent_id: intentId } : {}) },
  });

// prevNonce must echo the nonce returned by the previous response.
// probeDescriptor is compared server-side; presence/camera flags can only
// make a tick fail, never pass.
export const monitoringHeartbeat = (
  monitoringSessionId,
  prevNonce,
  { facePresent, probeDescriptor = null, cameraAvailable = true, expressionHint = null }
) =>
  request("/monitoring/heartbeat", {
    method: "POST",
    body: {
      monitoring_session_id: monitoringSessionId,
      prev_nonce: prevNonce,
      probe_descriptor: probeDescriptor,
      face_present: facePresent,
      camera_available: cameraAvailable,
      expression_hint: expressionHint,
    },
  });

export const getMonitoringStatus = (monitoringSessionId) =>
  request(`/monitoring/${monitoringSessionId}`);

export const getMonitoringForSession = (sessionId) =>
  request(`/monitoring/by-session/${encodeURIComponent(sessionId)}`);

export const listMonitoringEvents = (monitoringSessionId) =>
  request(`/monitoring/${monitoringSessionId}/events`);

// ADMIN only: session-level summaries (active + finished) for the admin dashboard.
export const listMonitoringSessions = ({ limit = 100, activeOnly = false } = {}) =>
  request(`/monitoring/admin/sessions?limit=${limit}&active_only=${activeOnly}`);

export const stopMonitoring = (monitoringSessionId) =>
  request(`/monitoring/${monitoringSessionId}/stop`, { method: "POST" });

// ---------------------------------------------------------------------
// Admin: users & roles
// ---------------------------------------------------------------------
export const listUsers = () => request("/users");
export const updateUserRole = (userId, role) =>
  request(`/users/${userId}/role`, { method: "PUT", body: { role } });

export const disableUser = (userId) => request(`/users/${userId}/disable`, { method: "POST" });
export const enableUser = (userId) => request(`/users/${userId}/enable`, { method: "POST" });
export const unlockUser = (userId) => request(`/users/${userId}/unlock`, { method: "POST" });
export const resetFaceEnrollment = (userId) => request(`/face/enrollment/${userId}`, { method: "DELETE" });

export const getUserRiskOverview = () => request("/security/risk-overview");

// ---------------------------------------------------------------------
// Qira — CipherQ Security Copilot
// ---------------------------------------------------------------------
export const getSecurityContext = (monitoringSessionId, locationPermissionState) =>
  request(
    `/security/context?monitoring_session_id=${encodeURIComponent(monitoringSessionId)}` +
      (locationPermissionState
        ? `&location_permission_state=${encodeURIComponent(locationPermissionState)}`
        : "")
  );

export const assessSecurity = (monitoringSessionId, locationPermissionState) =>
  request("/security/assess", {
    method: "POST",
    body: {
      monitoring_session_id: monitoringSessionId,
      location_permission_state: locationPermissionState ?? undefined,
    },
  });

export const askQira = (monitoringSessionId, question) =>
  request("/security/ask", {
    method: "POST",
    body: { monitoring_session_id: monitoringSessionId, question },
  });

// Admin-only: security incidents queue (Qira Part 13/14).
export const listSecurityIncidents = (resolved) =>
  request(`/security/incidents${resolved === undefined ? "" : `?resolved=${resolved}`}`);

export const resolveSecurityIncident = (incidentId, note) =>
  request(`/security/incidents/${incidentId}/resolve`, {
    method: "POST",
    body: { note },
  });

// ---------------------------------------------------------------------
// Reauthorization requests — the in-app path for a user whose DEVICE
// (not just session) was revoked by continuous monitoring. Normal
// `reauthenticateSession` above deliberately refuses to fix that case
// on its own (see authorization/reauth_requests.py); this is the
// escalation path to an admin instead.
// ---------------------------------------------------------------------
export const createReauthRequest = (deviceId, sessionId, message) =>
  request("/reauth-requests", {
    method: "POST",
    body: { device_id: deviceId, session_id: sessionId, message },
  });

// The user's own request history, newest first — used to poll for
// the admin's decision without needing a dedicated push channel.
export const listMyReauthRequests = () => request("/reauth-requests/mine");

// Admin-only: the full queue, optionally filtered to one status.
export const listReauthRequests = (statusFilter) =>
  request(`/reauth-requests${statusFilter ? `?status=${encodeURIComponent(statusFilter)}` : ""}`);

export const approveReauthRequest = (requestId, note) =>
  request(`/reauth-requests/${requestId}/approve`, { method: "POST", body: { note: note || null } });

export const rejectReauthRequest = (requestId, note) =>
  request(`/reauth-requests/${requestId}/reject`, { method: "POST", body: { note: note || null } });

export { ApiError };

// ---------------------------------------------------------------------
// Phase 2 — recipient-bound sharing (backend remains authoritative)
// ---------------------------------------------------------------------
export const listShareRecipients = (q = "") =>
  request(`/crypto/recipients${q ? `?q=${encodeURIComponent(q)}` : ""}`);
export const openShare = (shareId, sessionId) =>
  request(`/crypto/shares/${encodeURIComponent(shareId)}/open`, { method: "POST", body: { session_id: sessionId } });
export const listShares = () => request("/crypto/shares");
export const createShare = (payload) => request("/crypto/shares", { method: "POST", body: payload });
export const activateShare = (shareId, sessionId, deviceId) =>
  request(`/crypto/shares/${encodeURIComponent(shareId)}/activate`, {
    method: "POST", body: { session_id: sessionId, device_id: deviceId },
  });
export const reactToShare = (shareId, reaction) =>
  request(`/crypto/shares/${encodeURIComponent(shareId)}/reaction`, { method: "POST", body: { reaction } });
export const listShareMessages = (shareId, sessionId, deviceId) =>
  request(`/crypto/shares/${encodeURIComponent(shareId)}/messages?session_id=${encodeURIComponent(sessionId)}&device_id=${encodeURIComponent(deviceId)}`);
export const sendShareMessage = (shareId, sessionId, deviceId, text) =>
  request(`/crypto/shares/${encodeURIComponent(shareId)}/messages`, {
    method: "POST", body: { session_id: sessionId, device_id: deviceId, text },
  });
export const rejectShare = (shareId, reason = "Recipient declined") =>
  request(`/crypto/shares/${encodeURIComponent(shareId)}/reject`, { method: "POST", body: { reason } });
export const revokeShare = (shareId, reason = "Sender revoked access") =>
  request(`/crypto/shares/${encodeURIComponent(shareId)}/revoke`, { method: "POST", body: { reason } });
export const listPendingShareApprovals = () => request("/crypto/shares/admin/pending");
export const adminApproveShare = (shareId) =>
  request(`/crypto/shares/${encodeURIComponent(shareId)}/admin-approve`, { method: "POST" });

// Simple direct messaging: authenticated sender/recipient, automatic AES-GCM encryption,
// no per-message intent selection or face step-up. Attachments are limited by the UI/API to 1 MiB.
export const listDirectMessageRecipients = (q = "") =>
  request(`/messages/recipients${q ? `?q=${encodeURIComponent(q)}` : ""}`);
export const listDirectMessages = (folder = "inbox") =>
  request(`/messages?folder=${encodeURIComponent(folder)}`);
export const createDirectMessage = (payload) =>
  request("/messages", { method: "POST", body: payload });
export const decryptDirectMessage = (messageId) =>
  request(`/messages/${encodeURIComponent(messageId)}/decrypt`, { method: "POST" });
export const revokeDirectMessage = (messageId) =>
  request(`/messages/${encodeURIComponent(messageId)}/revoke`, { method: "POST", body: { reason: "Sender revoked access" } });
