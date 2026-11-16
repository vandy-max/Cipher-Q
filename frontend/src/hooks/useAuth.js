import { useState, useCallback } from "react";
import { stopMonitoring, registerDevice, createAuthSession } from "../services/api";

// Device and session identifiers are issued by the SERVER and bound to the
// authenticated account. The client only remembers them; it never invents them.
async function getOrCreateDeviceIdForUser(userId) {
  const key = `ibqc_device_id_${userId}`;
  let id = localStorage.getItem(key);
  if (id) return id;
  const res = await registerDevice();
  id = res.device_id;
  localStorage.setItem(key, id);
  return id;
}

export function useAuth() {
  const [token, setToken] = useState(() => localStorage.getItem("ibqc_token"));
  const [user, setUser] = useState(() => {
    try {
      return JSON.parse(localStorage.getItem("ibqc_user") || "null");
    } catch {
      return null;
    }
  });
  const [deviceId, setDeviceId] = useState(() => {
    const savedUser = (() => {
      try { return JSON.parse(localStorage.getItem("ibqc_user") || "null"); } catch { return null; }
    })();
    return savedUser?.userId ? localStorage.getItem(`ibqc_device_id_${savedUser.userId}`) : null;
  });
  const [sessionId, setSessionId] = useState(() => localStorage.getItem("ibqc_session_id"));

  const saveAuth = useCallback(async (authResult) => {
    const u = {
      userId: authResult.user_id,
      username: authResult.username,
      role: authResult.role,
    };
    // The token must be stored before the first authenticated call.
    localStorage.setItem("ibqc_token", authResult.token);
    let userDeviceId = null;
    let newSessionId = null;
    try {
      userDeviceId = await getOrCreateDeviceIdForUser(u.userId);
      newSessionId = (await createAuthSession(userDeviceId)).session_id;
    } catch (err) {
      // A stale stored device id (e.g. revoked/unknown) is discarded and re-issued once.
      localStorage.removeItem(`ibqc_device_id_${u.userId}`);
      userDeviceId = await getOrCreateDeviceIdForUser(u.userId);
      newSessionId = (await createAuthSession(userDeviceId)).session_id;
    }

    localStorage.setItem("ibqc_user", JSON.stringify(u));
    localStorage.setItem("ibqc_session_id", newSessionId);
    // Remove the legacy browser-global device key so old test state cannot
    // leak into this account-scoped device identity.
    localStorage.removeItem("ibqc_device_id");

    setToken(authResult.token);
    setUser(u);
    setDeviceId(userDeviceId);
    setSessionId(newSessionId);
  }, []);

  const logout = useCallback(() => {
    // Start the backend stop request while the bearer token is still present,
    // but never block navigation on network latency. The UI/session is cleared
    // synchronously so the landing page and public QIRA state render immediately.
    const monitoringSessionId = sessionStorage.getItem("ibqc_monitoring_session_id");
    if (monitoringSessionId) {
      try {
        Promise.resolve(stopMonitoring(monitoringSessionId)).catch(() => {});
      } catch {
        // Best effort only; local logout must always complete.
      }
    }
    sessionStorage.removeItem("ibqc_monitoring_session_id");
    localStorage.removeItem("ibqc_token");
    localStorage.removeItem("ibqc_user");
    localStorage.removeItem("ibqc_session_id");
    sessionStorage.removeItem("ibqc_security_access_consent");
    sessionStorage.removeItem("ibqc_face_verified_this_login");
    sessionStorage.removeItem("ibqc_pending_monitoring_face_confidence");
    sessionStorage.removeItem("ibqc_heartbeat_nonce");
    setToken(null);
    setUser(null);
    setDeviceId(null);
    setSessionId(null);
  }, []);

  return { token, user, deviceId, sessionId, saveAuth, logout, isAuthenticated: !!token };
}
