"""Quantum (BB84 *simulation*) abuse + failure handling."""
import dataclasses
import threading

import pytest

from config import get_settings
from security.ratelimit import ConcurrencyGate


def test_excessive_qubits_rejected(user):
    for n in (10**6, 8193, 63, 0, -5):
        assert user.post("/api/key-sessions", {"n_qubits": n}).status_code == 422, n


def test_invalid_qber_configuration_rejected(user):
    for p in (-0.1, 1.1, 2, "x"):
        assert user.post("/api/key-sessions", {"simulate_eavesdropper_prob": p}).status_code == 422, p
    r = user.client.post("/api/key-sessions", headers={**user.h, "Content-Type": "application/json"},
                         content='{"simulate_eavesdropper_prob": NaN}')
    assert r.status_code in (400, 422)


def test_client_cannot_choose_key_material(user):
    for k in ("key", "quantum_key", "quantum_key_hex", "seed", "bits"):
        assert user.post("/api/key-sessions", {k: "00" * 32}).status_code == 422, k


def test_eavesdropping_is_detected_and_no_key_established(user):
    r = user.post("/api/key-sessions", {"simulate_eavesdropper_prob": 1.0})
    assert r.status_code == 409
    j = r.json()
    assert j["status"] == "ABORTED_QBER" and j["qber"] > 0.11
    assert "key" not in {k for k in j if k.endswith("_hex") or k == "quantum_key"}
    # the aborted session cannot be used for anything
    got = user.get(f"/api/key-sessions/{j['key_session_id']}").json()
    assert got["status"] == "ABORTED_QBER"


def test_clean_exchange_reports_entropy_and_simulation_notice(user):
    r = user.post("/api/key-sessions", {})
    assert r.status_code == 201
    j = r.json()
    assert j["status"] == "ACTIVE" and j["qber"] < 0.11 and j["effective_entropy_bits"] >= 128
    assert j["simulation"] is True and "not physical QKD" in j["notice"]
    assert not any(k in j for k in ("quantum_key", "quantum_key_hex", "key", "key_bytes"))


def test_insufficient_sifted_material_rejected(user):
    r = user.post("/api/key-sessions", {"n_qubits": 64})
    assert r.status_code == 409
    assert r.json()["status"] in ("INSUFFICIENT_KEY", "NO_SIFTED_BITS")


def test_attack_simulation_disabled_in_deployment(user, monkeypatch):
    import api.routers.key_sessions as ks
    st = dataclasses.replace(get_settings(), allow_attack_simulation=False)
    monkeypatch.setattr(ks, "get_settings", lambda: st)
    assert user.post("/api/key-sessions", {"simulate_eavesdropper_prob": 0.5}).status_code == 403
    assert user.post("/api/key-sessions", {}).status_code == 201


def test_per_user_quota(user, monkeypatch):
    import api.routers.key_sessions as ks
    st = dataclasses.replace(get_settings(), quantum_per_user_per_hour=2)
    monkeypatch.setattr(ks, "get_settings", lambda: st)
    codes = [user.post("/api/key-sessions", {}).status_code for _ in range(4)]
    assert codes[:2] == [201, 201] and codes[2:] == [429, 429]


def test_concurrency_gate_sheds_load(user, monkeypatch):
    import api.routers.key_sessions as ks
    gate = ConcurrencyGate(1)
    monkeypatch.setattr(ks, "_gate", gate)
    assert gate.try_acquire()                     # a long-running exchange occupies the only slot
    r = user.post("/api/key-sessions", {})
    assert r.status_code == 503 and r.headers.get("Retry-After")
    gate.release()
    assert user.post("/api/key-sessions", {}).status_code == 201


def test_concurrent_expensive_requests_are_bounded(make_user, monkeypatch):
    import api.routers.key_sessions as ks
    monkeypatch.setattr(ks, "_gate", ConcurrencyGate(2))
    users = [make_user() for _ in range(6)]
    out = []
    def go(u):
        out.append(u.post("/api/key-sessions", {"n_qubits": 2048}).status_code)
    ts = [threading.Thread(target=go, args=(u,)) for u in users]
    [t.start() for t in ts]; [t.join() for t in ts]
    assert set(out) <= {201, 503} and 201 in out


def test_unauthenticated_cannot_create_key_session(client):
    assert client.post("/api/key-sessions", json={}).status_code == 401


def test_quantum_info_is_public_and_has_no_key_material(client):
    r = client.get("/api/quantum/info")
    assert r.status_code == 200
    t = r.text.lower()
    assert "quantum_key" not in t and "disclaimer" in t or "simulat" in t


def test_bb84_unit_entropy_accounting_and_abort():
    from quantum.bb84 import STATUS_OK, simulate_bb84 as run_bb84
    ok = run_bb84(n_qubits=1024, eavesdrop_prob=0.0)
    assert ok.status == STATUS_OK and ok.effective_entropy_bits >= 128 and ok.qber < 0.11
    bad = run_bb84(n_qubits=1024, eavesdrop_prob=1.0)
    assert bad.status != STATUS_OK
    with pytest.raises(ValueError):
        run_bb84(n_qubits=10**7, eavesdrop_prob=0.0, max_qubits=2048)
    with pytest.raises(ValueError):
        run_bb84(n_qubits=1024, eavesdrop_prob=1.5)
