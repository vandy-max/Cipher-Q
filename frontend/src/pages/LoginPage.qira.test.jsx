import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, screen, fireEvent, act, waitFor } from "@testing-library/react";

const api = vi.hoisted(() => ({ login: vi.fn(), register: vi.fn(), faceStatus: vi.fn(), setApiObserver: vi.fn() }));
vi.mock("../services/api", () => api);
vi.mock("../components/face/FaceAuthPanel", () => ({ default: () => <div data-testid="face" /> }));
vi.mock("../components/security/SecurityTelemetryConsent", () => ({ default: () => <div /> }));
vi.mock("../components/quantum/QuantumField", () => ({ default: () => null }));

import LoginPage from "./LoginPage";
import { qiraEngine } from "../qira";

let base = 0;
const hist = () => qiraEngine.getHistory().slice(base).map((h) => h.id);
const mountPage = (mode) => render(<LoginPage mode={mode} saveAuth={vi.fn()} logout={vi.fn()} navigate={vi.fn()} deviceId="d" sessionId="s" />);
const F = (name) => document.querySelector(`[data-qira-field="${name}"]`);
const fill = (label, value) => fireEvent.change(F(String(label).includes("email") ? "email" : String(label).includes("password") ? "password" : "username"), { target: { value } });
const form = () => F("username").closest("form");

beforeEach(() => {
  vi.clearAllMocks();
  qiraEngine.reset();
  base = qiraEngine.getHistory().length;
  sessionStorage.clear();
});

describe("LoginPage -> QIRA (real events only)", () => {
  it("page open: login waves, register is excited", () => {
    const a = mountPage("login");
    expect(hist()).toContain("login.welcome");
    a.unmount();
    mountPage("register");
    expect(hist()).toContain("register.page");
  });

  it("field focus reacts; the password value is never part of any QIRA event", () => {
    mountPage("register");
    fireEvent.focus(F("username"));
    expect(hist()).toContain("field.username.register");
    fireEvent.focus(F("email"));
    expect(hist()).toContain("field.email");
    fill(/^password/i, "S3cret-VALUE-12345");
    const dump = JSON.stringify(qiraEngine.getHistory()) + JSON.stringify(qiraEngine.getSnapshot());
    expect(dump).not.toContain("S3cret-VALUE-12345");
  });

  it("login: processing -> credentials accepted ONLY after the API resolves", async () => {
    let resolve;
    api.login.mockReturnValue(new Promise((r) => { resolve = r; }));
    api.faceStatus.mockResolvedValue({ enrolled: true });
    mountPage("login");
    fill(/username/i, "alice"); fill(/^password/i, "correct-horse-battery");
    fireEvent.submit(form());
    await waitFor(() => expect(hist()).toContain("login.processing"));
    expect(hist()).not.toContain("login.credentialsOk"); // API has not answered yet
    await act(async () => { resolve({ token: "t" }); });
    await waitFor(() => expect(hist()).toContain("login.credentialsOk"));
  });

  it("invalid credentials -> concerned; repeated failures -> double-check message; no raw error text", async () => {
    api.login.mockRejectedValue(Object.assign(new Error("SECRET_BACKEND_TRACE jwt=abc"), { status: 401, detail: "bad" }));
    mountPage("login");
    fill(/username/i, "alice"); fill(/^password/i, "wrong-password-1");
    for (let i = 0; i < 3; i++) { await act(async () => { fireEvent.submit(form()); }); qiraEngine.trigger("nav.page"); }
    expect(hist()).toContain("login.invalid");
    expect(hist()).toContain("login.repeated");
    const dump = JSON.stringify(qiraEngine.getHistory()) + JSON.stringify(qiraEngine.getSnapshot());
    expect(dump).not.toMatch(/SECRET_BACKEND_TRACE|jwt=abc/);
  });

  it("network failure is 'trouble connecting', never an authentication failure", async () => {
    api.login.mockRejectedValue(new TypeError("Failed to fetch"));
    mountPage("login");
    fill(/username/i, "alice"); fill(/^password/i, "whatever-pass-1");
    await act(async () => { fireEvent.submit(form()); });
    expect(hist()).toContain("net.error");
    expect(hist()).not.toContain("login.invalid");
  });

  it("registration: success only after the API confirms; failure is concerned", async () => {
    api.register.mockResolvedValue({ token: "t" });
    api.faceStatus.mockResolvedValue({ enrolled: false });
    mountPage("register");
    fill(/username/i, "newbie"); fill(/email/i, "n@x.io"); fill(/^password/i, "a-long-enough-pass");
    await act(async () => { fireEvent.submit(form()); });
    expect(hist()).toContain("register.processing");
    expect(hist()).toContain("register.success");
  });

  it("registration failure is concerned", async () => {
    api.register.mockRejectedValue(Object.assign(new Error("x"), { status: 409 }));
    mountPage("register");
    fill(/username/i, "newbie"); fill(/email/i, "n@x.io"); fill(/^password/i, "a-long-enough-pass");
    await act(async () => { fireEvent.submit(form()); });
    expect(hist()).toContain("register.failed");
    expect(hist()).not.toContain("register.success");
  });

  it("browser validation results map to hints (observed, not re-implemented)", () => {
    mountPage("register");
    const email = F("email");
    Object.defineProperty(email, "validity", { value: { valueMissing: false, typeMismatch: true, tooShort: false }, configurable: true });
    fireEvent.invalid(email);
    expect(hist()).toContain("register.invalidEmail");
  });
});
