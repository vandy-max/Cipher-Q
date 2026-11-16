// Behavioural tests for the Secure Sharing page (jsdom, API mocked). Not part of `npm test` (node:test).
//   npm i --no-save vitest@2 jsdom@24 @testing-library/react@14
//   npx vitest run --environment jsdom tests/share-page.spec.jsx   (needs esbuild jsx=automatic; see report)
import React from "react";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const api = vi.hoisted(() => ({
  listIntents: vi.fn(), listKeySessions: vi.fn(), listShareRecipients: vi.fn(), listShares: vi.fn(), createShare: vi.fn(),
  openShare: vi.fn(), activateShare: vi.fn(), rejectShare: vi.fn(), revokeShare: vi.fn(), listPendingShareApprovals: vi.fn(),
  adminApproveShare: vi.fn(), requestDecision: vi.fn(), encryptWithContext: vi.fn(), decryptWithContext: vi.fn(),
}));
vi.mock("../src/services/api", () => api);
vi.mock("../src/context/MonitoringContext", () => ({ useMonitoringContext: () => ({ deviceId: "dev", sessionId: "sess", reauthRequired: false }) }));
vi.mock("../src/components/face/FaceAuthPanel", () => ({ default: () => <div>step-up</div> }));

const { default: ShareMessagesPage } = await import("../src/pages/ShareMessagesPage");
const { buildTextEnvelope, bytesToBase64, utf8Bytes } = await import("../src/utils/sharePayload");

const me = { userId: 1, role: "USER_LEVEL_1" };
const intent = { intent_id: 7, status: "APPROVED", version: 1, body: { operations: ["encrypt", "decrypt", "share"], recipient_user_id: 2,
  resource: "vault:customer-records", purpose_code: "CASE_INVESTIGATION", data_scope: { classification: "CONFIDENTIAL", max_bytes: 4096 } } };
const share = (over) => ({ share_id: "shr_1", owner_user_id: 2, recipient_user_id: 1, owner_username: "alice", recipient_username: "me",
  intent_id: 7, purpose_code: "CASE_INVESTIGATION", resource: "vault:customer-records", classification: "CONFIDENTIAL", size: 100,
  status: "APPROVED", kind: "text", created_ts: 1, expires_ts: 4102444800, access_count: 0, opened_ts: null, ...over });

beforeEach(() => {
  Object.values(api).forEach((f) => f.mockReset());
  api.listIntents.mockResolvedValue([intent]);
  api.listKeySessions.mockResolvedValue([{ key_session_id: "ks_active_1", status: "ACTIVE" }]);
  api.listShareRecipients.mockResolvedValue([{ user_id: 2, username: "bob", role: "USER_LEVEL_1" }]);
  api.listShares.mockResolvedValue([]);
  api.listPendingShareApprovals.mockResolvedValue([]);
});
afterEach(cleanup);

describe("Secure Sharing page", () => {
  it("compose: encrypts the validated envelope, then creates the share, and never claims delivery", async () => {
    api.requestDecision.mockResolvedValue({ outcome: "PERMIT", context_id: "ctx_12345678", decision_id: "dec_1", policy_version: 1, reasons: [] });
    api.encryptWithContext.mockResolvedValue({ record_id: "rec_abcdef12" });
    api.createShare.mockResolvedValue({ share_id: "shr_9", status: "PENDING_ADMIN", kind: "text" });
    render(<ShareMessagesPage user={me} />);
    fireEvent.click(await screen.findByRole("tab", { name: /New share/ }));
    const selects = await screen.findAllByRole("combobox");
    await waitFor(() => expect(screen.getByRole("option", { name: /bob/ })).toBeTruthy());
    fireEvent.change(selects[0], { target: { value: "2" } });
    await waitFor(() => expect(selects[1].value).toBe("7"));
    fireEvent.change(document.querySelector("textarea"), { target: { value: "Top secret ✓" } });
    fireEvent.click(screen.getByRole("button", { name: /Review/ }));
    fireEvent.click(await screen.findByRole("button", { name: /Encrypt and send/ }));
    await waitFor(() => expect(api.createShare).toHaveBeenCalledTimes(1));

    const envelope = buildTextEnvelope({ text: "Top secret ✓" });
    expect(api.requestDecision.mock.calls[0][0]).toMatchObject({ operation: "encrypt", key_session_id: "ks_active_1", requested_bytes: utf8Bytes(envelope).length });
    expect(api.encryptWithContext.mock.calls[0][0].plaintext_base64).toBe(bytesToBase64(utf8Bytes(envelope)));
    expect(api.createShare.mock.calls[0][0]).toMatchObject({ record_id: "rec_abcdef12", intent_id: 7, kind: "text", expires_in_minutes: 1440 });
    const alerts = document.body.textContent;
    expect(alerts).toMatch(/cannot open it until an administrator approves/);
    expect(alerts).not.toMatch(/delivered successfully/i);
  });

  it("compose: if the share cannot be created after encryption, the failure is reported as NOT shared", async () => {
    api.requestDecision.mockResolvedValue({ outcome: "PERMIT", context_id: "ctx_12345678", decision_id: "d", policy_version: 1, reasons: [] });
    api.encryptWithContext.mockResolvedValue({ record_id: "rec_abcdef12" });
    api.createShare.mockRejectedValue(Object.assign(new Error("x"), { detail: "recipient has no active key session; recipient must establish one" }));
    render(<ShareMessagesPage user={me} />);
    fireEvent.click(await screen.findByRole("tab", { name: /New share/ }));
    const selects = await screen.findAllByRole("combobox");
    await waitFor(() => expect(screen.getByRole("option", { name: /bob/ })).toBeTruthy());
    fireEvent.change(selects[0], { target: { value: "2" } });
    await waitFor(() => expect(selects[1].value).toBe("7"));
    fireEvent.change(document.querySelector("textarea"), { target: { value: "hello" } });
    fireEvent.click(screen.getByRole("button", { name: /Review/ }));
    fireEvent.click(await screen.findByRole("button", { name: /Encrypt and send/ }));
    await waitFor(() => expect(document.body.textContent).toMatch(/share was NOT created/));
    expect(document.body.textContent).toMatch(/must establish one/);
  });

  it("inbox: pending shares cannot be decrypted; approved ones open, decrypt, show, and clear", async () => {
    api.listShares.mockResolvedValue([share({ share_id: "shr_p", status: "PENDING_ADMIN" }), share({ share_id: "shr_a" })]);
    api.openShare.mockResolvedValue({});
    api.requestDecision.mockResolvedValue({ outcome: "PERMIT", context_id: "ctx_12345678", decision_id: "d", policy_version: 1, reasons: [] });
    api.decryptWithContext.mockResolvedValue({ record_id: "shr_a", plaintext_base64: bytesToBase64(utf8Bytes(buildTextEnvelope({ subject: "Hi", text: "the secret body" }))) });
    render(<ShareMessagesPage user={me} />);
    await screen.findByText(/Pending approval/);
    const buttons = await screen.findAllByRole("button", { name: /Open and decrypt/ });
    expect(buttons).toHaveLength(1);                           // only the approved share
    fireEvent.click(buttons[0]);
    await waitFor(() => expect(screen.getByTestId("plaintext").textContent).toBe("the secret body"));
    expect(api.openShare).toHaveBeenCalledWith("shr_a");
    expect(api.requestDecision.mock.calls[0][0]).toMatchObject({ operation: "decrypt", record_id: "shr_a", intent_id: 7 });
    fireEvent.click(screen.getByRole("button", { name: /Clear from screen/ }));
    expect(screen.queryByTestId("plaintext")).toBeNull();
  });

  it("inbox: a file is offered for download only after its SHA-256 verifies", async () => {
    const { buildFileEnvelope } = await import("../src/utils/sharePayload");
    const bytes = Uint8Array.from([37, 80, 68, 70, 45, 1, 2, 3, 250]);
    api.listShares.mockResolvedValue([share({ kind: "file" })]);
    api.openShare.mockResolvedValue({});
    api.requestDecision.mockResolvedValue({ outcome: "PERMIT", context_id: "ctx_12345678", decision_id: "d", policy_version: 1, reasons: [] });
    api.decryptWithContext.mockResolvedValue({ plaintext_base64: bytesToBase64(utf8Bytes(await buildFileEnvelope({ filename: "r.pdf", bytes }))) });
    render(<ShareMessagesPage user={me} />);
    fireEvent.click(await screen.findByRole("button", { name: /Open and decrypt/ }));
    await screen.findByText(/Integrity verified/);
    expect(screen.getByRole("button", { name: /Download original file/ })).toBeTruthy();
  });
});
