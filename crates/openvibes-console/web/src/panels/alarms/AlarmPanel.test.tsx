// The alarm panel's waiting suppression request (approved screen 12) as markup.
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

vi.hoisted(() => {
  Object.assign(globalThis, { window: { location: { pathname: "/", search: "" }, history: { replaceState() {} }, addEventListener() {}, removeEventListener() {} } });
});

import type { AlarmSuppression } from "../../api/types";
import { WaitingRequest } from "./AlarmPanel";

const waiting = (canWithdraw: boolean) => ({ id: "4", status: "waiting", can_withdraw: canWithdraw }) as AlarmSuppression;

describe("WaitingRequest", () => {
  it("says the request waits and offers Withdraw to the requester", () => {
    const out = renderToStaticMarkup(<WaitingRequest request={waiting(true)} />);
    expect(out).toContain("Suppression requested, waiting for approval… these alarms keep arriving");
    expect(out).toMatch(/<button[^>]*>.*Withdraw request<\/button>/);
  });
  it("offers no Withdraw to someone else", () => {
    expect(renderToStaticMarkup(<WaitingRequest request={waiting(false)} />)).not.toContain("Withdraw request");
  });
});
