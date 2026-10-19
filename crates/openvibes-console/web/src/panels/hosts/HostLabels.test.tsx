import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it, vi } from "vitest";

vi.hoisted(() => {
  Object.assign(globalThis, { window: { location: { pathname: "/", search: "" }, history: { replaceState() {} }, addEventListener() {}, removeEventListener() {} } });
});

import { ApiError } from "../../api/client";
import { LabelsCard, MAX_LABELS, labelError, nextLabel } from "./HostLabels";

const groups = [{ asset_group_id: "g1", name: "Production", kind: "rule" as const }, { asset_group_id: "g2", name: "All hosts", kind: "automatic" as const }];
const card = (editable: boolean, error?: string) => renderToStaticMarkup(
  <LabelsCard labels={["db", "eu"]} groups={groups} editable={editable} error={error} onAdd={() => {}} onRemove={() => {}} />);

describe("host labels", () => {
  it("trims, and ignores empty and duplicate labels", () => {
    expect(nextLabel(["db"], "  web ")).toBe("web");
    expect(nextLabel(["db"], "db")).toBeUndefined();
    expect(nextLabel(["db"], "   ")).toBeUndefined();
  });
  it("explains the cap and a bad label", () => {
    expect(labelError(new ApiError(409, "too_many_labels", "x"))).toBe(`A host can have at most ${MAX_LABELS} labels. Remove one first.`);
    expect(labelError(new ApiError(422, "invalid_label", "Label must be 1-64 characters"))).toBe("Label must be 1-64 characters");
    expect(labelError(new Error("boom"))).toBe("The label could not be saved.");
  });
  it("shows group chips with the kind word, linking to the group page", () => {
    const html = card(true);
    expect(html).toMatch(/<a [^>]*href="[^"]*host-groups[^"]*g1[^"]*"[^>]*>Production/);
    expect(html).toContain("Rule");
    expect(html).toContain("Automatic");
  });
  it("editable: remove buttons, a labelled input, the helper text and the error", () => {
    const html = card(true, "A host can have at most 32 labels. Remove one first.");
    expect(html).toContain('aria-label="Remove label db"');
    expect(html).toContain("Add a label");
    expect(html).toContain("For filtering and finding hosts. Labels never change who can see a host.");
    expect(html).toContain('role="alert"');
  });
  it("without hosts.label: labels shown, no controls", () => {
    const html = card(false);
    expect(html).toContain(">db<");
    expect(html).not.toContain("Remove label");
    expect(html).not.toContain("<input");
  });
});
