// What the detail pages' markup tests share: render under a session, and read
// the markup as text (no DOM library in vitest; see ui/controls.test.tsx).
import "./windowStub";

import { renderToStaticMarkup } from "react-dom/server";

import type { Session } from "../../api/types";
import { SessionContext } from "../../app/session";

const session = { principal: { id: "u-me", username: "me", display_name: "Me" }, capabilities: [] } as unknown as Session;
export const render = (node: React.ReactNode, can = true) => renderToStaticMarkup(
  <SessionContext.Provider value={{ session, demo: false, can: () => can, canEverywhere: () => can }}>{node}</SessionContext.Provider>,
).replace(/<!-- -->/g, "");
export const text = (html: string) => html.replace(/<[^>]+>/g, " ").replace(/\s+/g, " ");
/** The markup's text with tags dropped and nothing added, for a line that is one run ("a · b"). */
export const flat = (html: string) => html.replace(/<[^>]+>/g, "");
