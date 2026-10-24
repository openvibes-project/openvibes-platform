// A signed-in session for markup tests (no DOM library in vitest).
import type { ReactNode } from "react";

import type { Session } from "./api/types";
import { SessionContext } from "./app/session";

export const session = { principal: { id: "u-me", username: "me", display_name: "Me" }, capabilities: [] } as unknown as Session;

/** `node` inside a session that holds every permission (or none, with `can` false). */
export const withSession = (node: ReactNode, can = true) => (
  <SessionContext.Provider value={{ session, demo: false, can: () => can, canEverywhere: () => can }}>{node}</SessionContext.Provider>
);
