// The signed-in session and what it may do. In demo mode the session comes
// from the in-browser API for the chosen persona.
import { createContext, useContext } from "react";

import type { Permission, Session } from "../api/types";

export type Access = { permission: Permission; global?: boolean };

export function allows(session: Session | undefined, { permission, global = false }: Access): boolean {
  return session?.capabilities.some((capability) =>
    capability.permission === permission && (!global || capability.scope.kind === "global")) === true;
}

export type SessionState = {
  session: Session | undefined;
  demo: boolean;
  can: (permission: Permission, global?: boolean) => boolean;
};

export const SessionContext = createContext<SessionState>({ session: undefined, demo: false, can: () => false });

export function useSession(): SessionState {
  return useContext(SessionContext);
}
