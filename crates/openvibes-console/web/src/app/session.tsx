// The signed-in session and what it may do. In demo mode the session comes
// from the in-browser API for the chosen persona.
import { createContext, useContext } from "react";

import type { Permission, Session } from "../api/types";

export type Access = { permission: Permission };

export function allows(session: Session | undefined, { permission }: Access): boolean {
  return session?.capabilities.some((capability) => capability.permission === permission) === true;
}

/** Whether the session holds `permission` over every host (an unscoped grant). */
export const holdsEverywhere = (session: Session | undefined, permission: Permission): boolean =>
  session?.capabilities.some((c) => c.permission === permission && c.scope.kind === "global") === true;

/** Whether `can` grants any of these (a view's or a tab's access list). */
export const grantsAny = (can: SessionState["can"], access: readonly Access[]): boolean =>
  access.some((a) => can(a.permission));

type SessionState = {
  session: Session | undefined;
  demo: boolean;
  can: (permission: Permission) => boolean;
  /** Held over every host, not just some host groups. */
  canEverywhere: (permission: Permission) => boolean;
  /** Loads the session again (e.g. after the person changes their picture). */
  reloadSession?: () => void;
};

export const SessionContext = createContext<SessionState>({ session: undefined, demo: false, can: () => false, canEverywhere: () => false });

export function useSession(): SessionState {
  return useContext(SessionContext);
}
