// One way to talk to /api/v1, whether the data is live (the console's own
// API with the browser session) or the in-browser demo. Loads are cached
// by path; a mutation invalidates a path prefix and every view that shows
// data under it reloads.
import { useEffect, useState, useSyncExternalStore } from "react";

import { createDemoServer, type Persona } from "../demo/server";

export class ApiError extends Error {
  constructor(readonly status: number, readonly code: string, title: string, readonly fieldErrors?: { field: string; code: string; message: string }[]) {
    super(title);
  }
}

type Demo = ReturnType<typeof createDemoServer>;
let demo: Demo | undefined;
let csrfToken = "";
const cache = new Map<string, Promise<unknown>>();
const listeners = new Set<() => void>();
let generation = 0;

export function configureDemo(persona: Persona | undefined): void {
  demo = persona === undefined ? undefined : createDemoServer({ persona });
  cache.clear();
  generation += 1;
  for (const listener of listeners) listener();
}

export const isDemo = () => demo !== undefined;

const signedOut = new Set<() => void>();
/** Called when a live request finds the session gone (expired or signed out elsewhere). */
export function onSignedOut(listener: () => void): () => void {
  signedOut.add(listener);
  return () => signedOut.delete(listener);
}
export const setCsrfToken = (token: string) => { csrfToken = token; };

export async function request<T>(method: string, path: string, body?: unknown, extra: Record<string, string> = {}): Promise<T> {
  const response = demo
    ? await demo.handle(method, path, body, extra)
    : await fetch(path, {
      method,
      cache: "no-store",
      credentials: "same-origin",
      headers: {
        accept: "application/json",
        ...(body === undefined ? {} : { "content-type": "application/json" }),
        ...(method === "GET" ? {} : { "x-csrf-token": csrfToken }),
        ...extra,
      },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    });
  if (response.status === 204) return undefined as T;
  const text = await response.text();
  let payload: unknown;
  try {
    payload = text === "" ? undefined : JSON.parse(text);
  } catch {
    payload = undefined;
  }
  if (response.status === 401 && !demo && path !== "/api/v1/session") for (const listener of signedOut) listener();
  if (!response.ok) {
    const details = (payload ?? {}) as { code?: string; title?: string; field_errors?: { field: string; code: string; message: string }[] | null };
    throw new ApiError(response.status, details.code ?? "unavailable", details.title ?? `Request failed (${response.status})`, details.field_errors ?? undefined);
  }
  return payload as T;
}

export function load<T>(path: string): Promise<T> {
  let pending = cache.get(path);
  if (pending === undefined) {
    pending = request<T>("GET", path);
    pending.catch(() => cache.delete(path));
    cache.set(path, pending);
  }
  return pending as Promise<T>;
}

export function subscribe(listener: () => void): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

/** Stores a value the client already has (e.g. a save's response) as the
 *  load of `path`, so views show it at once instead of refetching. */
export function prime<T>(path: string, value: T): void {
  cache.set(path, Promise.resolve(value));
  generation += 1;
  for (const listener of listeners) listener();
}

/** Drops cached loads under `prefix` (all when omitted) and refreshes views. */
export function invalidate(prefix = "/"): void {
  for (const key of [...cache.keys()]) if (key.startsWith(prefix)) cache.delete(key);
  generation += 1;
  for (const listener of listeners) listener();
}

export type Resource<T> = { data: T | undefined; error: ApiError | undefined; loading: boolean };

type Loaded<T> = { key: string; path: string; data: T | undefined; error: ApiError | undefined };

const failure = (error: unknown) => error instanceof ApiError ? error : new ApiError(0, "network", "The console could not be reached");

/** Loads `path` (skipped when null), keeping the last data while reloading. */
export function useResource<T>(path: string | null): Resource<T> {
  const version = useSyncExternalStore(subscribe, () => generation);
  const key = `${path}#${version}`;
  const [loaded, setLoaded] = useState<Loaded<T>>({ key: "", path: "", data: undefined, error: undefined });
  useEffect(() => {
    if (path === null) return;
    let live = true;
    load<T>(path).then(
      (data) => { if (live) setLoaded({ key, path, data, error: undefined }); },
      (error: unknown) => { if (live) setLoaded({ key, path, data: undefined, error: failure(error) }); },
    );
    return () => { live = false; };
  }, [path, key]);
  if (path === null) return { data: undefined, error: undefined, loading: false };
  const samePath = loaded.path === path;
  return { data: samePath ? loaded.data : undefined, error: samePath ? loaded.error : undefined, loading: loaded.key !== key };
}

/** Loads every page of a cursor-paged list (bounded) for client-side filtering. */
export function useAllPages<T>(path: string | null, max = 2000): Resource<T[]> {
  const version = useSyncExternalStore(subscribe, () => generation);
  const key = `${path}#${version}#${max}`;
  const [loaded, setLoaded] = useState<Loaded<T[]>>({ key: "", path: "", data: undefined, error: undefined });
  useEffect(() => {
    if (path === null) return;
    let live = true;
    (async () => {
      const items: T[] = [];
      let cursor: string | null | undefined = null;
      do {
        const separator = path.includes("?") ? "&" : "?";
        const pageData: { items: T[]; next_cursor?: string | null } = await load(`${path}${separator}limit=100${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ""}`);
        items.push(...pageData.items);
        cursor = pageData.next_cursor;
      } while (cursor && items.length < max);
      return items;
    })().then(
      (data) => { if (live) setLoaded({ key, path, data, error: undefined }); },
      (error: unknown) => { if (live) setLoaded({ key, path, data: undefined, error: failure(error) }); },
    );
    return () => { live = false; };
  }, [path, key, max]);
  if (path === null) return { data: undefined, error: undefined, loading: false };
  const samePath = loaded.path === path;
  return { data: samePath ? loaded.data : undefined, error: samePath ? loaded.error : undefined, loading: loaded.key !== key };
}
