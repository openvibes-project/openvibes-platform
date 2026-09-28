// Reading widget configs written by any console version: every value is
// checked and falls back to a default, so an old or new config never
// breaks a dashboard.
import { LIST_VIEWS, type ListView } from "../views/rows";
import type { Widget } from "./layout";

type Config = Widget["config"] | Record<string, unknown>;

export function str<T extends string>(config: Config, key: string, fallback: T, allowed?: readonly T[]): T {
  const value = config[key];
  if (typeof value !== "string") return fallback;
  return allowed && !allowed.includes(value as T) ? fallback : (value as T);
}

export function int(config: Config, key: string, fallback: number, min: number, max: number): number {
  const value = config[key];
  return typeof value === "number" && Number.isInteger(value) ? Math.min(max, Math.max(min, value)) : fallback;
}

export function list<T extends string>(config: Config, key: string, allowed: readonly T[]): T[] {
  const value = config[key];
  return Array.isArray(value) ? value.filter((item): item is T => allowed.includes(item as T)) : [];
}

export function noteParts(line: string): ({ text: string } | { href: string })[] {
  const parts: ({ text: string } | { href: string })[] = [];
  let text = "";
  for (const word of line.split(/(\s+)/)) {
    if (/^https:\/\/[^\s<>"']+$/.test(word)) {
      if (text) parts.push({ text });
      text = "";
      parts.push({ href: word });
    } else text += word;
  }
  if (text) parts.push({ text });
  return parts;
}

export function parseListConfig(config: Config): { view: ListView; params: URLSearchParams; limit: number } | undefined {
  const view = config.view;
  if (typeof view !== "string" || !(LIST_VIEWS as readonly string[]).includes(view)) return undefined;
  // URLSearchParams never throws; empty keys (from garbage like "%%%") and
  // panel stacks are dropped, so only real filters reach the list.
  const params = new URLSearchParams(typeof config.query === "string" ? config.query : "");
  params.delete("open");
  for (const key of [...params.keys()]) if (params.get(key) === "") params.delete(key);
  return { view: view as ListView, params, limit: int(config, "limit", 8, 1, 20) };
}
