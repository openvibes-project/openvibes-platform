// The console draws its own selects, checkboxes and number fields: native
// popups and spinners cannot be themed. This scans the sources so they stay out.
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { expect, it } from "vitest";

const files = (dir: string): string[] =>
  readdirSync(dir, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? files(join(dir, e.name)) : e.name.endsWith(".tsx") ? [join(dir, e.name)] : []));

const line = (text: string, at: number) => text.slice(0, at).split("\n").length;
const classes = (tag: string) => /className="([^"]*)"/.exec(tag)?.[1]?.split(/\s+/) ?? [];

it("uses no native select, radio, bare checkbox or bare number input", () => {
  const bad: string[] = [];
  const exceptions: string[] = []; // documented exceptions, "file:line reason" (spec 2.4); starts empty
  for (const file of files("src")) {
    const text = readFileSync(file, "utf8").replace(/^\s*\/\/.*$/gm, (c) => c.replace(/\S/g, " ")); // comments blanked, lines kept
    const at = (re: RegExp, why: string, ok: (m: string) => boolean = () => false) => {
      for (const m of text.matchAll(re)) if (!ok(m[0])) bad.push(`${file}:${line(text, m.index ?? 0)} ${why}`);
    };
    at(/<select[\s>]/g, "native <select>: use Select or Segmented");
    for (const m of text.matchAll(/<input\b(?:[^>]|=>)*>/g)) {
      const tag = m[0];
      const where = `${file}:${line(text, m.index ?? 0)}`;
      if (/type="radio"/.test(tag)) bad.push(`${where} native radio: use Segmented`);
      if (/type="checkbox"/.test(tag) && !classes(tag).includes("checkbox")) bad.push(`${where} checkbox without className="checkbox"`);
      if (/type="number"/.test(tag) && !classes(tag).includes("input")) bad.push(`${where} number input without className="input"`);
    }
  }
  expect(bad.filter((b) => !exceptions.some((e) => b.startsWith(e)))).toEqual([]);
});
