// CSV in the browser: safe cells and a download, shared by every export.

/** One CSV cell: quoted, and a leading = + - @ (or tab/CR) prefixed with '
 *  so a spreadsheet never runs it as a formula (CSV injection). */
export function csvCell(value: unknown): string {
  let text = value === null || value === undefined ? "" : String(value);
  if (/^[=+\-@\t\r]/.test(text)) text = `'${text}`;
  return `"${text.replaceAll('"', '""')}"`;
}

/** Rows (the first one the header) as CSV text. */
export function csvText(rows: readonly (readonly unknown[])[]): string {
  return `${rows.map((row) => row.map(csvCell).join(",")).join("\n")}\n`;
}

/** Saves `rows` as a CSV file named `name`. */
export function downloadCsv(name: string, rows: readonly (readonly unknown[])[]): void {
  const url = URL.createObjectURL(new Blob([csvText(rows)], { type: "text/csv" }));
  const link = Object.assign(document.createElement("a"), { href: url, download: name });
  link.click();
  URL.revokeObjectURL(url);
}
