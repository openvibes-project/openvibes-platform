// CSV in the browser: safe cells and a download, shared by every export.

/** One CSV cell: quoted, and prefixed with ' when it starts with = + - @
 *  (or tab/CR), or holds one after a , or ; (a ;-separator Excel splits
 *  there despite the quotes), so a spreadsheet never runs it as a formula. */
export function csvCell(value: unknown): string {
  let text = value === null || value === undefined ? "" : String(value);
  if (/^[=+\-@\t\r]/.test(text) || /[,;]\s*[=+\-@]/.test(text)) text = `'${text}`;
  return `"${text.replaceAll('"', '""')}"`;
}

/** Rows (the first one the header) as CSV text. */
export function csvText(rows: readonly (readonly unknown[])[]): string {
  return `${rows.map((row) => row.map(csvCell).join(",")).join("\n")}\n`;
}

/** Saves `rows` as a CSV file named `name`, with a UTF-8 byte-order mark
 *  so Excel shows non-ASCII names correctly. */
export function downloadCsv(name: string, rows: readonly (readonly unknown[])[]): void {
  const url = URL.createObjectURL(new Blob(["\uFEFF", csvText(rows)], { type: "text/csv;charset=utf-8" }));
  const link = Object.assign(document.createElement("a"), { href: url, download: name });
  link.click();
  // Revoked later: right after click() some browsers cancel the download.
  window.setTimeout(() => URL.revokeObjectURL(url), 10_000);
}
