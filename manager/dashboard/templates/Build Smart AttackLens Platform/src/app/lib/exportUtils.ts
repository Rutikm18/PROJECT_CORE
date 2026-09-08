import * as XLSX from "xlsx";

export type Col = { key: string; header: string };
export type Sheet = {
  name: string;
  rows: Record<string, unknown>[];
  cols: Col[];
  severityKey?: string; // column key used to colour Excel rows (best-effort)
};

function cell(value: unknown): string {
  if (value === null || value === undefined) return "";
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

function csvField(s: string): string {
  return /[",\n\r]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

export function toCSV(rows: Record<string, unknown>[], cols: Col[]): string {
  const head = cols.map((c) => csvField(c.header)).join(",");
  const body = rows.map((r) => cols.map((c) => csvField(cell(r[c.key]))).join(",")).join("\r\n");
  return body ? `${head}\r\n${body}` : head;
}

export function downloadText(text: string, filename: string, mime: string): void {
  const blob = new Blob([text], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

export function toXLSX(sheets: Sheet[], filename: string): void {
  const wb = XLSX.utils.book_new();
  for (const s of sheets) {
    const aoa = [s.cols.map((c) => c.header), ...s.rows.map((r) => s.cols.map((c) => cell(r[c.key])))];
    const ws = XLSX.utils.aoa_to_sheet(aoa);
    (ws as Record<string, unknown>)["!freeze"] = { xSplit: 0, ySplit: 1 };
    (ws as Record<string, unknown>)["!cols"] = s.cols.map((c) => {
      const max = Math.max(c.header.length, ...s.rows.map((r) => cell(r[c.key]).length));
      return { wch: Math.min(60, Math.max(10, max + 2)) };
    });
    XLSX.utils.book_append_sheet(wb, ws, s.name.slice(0, 31));
  }
  XLSX.writeFile(wb, filename);
}
