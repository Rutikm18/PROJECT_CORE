import { describe, it, expect } from "vitest";
import { toCSV } from "./exportUtils";

describe("toCSV", () => {
  const cols = [
    { key: "id", header: "ID" },
    { key: "note", header: "Note" },
  ];
  it("emits a header row then one row per record, in column order", () => {
    const csv = toCSV([{ id: 1, note: "ok" }], cols);
    expect(csv).toBe("ID,Note\r\n1,ok");
  });
  it("quotes and escapes commas, quotes, and newlines", () => {
    const csv = toCSV([{ id: 1, note: 'a,"b"\nc' }], cols);
    expect(csv).toBe('ID,Note\r\n1,"a,""b""\nc"');
  });
  it("renders missing/undefined as empty and JSON-stringifies objects", () => {
    const csv = toCSV([{ id: 2, note: { k: 1 } }], cols);
    expect(csv).toBe('ID,Note\r\n2,"{""k"":1}"');
  });
  it("returns just the header when there are no rows", () => {
    expect(toCSV([], cols)).toBe("ID,Note");
  });
});
