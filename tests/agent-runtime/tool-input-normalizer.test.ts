import { describe, expect, it } from "vitest";
import { normalizeToolInput } from "../../src/agent-runtime/tool-input-normalizer.js";

describe("normalizeToolInput", () => {
  it("returns same ref + changed=false when tool has no alias map", () => {
    const raw = { foo: "bar" };
    const result = normalizeToolInput("UnknownTool", raw);
    expect(result.input).toBe(raw);
    expect(result.changed).toBe(false);
    expect(result.renames).toEqual([]);
  });

  it("returns same ref + changed=false when input already canonical", () => {
    const raw = { file_path: "/abs/path", content: "hello" };
    const result = normalizeToolInput("Write", raw);
    expect(result.input).toBe(raw);
    expect(result.changed).toBe(false);
    expect(result.renames).toEqual([]);
  });

  it("rewrites Write filePath → file_path", () => {
    const raw = { filePath: "/abs/path", content: "hello" };
    const result = normalizeToolInput("Write", raw);
    expect(result.changed).toBe(true);
    expect(result.input).toEqual({ file_path: "/abs/path", content: "hello" });
    expect(result.input).not.toBe(raw);
    expect(result.renames).toContain("filePath→file_path");
  });

  it("rewrites Write text → content", () => {
    const raw = { file_path: "/abs", text: "body" };
    const result = normalizeToolInput("Write", raw);
    expect(result.changed).toBe(true);
    expect(result.input).toEqual({ file_path: "/abs", content: "body" });
  });

  it("rewrites multiple aliases at once", () => {
    const raw = { filePath: "/abs", text: "body" };
    const result = normalizeToolInput("Write", raw);
    expect(result.changed).toBe(true);
    expect(result.input).toEqual({ file_path: "/abs", content: "body" });
    expect(result.renames.sort()).toEqual(["filePath→file_path", "text→content"]);
  });

  it("prefers canonical over alias when both are present", () => {
    const raw = { file_path: "/canonical", filePath: "/alias", content: "x" };
    const result = normalizeToolInput("Write", raw);
    expect(result.changed).toBe(false);
    expect(result.input).toBe(raw);
  });

  it("does not mutate the original input object", () => {
    const raw = { filePath: "/abs", content: "hello" };
    const snapshot = { ...raw };
    normalizeToolInput("Write", raw);
    expect(raw).toEqual(snapshot);
  });

  it("rewrites Edit oldString / newString / replaceAll", () => {
    const raw = {
      file_path: "/abs",
      oldString: "foo",
      newString: "bar",
      replaceAll: true,
    };
    const result = normalizeToolInput("Edit", raw);
    expect(result.changed).toBe(true);
    expect(result.input).toEqual({
      file_path: "/abs",
      old_string: "foo",
      new_string: "bar",
      replace_all: true,
    });
  });

  it("rewrites Read filePath + startLine → file_path + offset", () => {
    const raw = { filePath: "/abs", startLine: 10 };
    const result = normalizeToolInput("Read", raw);
    expect(result.changed).toBe(true);
    expect(result.input).toEqual({ file_path: "/abs", offset: 10 });
  });

  it("rewrites NotebookEdit aliases", () => {
    const raw = { notebookPath: "/nb", newSource: "src", cellId: "c1" };
    const result = normalizeToolInput("NotebookEdit", raw);
    expect(result.changed).toBe(true);
    expect(result.input).toEqual({
      notebook_path: "/nb",
      new_source: "src",
      cell_id: "c1",
    });
  });

  it("handles non-object input without crashing", () => {
    expect(normalizeToolInput("Write", null).changed).toBe(false);
    expect(normalizeToolInput("Write", "string").changed).toBe(false);
    expect(normalizeToolInput("Write", [1, 2, 3]).changed).toBe(false);
    expect(normalizeToolInput("Write", 42).changed).toBe(false);
  });
});
