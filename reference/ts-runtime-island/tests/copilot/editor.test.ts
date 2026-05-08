import { chmodSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { openInEditor } from "../../src/copilot/editor.js";

describe("openInEditor", () => {
  let workDir: string;

  beforeEach(() => {
    workDir = path.join(tmpdir(), `kuzushi-editor-${Date.now()}-${Math.random()}`);
    mkdirSync(workDir, { recursive: true });
  });

  afterEach(() => {
    rmSync(workDir, { recursive: true, force: true });
  });

  it("waits for the editor process and reads the saved file", async () => {
    const editor = path.join(workDir, "editor.sh");
    writeFileSync(
      editor,
      ["#!/bin/sh", "printf '\\n# edited by test\\n' >> \"$1\"", "exit 0", ""].join("\n"),
      "utf8",
    );
    chmodSync(editor, 0o755);

    const edited = await openInEditor("# seed\n", { editor, hint: "prompt.md" });

    expect(edited).toBe("# seed\n\n# edited by test\n");
  });

  it("returns null when the editor exits non-zero", async () => {
    const editor = path.join(workDir, "cancel.sh");
    writeFileSync(editor, "#!/bin/sh\nexit 1\n", "utf8");
    chmodSync(editor, 0o755);

    await expect(openInEditor("# seed\n", { editor })).resolves.toBeNull();
  });
});
