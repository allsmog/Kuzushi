import { describe, expect, it } from "vitest";
import { deriveNavigation } from "../../src/ui/layout-context.js";
import type { ShellState } from "../../src/ui/state.js";

describe("deriveNavigation", () => {
  it("derives shell breadcrumbs from focused module and view", () => {
    const shell = {
      focusedModule: "sast",
      shellView: "findings",
      processing: false,
      workspace: "demo",
    } as ShellState;

    const nav = deriveNavigation({
      mode: "shell",
      phase: "idle",
      repoName: "repo",
      shell,
    });

    expect(nav.title).toBe("findings");
    expect(nav.breadcrumbs).toEqual(["shell", "sast", "findings"]);
    expect(nav.status).toContain("idle");
  });

  it("derives non-shell title from mode", () => {
    const nav = deriveNavigation({
      mode: "running",
      phase: "triaging",
      repoName: "repo",
      shell: undefined,
    });

    expect(nav.title).toBe("Scan Run");
    expect(nav.breadcrumbs).toEqual(["repo", "Scan Run"]);
    expect(nav.status).toEqual(["triaging"]);
  });
});
