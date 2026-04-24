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

  it("derives titles for threat tabs from the current threatTab", () => {
    const nav = deriveNavigation({
      mode: "shell",
      phase: "idle",
      repoName: "repo",
      shell: {
        focusedModule: null,
        shellView: "threats",
        threatTab: "dfd",
        processing: false,
        workspace: "demo",
      } as ShellState,
    });

    expect(nav.title).toBe("data flow diagram");
    expect(nav.breadcrumbs).toEqual(["shell", "threats"]);
  });

  it("defaults bare threat navigation to the summary title", () => {
    const nav = deriveNavigation({
      mode: "shell",
      phase: "idle",
      repoName: "repo",
      shell: {
        focusedModule: null,
        shellView: "threats",
        processing: false,
      } as ShellState,
    });

    expect(nav.title).toBe("threat summary");
  });

  it("derives titles for context build and task story views", () => {
    const contextNav = deriveNavigation({
      mode: "shell",
      phase: "idle",
      repoName: "repo",
      shell: {
        focusedModule: null,
        shellView: "context-build",
        processing: false,
      } as ShellState,
    });
    const storyNav = deriveNavigation({
      mode: "shell",
      phase: "idle",
      repoName: "repo",
      shell: {
        focusedModule: null,
        shellView: "task-story",
        processing: false,
      } as ShellState,
    });

    expect(contextNav.title).toBe("context build");
    expect(storyNav.title).toBe("task details");
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
