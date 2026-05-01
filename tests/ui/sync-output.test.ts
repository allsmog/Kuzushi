import { afterEach, describe, expect, it } from "vitest";
import { supportsSyncOutput } from "../../src/ui/sync-output.js";

const ORIGINAL_ENV = { ...process.env };

afterEach(() => {
  for (const key of Object.keys(process.env)) {
    if (!(key in ORIGINAL_ENV)) delete process.env[key];
  }
  for (const [key, value] of Object.entries(ORIGINAL_ENV)) {
    process.env[key] = value;
  }
});

describe("supportsSyncOutput", () => {
  it("honors explicit enable", () => {
    process.env["KUZUSHI_SYNC_OUTPUT"] = "1";
    delete process.env["TMUX"];
    expect(supportsSyncOutput()).toBe(true);
  });

  it("honors explicit disable", () => {
    process.env["KUZUSHI_SYNC_OUTPUT"] = "0";
    delete process.env["TMUX"];
    expect(supportsSyncOutput()).toBe(false);
  });

  it("disables in tmux sessions", () => {
    process.env["TMUX"] = "/tmp/tmux";
    process.env["KUZUSHI_SYNC_OUTPUT"] = "1";
    process.env["TERM"] = "xterm-256color";
    expect(supportsSyncOutput()).toBe(false);
  });

  it("disables when TERM is dumb", () => {
    delete process.env["KUZUSHI_SYNC_OUTPUT"];
    delete process.env["TMUX"];
    process.env["TERM"] = "dumb";
    expect(supportsSyncOutput()).toBe(false);
  });

  it("enables by default for regular interactive TERM values", () => {
    delete process.env["KUZUSHI_SYNC_OUTPUT"];
    delete process.env["TMUX"];
    process.env["TERM"] = "xterm-256color";
    delete process.env["TERM_PROGRAM"];
    delete process.env["KITTY_WINDOW_ID"];
    delete process.env["ALACRITTY_LOG"];
    delete process.env["WT_SESSION"];
    expect(supportsSyncOutput()).toBe(true);
  });
});
