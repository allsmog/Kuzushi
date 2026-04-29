import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { playStartupSound, startupSoundCommand } from "../src/startup-sound.js";

let tmpDir: string | null = null;

afterEach(() => {
  if (tmpDir) {
    rmSync(tmpDir, { recursive: true, force: true });
    tmpDir = null;
  }
});

function makeSoundsDir(): string {
  tmpDir = mkdtempSync(path.join(os.tmpdir(), "kuzushi-startup-sound-"));
  writeFileSync(path.join(tmpDir, "startup.wav"), "");
  writeFileSync(path.join(tmpDir, "ignore.txt"), "");
  return tmpDir;
}

describe("startupSoundCommand", () => {
  it("maps supported platforms to native audio commands", () => {
    expect(startupSoundCommand("darwin")).toBe("afplay");
    expect(startupSoundCommand("linux")).toBe("aplay");
    expect(startupSoundCommand("win32")).toBeNull();
  });
});

describe("playStartupSound", () => {
  it("does not spawn when startup sound is disabled", () => {
    const spawnCommand = vi.fn(() => ({ unref: vi.fn() }));

    playStartupSound({
      enabled: false,
      soundsDir: makeSoundsDir(),
      platform: "darwin",
      spawnCommand,
    });

    expect(spawnCommand).not.toHaveBeenCalled();
  });

  it("spawns the platform audio command when enabled", () => {
    const unref = vi.fn();
    const spawnCommand = vi.fn(() => ({ unref }));
    const soundsDir = makeSoundsDir();

    playStartupSound({
      enabled: true,
      soundsDir,
      platform: "darwin",
      random: () => 0,
      spawnCommand,
    });

    expect(spawnCommand).toHaveBeenCalledWith("afplay", [path.join(soundsDir, "startup.wav")], {
      stdio: "ignore",
      detached: true,
    });
    expect(unref).toHaveBeenCalledOnce();
  });
});
