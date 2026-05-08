import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { CoreDispatcher } from "../../src/copilot/dispatcher/core-dispatcher.js";
import { DispatcherDriver } from "../../src/copilot/dispatcher/driver.js";
import { Datastore } from "../../src/copilot/options.js";
import { createArraySink, createPrintSink, type PrintLevel } from "../../src/copilot/print.js";
import { SpoolController } from "../../src/copilot/spool.js";
import { ModuleRegistry } from "../../src/modules/registry.js";

const tempDirs: string[] = [];

beforeEach(() => {
  // no-op; each test creates its own tempdir
});

afterEach(() => {
  while (tempDirs.length > 0) rmSync(tempDirs.pop()!, { recursive: true, force: true });
});

function mkTmp(): string {
  const d = mkdtempSync(path.join(os.tmpdir(), "kz-spool-"));
  tempDirs.push(d);
  return d;
}

describe("SpoolController", () => {
  it("tap() is a no-op when no file is open", () => {
    const spool = new SpoolController();
    expect(spool.isActive()).toBe(false);
    expect(() => spool.tap("anything")).not.toThrow();
  });

  it("writes captured lines to the file after start()", () => {
    const dir = mkTmp();
    const file = path.join(dir, "audit.log");
    const spool = new SpoolController();
    spool.start(file, dir);
    spool.tap("[*] Running sast:scan\n");
    spool.tap("[+] sast:scan completed\n");
    spool.stop();
    const contents = readFileSync(file, "utf8");
    expect(contents).toContain("[*] Running sast:scan");
    expect(contents).toContain("[+] sast:scan completed");
    expect(contents).toMatch(/kuzushi spool started at/);
    expect(contents).toMatch(/kuzushi spool stopped at/);
  });

  it("appends to an existing file across start cycles", () => {
    const dir = mkTmp();
    const file = path.join(dir, "audit.log");
    const spool = new SpoolController();
    spool.start(file, dir);
    spool.tap("first\n");
    spool.stop();
    spool.start(file, dir);
    spool.tap("second\n");
    spool.stop();
    const contents = readFileSync(file, "utf8");
    expect(contents).toContain("first");
    expect(contents).toContain("second");
  });

  it("resolves a relative path against the provided cwd", () => {
    const dir = mkTmp();
    const spool = new SpoolController();
    const absolute = spool.start("spool.log", dir);
    spool.tap("x\n");
    spool.stop();
    expect(absolute).toBe(path.resolve(dir, "spool.log"));
    expect(existsSync(path.join(dir, "spool.log"))).toBe(true);
  });

  it("status() reports the active file basename + elapsed seconds", () => {
    const dir = mkTmp();
    const spool = new SpoolController();
    expect(spool.status()).toBeUndefined();
    spool.start(path.join(dir, "xyz.log"), dir);
    expect(spool.status()).toContain("xyz.log");
    spool.stop();
    expect(spool.status()).toBeUndefined();
  });
});

describe("`spool` command end-to-end", () => {
  function driverWithSpool(): {
    driver: DispatcherDriver;
    spool: SpoolController;
    cwd: string;
  } {
    const registry = new ModuleRegistry();
    const spool = new SpoolController();
    const core = new CoreDispatcher({
      registry,
      globals: new Datastore(),
      history: () => [],
      spool,
    });
    const cwd = mkTmp();
    const driver = new DispatcherDriver({ base: core, cwd, print: createArraySink() });
    return { driver, spool, cwd };
  }

  it("`spool <file>` starts, `spool off` stops", async () => {
    const { driver, spool, cwd } = driverWithSpool();
    const start = await driver.handle("spool audit.log");
    expect(start.output).toContain("Spooling to");
    expect(spool.isActive()).toBe(true);
    const stop = await driver.handle("spool off");
    expect(stop.output).toContain("Stopped spool");
    expect(spool.isActive()).toBe(false);
    expect(existsSync(path.join(cwd, "audit.log"))).toBe(true);
  });

  it("`spool status` reports current state", async () => {
    const { driver } = driverWithSpool();
    const initial = await driver.handle("spool status");
    expect(initial.output).toContain("off");
  });

  it("print-sink onPrint hook mirrors lines to the active file", () => {
    const dir = mkTmp();
    const spool = new SpoolController();
    const sink = createPrintSink({
      color: false,
      write: () => {},
      onPrint: (line: string, _level: PrintLevel) => {
        spool.tap(line);
      },
    });
    spool.start(path.join(dir, "run.log"), dir);
    sink.status("scan started");
    sink.good("finding captured");
    sink.error("oh no");
    spool.stop();
    const contents = readFileSync(path.join(dir, "run.log"), "utf8");
    expect(contents).toContain("[*] scan started");
    expect(contents).toContain("[+] finding captured");
    expect(contents).toContain("[-] oh no");
  });
});
