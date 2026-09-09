import assert from "node:assert/strict";
import {
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  symlinkSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { linkCheckout, priorInstallationPath, restoreInstallation } from "./local-install-link.mjs";

test("linking preserves the entire prior installation and restores its exact files", (t) => {
  const { installed, source } = fixture(t);
  assert.equal(linkCheckout(installed, source).state, "linked");
  assert.equal(realpathSync(installed), realpathSync(source));
  const backup = priorInstallationPath(installed);
  assert.equal(readFileSync(path.join(backup, "runtime.txt"), "utf8"), "original runtime");
  assert.deepEqual(linkCheckout(installed, source), { state: "already linked", backup });
  assert.equal(readFileSync(path.join(backup, "runtime.txt"), "utf8"), "original runtime");
  restoreInstallation(installed, source);
  assert.ok(lstatSync(installed).isDirectory());
  assert.equal(readFileSync(path.join(installed, "runtime.txt"), "utf8"), "original runtime");
  assert.equal(lstatSync(backup, { throwIfNoEntry: false }), undefined);
});

test("restore never overwrites a replacement installation made after linking", (t) => {
  const { installed, source } = fixture(t);
  linkCheckout(installed, source);
  unlinkSync(installed);
  mkdirSync(installed);
  writeFileSync(path.join(installed, "replacement.txt"), "new installation");
  assert.throws(() => restoreInstallation(installed, source), /no longer points to this checkout/);
  assert.equal(readFileSync(path.join(installed, "replacement.txt"), "utf8"), "new installation");
  assert.equal(
    readFileSync(path.join(priorInstallationPath(installed), "runtime.txt"), "utf8"),
    "original runtime",
  );
});

test("linking refuses to overwrite a previous saved installation", (t) => {
  const { installed, source } = fixture(t);
  mkdirSync(priorInstallationPath(installed));
  assert.throws(() => linkCheckout(installed, source), /already saved/);
  assert.ok(lstatSync(installed).isDirectory());
  assert.equal(readFileSync(path.join(installed, "runtime.txt"), "utf8"), "original runtime");
});

test("an existing link to another checkout is preserved and restored as a link", (t) => {
  const { installed, source, root } = fixture(t);
  const earlier = path.join(root, "earlier");
  mkdirSync(earlier);
  writeFileSync(path.join(earlier, "package.json"), JSON.stringify({ name: "kuzushi" }));
  rmSync(installed, { recursive: true });
  symlinkSync(earlier, installed, "junction");
  linkCheckout(installed, source);
  assert.ok(lstatSync(priorInstallationPath(installed)).isSymbolicLink());
  restoreInstallation(installed, source);
  assert.ok(lstatSync(installed).isSymbolicLink());
  assert.equal(realpathSync(installed), realpathSync(earlier));
});

test("missing and unrelated installations are refused without modifying them", (t) => {
  const { installed, source } = fixture(t);
  writeFileSync(path.join(installed, "package.json"), JSON.stringify({ name: "another-product" }));
  assert.throws(() => linkCheckout(installed, source), /No Kuzushi installation/);
  assert.equal(
    JSON.parse(readFileSync(path.join(installed, "package.json"))).name,
    "another-product",
  );
  assert.throws(() => linkCheckout(`${installed}-absent`, source), /npm install -g kuzushi/);
  assert.throws(() => restoreInstallation(installed, source), /No saved installation/);
});

test("an existing manual source link does not claim a nonexistent backup", (t) => {
  const { installed, source } = fixture(t);
  rmSync(installed, { recursive: true });
  symlinkSync(source, installed, "junction");
  assert.deepEqual(linkCheckout(installed, source), { state: "already linked", backup: undefined });
});

function fixture(t) {
  const root = mkdtempSync(path.join(tmpdir(), "kuzushi-global-link-"));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const installed = path.join(root, "kuzushi");
  const source = path.join(root, "checkout");
  for (const dir of [installed, source]) {
    mkdirSync(dir);
    writeFileSync(path.join(dir, "package.json"), JSON.stringify({ name: "kuzushi" }));
  }
  writeFileSync(path.join(installed, "runtime.txt"), "original runtime");
  return { root, installed, source };
}
