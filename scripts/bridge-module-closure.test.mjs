import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import {
  BRIDGE_ENTRYPOINT,
  bridgeModuleClosure,
  bridgeModuleReferences,
  resolveBridgeModule,
} from "./bridge-module-closure.mjs";

const repo = path.join(import.meta.dirname, "..");

function readerFor(modules) {
  return (module) => {
    if (!Object.hasOwn(modules, module)) {
      throw new Error("ENOENT: no such file");
    }
    return modules[module];
  };
}

test("references cover static, bare, dynamic, and runtime-URL forms", () => {
  const source = [
    'import { a } from "./a.mjs";',
    'export { b } from "./nested/b.mjs";',
    'import "./c.mjs";',
    'const d = await import("./d.mjs");',
    'const worker = new URL("./worker.mjs", import.meta.url);',
  ].join("\n");
  assert.deepEqual(bridgeModuleReferences(source).modules, [
    "./a.mjs",
    "./nested/b.mjs",
    "./c.mjs",
    "./d.mjs",
    "./worker.mjs",
  ]);
});

test("references cover template-literal specifiers", () => {
  const source = [
    "const worker = new URL(`./worker.mjs`, import.meta.url);",
    "const loaded = await import(`./loaded.mjs`);",
  ].join("\n");
  assert.deepEqual(bridgeModuleReferences(source).modules, ["./loaded.mjs", "./worker.mjs"]);
});

test("a loader query or fragment suffix is not part of the module path", () => {
  const source = [
    'await import("./worker.mjs?worker");',
    'const url = new URL("./asset.mjs#inline", import.meta.url);',
  ].join("\n");
  assert.deepEqual(bridgeModuleReferences(source).modules, ["./worker.mjs", "./asset.mjs"]);
});

test("an interpolated specifier is reported rather than silently dropped", () => {
  const source = [
    "await import(`./${name}.mjs`);",
    "const url = new URL(`./engines/${engine}/run.mjs`, import.meta.url);",
  ].join("\n");
  const references = bridgeModuleReferences(source);
  assert.deepEqual(references.modules, []);
  assert.deepEqual(references.unresolvable, ["./${name}.mjs", "./engines/${engine}/run.mjs"]);
});

test("a relative reference that is not a module is out of scope", () => {
  const source = 'const schema = new URL("./schema.json", import.meta.url);';
  assert.deepEqual(bridgeModuleReferences(source), { modules: [], unresolvable: [] });
});

test("references survive a multiline import clause", () => {
  const source = ["import {", "  first,", "  second,", '} from "./wide.mjs";"'].join("\n");
  assert.deepEqual(bridgeModuleReferences(source).modules, ["./wide.mjs"]);
});

test("references ignore bare and node specifiers", () => {
  const source = ['import a from "langchain";', 'import { readFileSync } from "node:fs";'].join(
    "\n",
  );
  assert.deepEqual(bridgeModuleReferences(source).modules, []);
});

test("specifiers resolve against the referencing module's directory", () => {
  assert.equal(
    resolveBridgeModule("scripts/langgraph-bridge.mjs", "./langgraph-bridge/model.mjs"),
    "scripts/langgraph-bridge/model.mjs",
  );
  assert.equal(
    resolveBridgeModule("scripts/langgraph-bridge/model.mjs", "./oauth-models.mjs"),
    "scripts/langgraph-bridge/oauth-models.mjs",
  );
  assert.equal(
    resolveBridgeModule("scripts/langgraph-bridge/model.mjs", "../shared.mjs"),
    "scripts/shared.mjs",
  );
});

test("the closure walks transitively and reports each module once", () => {
  const { modules, failures } = bridgeModuleClosure(
    readerFor({
      "scripts/entry.mjs": 'import "./a.mjs";\nimport "./b.mjs";',
      "scripts/a.mjs": 'import "./shared.mjs";',
      "scripts/b.mjs": 'import "./shared.mjs";',
      "scripts/shared.mjs": "",
    }),
    "scripts/entry.mjs",
  );
  assert.deepEqual(failures, []);
  assert.deepEqual(modules, [
    "scripts/a.mjs",
    "scripts/b.mjs",
    "scripts/entry.mjs",
    "scripts/shared.mjs",
  ]);
});

test("a module cycle terminates", () => {
  const { modules, failures } = bridgeModuleClosure(
    readerFor({
      "scripts/entry.mjs": 'import "./loop.mjs";',
      "scripts/loop.mjs": 'import "./entry.mjs";',
    }),
    "scripts/entry.mjs",
  );
  assert.deepEqual(failures, []);
  assert.deepEqual(modules, ["scripts/entry.mjs", "scripts/loop.mjs"]);
});

test("the closure reports an unresolvable specifier as a contract failure", () => {
  const { modules, failures } = bridgeModuleClosure(
    readerFor({ "scripts/entry.mjs": "await import(`./${engine}.mjs`);" }),
    "scripts/entry.mjs",
  );
  assert.deepEqual(modules, ["scripts/entry.mjs"]);
  assert.equal(failures.length, 1);
  assert.match(
    failures[0],
    /references \.\/\$\{engine\}\.mjs, which the packaging contract cannot resolve/,
  );
});

test("a referenced module that cannot be read is reported, not thrown", () => {
  const { modules, failures } = bridgeModuleClosure(
    readerFor({ "scripts/entry.mjs": 'import "./missing.mjs";' }),
    "scripts/entry.mjs",
  );
  assert.deepEqual(modules, ["scripts/entry.mjs", "scripts/missing.mjs"]);
  assert.equal(failures.length, 1);
  assert.match(failures[0], /scripts\/missing\.mjs must be readable/);
});

test("the shipped bridge closure is readable and matches package.json files", () => {
  const { modules, failures } = bridgeModuleClosure((module) =>
    readFileSync(path.join(repo, module), "utf8"),
  );
  assert.deepEqual(failures, []);
  assert.ok(modules.includes(BRIDGE_ENTRYPOINT));

  const packaged = JSON.parse(readFileSync(path.join(repo, "package.json"), "utf8")).files.filter(
    (entry) => entry === BRIDGE_ENTRYPOINT || entry.startsWith("scripts/langgraph-bridge/"),
  );
  assert.deepEqual(modules, [...packaged].sort());
});
