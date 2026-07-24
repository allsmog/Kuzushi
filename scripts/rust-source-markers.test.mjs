import assert from "node:assert/strict";
import test from "node:test";
import { hasActiveRustModule } from "./rust-source-markers.mjs";

const moduleName = "run_lifecycle_semantic_equivalence_tests";
const declaration = `mod ${moduleName};`;

test("active Rust module declarations are detected", () => {
  assert.equal(hasActiveRustModule(declaration, moduleName), true);
});

test("commented and quoted Rust module markers are rejected", () => {
  const inactiveSources = [
    `// ${declaration}`,
    `/* ${declaration} */`,
    `/* outer /* nested */ ${declaration} */`,
    `const MARKER: &str = "${declaration}";`,
    `const MARKER: &str = r#"\n${declaration}\n"#;`,
  ];
  for (const source of inactiveSources) {
    assert.equal(hasActiveRustModule(source, moduleName), false, source);
  }
});
