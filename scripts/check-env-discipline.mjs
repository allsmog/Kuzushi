#!/usr/bin/env node
import { readFileSync } from "node:fs";
import path from "node:path";

const root = process.cwd();

const checks = [
  {
    file: "crates/kuzushi-core/src/modules/pwn/mod.rs",
    required: ["revngImage", "revngNative", "revngContainerRuntime"],
    forbidden: ["KUZUSHI_REVNG_IMAGE", "KUZUSHI_REVNG_NATIVE", "KUZUSHI_REVNG_CONTAINER_RUNTIME"],
  },
  {
    file: "crates/kuzushi-core/src/modules/codeql_db_module.rs",
    required: ["prepared_codeql_launcher"],
    forbidden: ["KUZUSHI_CODEQL_BIN"],
  },
  {
    file: "crates/kuzushi-core/src/codeql_repository_execution/launcher.rs",
    required: ['"codeqlBin"', "CODEQL_LAUNCHER_INPUT_KEY", "bind_codeql_launcher"],
    forbidden: [],
  },
  {
    file: "crates/kuzushi-openai/src/langgraph_runtime/runtime_impl.rs",
    required: ["credential_for_model", "bridge_api_key_env_for_model"],
    forbidden: ["MODEL_", "model_fallback", "fallback_model"],
  },
];

const failures = checks.flatMap(({ file, required, forbidden }) => {
  const source = readFileSync(path.join(root, file), "utf8");
  return [
    ...required
      .filter((needle) => !source.includes(needle))
      .map((needle) => `${file} must keep option/config boundary token ${needle}`),
    ...forbidden
      .filter((needle) => source.includes(needle))
      .map((needle) => `${file} must not read product-behavior env token ${needle}`),
  ];
});

if (failures.length > 0) {
  console.error("Env discipline contract failed:");
  for (const failure of failures) console.error(`- ${failure}`);
  process.exit(1);
}

console.log("env discipline contract passed");
