import { copyFileSync, mkdirSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const contracts = [
  "model.test.mjs",
  "mcp.test.mjs",
  "tool-schema.test.mjs",
  "response-stream.test.mjs",
];

// Only test files are injected. Their relative imports execute the installed
// package's bridge and npm-resolved production dependencies.
export function exerciseConsumerBridge(packageRoot, run) {
  const installed = join(packageRoot, "scripts", "langgraph-bridge");
  mkdirSync(installed, { recursive: true });
  const tests = contracts.map((name) => {
    const destination = join(installed, name);
    copyFileSync(
      fileURLToPath(new URL(`./langgraph-bridge/${name}`, import.meta.url)),
      destination,
    );
    return destination;
  });
  run("consumer bridge contracts", process.execPath, ["--test", ...tests], { cwd: packageRoot });
}
