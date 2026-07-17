#!/usr/bin/env node
// typecheck-all.mjs — Run every TypeScript project check in parallel.
//
// Runs every project declared in typescript-projects.mjs concurrently
// and interleaves their output with short prefixes so failures are easy to
// attribute.
//
// Exit code: max of child exit codes (nonzero if any project failed).

import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { TYPESCRIPT_PROJECTS } from "./typescript-projects.mjs";

const __filename = fileURLToPath(import.meta.url);
const REPO_ROOT = resolve(dirname(__filename), "..");

// Resolve tsc from the repo's node_modules so we don't depend on PATH —
// `pnpm run <script>` adds node_modules/.bin to PATH, but `node scripts/…` doesn't.
const LOCAL_TSC = resolve(
  REPO_ROOT,
  "node_modules",
  ".bin",
  process.platform === "win32" ? "tsc.cmd" : "tsc",
);
const TSC = existsSync(LOCAL_TSC) ? LOCAL_TSC : "tsc";

const projects = TYPESCRIPT_PROJECTS.map(({ name, config }) => ({
  name,
  cmd: TSC,
  args: ["-p", config, "--noEmit"],
}));

const COLORS = process.stdout.isTTY
  ? {
      reset: "\x1b[0m",
      dim: "\x1b[2m",
      bold: "\x1b[1m",
      cyan: "\x1b[36m",
      green: "\x1b[32m",
      red: "\x1b[31m",
      yellow: "\x1b[33m",
    }
  : { reset: "", dim: "", bold: "", cyan: "", green: "", red: "", yellow: "" };

const label = (name) => `${COLORS.cyan}[${name}]${COLORS.reset}`;

function runProject({ name, cmd, args }) {
  return new Promise((resolve) => {
    const start = Date.now();
    process.stdout.write(`${label(name)} ${COLORS.dim}tsc ${args.join(" ")}${COLORS.reset}\n`);

    const child = spawn(cmd, args, {
      cwd: REPO_ROOT,
      env: process.env,
      stdio: ["ignore", "pipe", "pipe"],
    });

    const forward = (stream, dest) => {
      let buf = "";
      stream.on("data", (chunk) => {
        buf += chunk.toString("utf8");
        let idx = buf.indexOf("\n");
        while (idx !== -1) {
          const line = buf.slice(0, idx);
          dest.write(`${label(name)} ${line}\n`);
          buf = buf.slice(idx + 1);
          idx = buf.indexOf("\n");
        }
      });
      stream.on("end", () => {
        if (buf.length > 0) dest.write(`${label(name)} ${buf}\n`);
      });
    };

    forward(child.stdout, process.stdout);
    forward(child.stderr, process.stderr);

    child.on("error", (err) => {
      process.stderr.write(
        `${label(name)} ${COLORS.red}spawn error: ${err.message}${COLORS.reset}\n`,
      );
      resolve({ name, code: 1, ms: Date.now() - start });
    });
    child.on("close", (code) => {
      resolve({ name, code: code ?? 1, ms: Date.now() - start });
    });
  });
}

const results = await Promise.all(projects.map(runProject));

process.stdout.write("\n");
let worst = 0;
for (const { name, code, ms } of results) {
  const status =
    code === 0
      ? `${COLORS.green}✓ pass${COLORS.reset}`
      : `${COLORS.red}✗ fail (exit ${code})${COLORS.reset}`;
  process.stdout.write(
    `  ${label(name).padEnd(20)} ${status}  ${COLORS.dim}${ms}ms${COLORS.reset}\n`,
  );
  if (code > worst) worst = code;
}

process.exit(worst);
