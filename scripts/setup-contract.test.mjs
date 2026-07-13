import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");

test("bootstrap and devcontainer enforce the pinned complete Rust toolchain", () => {
  const toolchain = readFileSync(resolve(repoRoot, "rust-toolchain.toml"), "utf8");
  const channel = toolchain.match(/^channel\s*=\s*"([^"]+)"/m)?.[1];
  assert.ok(channel, "rust-toolchain.toml must declare a channel");
  assert.match(toolchain, /components\s*=\s*\[[^\]]*"clippy"[^\]]*"rustfmt"/);

  const bootstrap = readFileSync(resolve(repoRoot, "scripts/bootstrap.sh"), "utf8");
  assert.match(bootstrap, /RUSTC_VERSION_LINE=.*rustc --version/);
  assert.match(bootstrap, /RUSTC_ACTUAL_VERSION=/);
  assert.match(bootstrap, /RUSTC_ACTUAL_VERSION.*PINNED_RUST_VERSION/);
  assert.match(bootstrap, /cargo clippy --version/);
  assert.match(bootstrap, /command -v "\$tool"/);

  const devcontainer = JSON.parse(
    readFileSync(resolve(repoRoot, ".devcontainer/devcontainer.json"), "utf8"),
  );
  const rust = devcontainer.features["ghcr.io/devcontainers/features/rust:1"];
  assert.equal(rust.version, channel);
  assert.deepEqual(new Set(rust.components.split(",")), new Set(["rustfmt", "clippy"]));
});

test("devcontainer and doctor share the exact Semgrep dependency pin", () => {
  const requirements = readFileSync(resolve(repoRoot, ".github/requirements-ci.txt"), "utf8");
  const semgrepVersion = requirements.match(/^semgrep==([^\s#]+)$/m)?.[1];
  assert.ok(semgrepVersion, "requirements-ci.txt must contain an exact Semgrep pin");

  const devcontainer = JSON.parse(
    readFileSync(resolve(repoRoot, ".devcontainer/devcontainer.json"), "utf8"),
  );
  assert.match(
    devcontainer.postCreateCommand,
    /python -m pip install --user --no-cache-dir -r \.github\/requirements-ci\.txt/,
  );
  assert.doesNotMatch(devcontainer.postCreateCommand, /pip install[^&]*\bsemgrep\b/);

  const doctor = readFileSync(resolve(repoRoot, "scripts/doctor.sh"), "utf8");
  assert.match(doctor, /SEMGREP_REQUIREMENTS_FILE=/);
  assert.match(doctor, /PINNED_SEMGREP_VERSION=/);
  assert.match(doctor, /SEMGREP_VERSION.*PINNED_SEMGREP_VERSION/);
});
