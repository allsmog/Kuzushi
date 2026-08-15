#!/usr/bin/env node
// Provisions the `upstream-codex` git remote used for substrate diffing against
// https://github.com/openai/codex. This is contributor convenience, not a
// repository contract: nothing in the build reads the remote, so a contributor
// who deliberately points it at a fork or mirror keeps their URL untouched.
//
// Setup owns this side effect. Gates assert committed repository content and
// must not probe (or mutate) a developer's local git configuration.
import { execFileSync } from "node:child_process";
import path from "node:path";
import { pathToFileURL } from "node:url";

export const UPSTREAM_REMOTE_NAME = "upstream-codex";
export const UPSTREAM_REMOTE_URL = "https://github.com/openai/codex.git";

// Decides what to do about the remote without touching git, so the policy is
// testable on its own. `currentUrl` is null when the remote does not exist.
export function planUpstreamRemote(currentUrl) {
  if (currentUrl === null) return { action: "add", url: UPSTREAM_REMOTE_URL };
  if (currentUrl === UPSTREAM_REMOTE_URL) return { action: "keep", url: currentUrl };
  return { action: "diverged", url: currentUrl };
}

export function describeUpstreamRemotePlan(plan) {
  switch (plan.action) {
    case "add":
      return `added git remote ${UPSTREAM_REMOTE_NAME} -> ${plan.url}`;
    case "keep":
      return `git remote ${UPSTREAM_REMOTE_NAME} already points at ${plan.url}`;
    default:
      return `left git remote ${UPSTREAM_REMOTE_NAME} at ${plan.url} (expected ${UPSTREAM_REMOTE_URL})`;
  }
}

function readRemoteUrl(cwd) {
  try {
    return execFileSync("git", ["remote", "get-url", UPSTREAM_REMOTE_NAME], {
      cwd,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
    }).trim();
  } catch {
    return null;
  }
}

export function ensureUpstreamRemote(cwd = process.cwd()) {
  const plan = planUpstreamRemote(readRemoteUrl(cwd));
  if (plan.action === "add") {
    // Keep git's stderr so a failure reports why (unwritable config, not a
    // repository) instead of an opaque non-zero exit.
    execFileSync("git", ["remote", "add", UPSTREAM_REMOTE_NAME, plan.url], {
      cwd,
      encoding: "utf8",
      stdio: ["ignore", "ignore", "pipe"],
    });
  }
  return plan;
}

export function describeUpstreamRemoteFailure(error) {
  const reason = String(error?.stderr || error?.message || error).trim();
  return `could not configure ${UPSTREAM_REMOTE_NAME}: ${reason.split("\n")[0] || "unknown error"}`;
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  try {
    console.log(describeUpstreamRemotePlan(ensureUpstreamRemote()));
  } catch (error) {
    console.error(describeUpstreamRemoteFailure(error));
    process.exit(1);
  }
}
