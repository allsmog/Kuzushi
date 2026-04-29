import path from "node:path";
import { resolveRepo } from "../cli/shared.js";
import type { ExecutionContext } from "./types.js";

export function resolveModuleTarget(
  ctx: ExecutionContext,
  input?: string,
): ReturnType<typeof resolveRepo> {
  const raw = input?.trim();
  const base = raw ? ctx.cwd : (ctx.target ?? ctx.cwd);
  const target = raw ? (path.isAbsolute(raw) ? raw : path.resolve(base, raw)) : base;
  return resolveRepo(target);
}
