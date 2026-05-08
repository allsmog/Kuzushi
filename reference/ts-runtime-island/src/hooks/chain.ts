import type { Finding } from "../scanners/types.js";
import type { HookContext, PipelineHooks } from "./types.js";

/**
 * Chains multiple PipelineHooks objects into a single composite hook.
 * Hooks are executed in order; transformer hooks (afterScan, beforeTriage,
 * afterTriage) pipe their output forward through the chain.
 */
export class PipelineHookChain implements PipelineHooks {
  private hooks: PipelineHooks[];

  constructor(hooks: PipelineHooks[]) {
    this.hooks = hooks;
  }

  get length(): number {
    return this.hooks.length;
  }

  async beforeScan(ctx: HookContext): Promise<void> {
    for (const h of this.hooks) {
      if (h.beforeScan) {
        await h.beforeScan(ctx);
      }
    }
  }

  async afterScan(ctx: HookContext, findings: Finding[]): Promise<Finding[]> {
    let result = findings;
    for (const h of this.hooks) {
      if (h.afterScan) {
        result = await h.afterScan(ctx, result);
      }
    }
    return result;
  }

  async beforeTriage(ctx: HookContext, finding: Finding): Promise<Finding | null> {
    let result: Finding | null = finding;
    for (const h of this.hooks) {
      if (result === null) break;
      if (h.beforeTriage) {
        result = await h.beforeTriage(ctx, result);
      }
    }
    return result;
  }

  async afterTriage(
    ctx: HookContext,
    finding: Finding,
    triageResult: { verdict: string; confidence: number; rationale: string },
  ): Promise<{ verdict: string; confidence: number; rationale: string }> {
    let result = triageResult;
    for (const h of this.hooks) {
      if (h.afterTriage) {
        result = await h.afterTriage(ctx, finding, result);
      }
    }
    return result;
  }

  async afterAll(
    ctx: HookContext,
    summary: { findings: Finding[]; stats: Record<string, unknown> },
  ): Promise<void> {
    for (const h of this.hooks) {
      if (h.afterAll) {
        await h.afterAll(ctx, summary);
      }
    }
  }
}
