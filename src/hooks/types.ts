import type { Finding } from "../scanners/types.js";

export interface HookContext {
  repo: string;
  config: Record<string, unknown>;
  timestamp: string;
}

export interface PipelineHooks {
  /** Called before scanning begins. */
  beforeScan?(ctx: HookContext): Promise<void> | void;

  /** Called after scanning, can filter/enrich findings. */
  afterScan?(ctx: HookContext, findings: Finding[]): Promise<Finding[]> | Finding[];

  /** Called before triaging a finding, return null to skip. */
  beforeTriage?(ctx: HookContext, finding: Finding): Promise<Finding | null> | Finding | null;

  /** Called after triaging, can override verdict/confidence. */
  afterTriage?(
    ctx: HookContext,
    finding: Finding,
    result: { verdict: string; confidence: number; rationale: string },
  ):
    | Promise<{ verdict: string; confidence: number; rationale: string }>
    | { verdict: string; confidence: number; rationale: string };

  /** Called after entire pipeline completes. */
  afterAll?(
    ctx: HookContext,
    summary: { findings: Finding[]; stats: Record<string, unknown> },
  ): Promise<void> | void;
}
