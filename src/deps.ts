import type { KuzushiConfig, LLMClient, RawFinding, ScanOpts, TriageResult } from "./types.js";
import { runSemgrep, selectFindings } from "./scanner.js";
import { triageFinding } from "./triage.js";
import { readFileContext } from "./context.js";
import { createAnthropicClient } from "./llm/anthropic.js";
import { resolveScanner } from "./scanner/resolve.js";

/** Dependency injection bag — plain object, not a framework. */
export interface KuzushiDeps {
  runScanner: (repoPath: string, opts: ScanOpts) => Promise<RawFinding[]>;
  triageFinding: (
    finding: RawFinding,
    codeContext: string,
    repoName: string,
  ) => Promise<TriageResult>;
  readFileContext: (
    filePath: string,
    line: number,
    radius: number,
  ) => Promise<string>;
}

/** Wire real implementations. Resolves scanner binary and LLM from config. */
export async function createDefaultDeps(config: KuzushiConfig, llm?: LLMClient): Promise<KuzushiDeps> {
  const client = llm ?? createAnthropicClient(config.model, config.maxTokens);
  const scannerBin = await resolveScanner();

  return {
    async runScanner(repoPath, opts) {
      const semgrepOutput = await runSemgrep(repoPath, opts, scannerBin);
      const repoName = repoPath.split("/").pop() ?? "unknown";
      return selectFindings(semgrepOutput, repoName, "HEAD", opts.maxFindings);
    },
    triageFinding: (finding, codeContext, repoName) =>
      triageFinding(client, finding, codeContext, repoName),
    readFileContext,
  };
}
