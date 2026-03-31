import type { KuzushiConfig } from "../types.js";

export type ConfigValidationSeverity = "error" | "warning";

export interface ConfigValidationIssue {
  severity: ConfigValidationSeverity;
  path: string;
  message: string;
  hint?: string;
}

export function validateKuzushiConfig(config: KuzushiConfig): ConfigValidationIssue[] {
  const issues: ConfigValidationIssue[] = [];

  if (config.busBackend !== "in-process") {
    issues.push({
      severity: "error",
      path: "busBackend",
      message: `Unsupported bus backend "${String(config.busBackend)}".`,
      hint: "Use \"in-process\" until a distributed MessageBus adapter is implemented.",
    });
  }

  if (config.pocHarness === true && config.verify !== true) {
    issues.push({
      severity: "error",
      path: "pocHarness",
      message: "PoC harness generation requires verification to be enabled.",
      hint: "Set verify=true when pocHarness=true.",
    });
  }

  if (config.dynamicAnalysisEnabled === true && config.verify !== true) {
    issues.push({
      severity: "error",
      path: "dynamicAnalysisEnabled",
      message: "Dynamic analysis requires verification to be enabled.",
      hint: "Set verify=true before enabling dynamicAnalysisEnabled.",
    });
  }

  if ((config.externalTasks?.length ?? 0) > 0 && config.enableExternalTasks !== true) {
    issues.push({
      severity: "warning",
      path: "externalTasks",
      message: "externalTasks are configured but enableExternalTasks is false, so they will not load.",
      hint: "Set enableExternalTasks=true to activate the configured external tasks.",
    });
  }

  if (config.qualityGates?.failOnExploitable === true && config.verify !== true) {
    issues.push({
      severity: "warning",
      path: "qualityGates.failOnExploitable",
      message: "failOnExploitable is enabled while verification is disabled, so exploitable findings will never be confirmed.",
      hint: "Enable verify=true if you want failOnExploitable to have effect.",
    });
  }

  return issues;
}

export function hasConfigValidationErrors(issues: ReadonlyArray<ConfigValidationIssue>): boolean {
  return issues.some((issue) => issue.severity === "error");
}

export function formatConfigValidationIssue(issue: ConfigValidationIssue): string {
  const location = issue.path ? `${issue.path}: ` : "";
  const hint = issue.hint ? ` (${issue.hint})` : "";
  return `${location}${issue.message}${hint}`;
}
