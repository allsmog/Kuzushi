import type { ToolResult } from "./types.js";

export const ProblemCode = {
  GovernanceBlocked: "governance_blocked",
  InputValidationFailed: "input_validation_failed",
  ToolNotFound: "tool_not_found",
  UpstreamProtocolInvalid: "upstream_protocol_invalid",
} as const;

export type ProblemCode = (typeof ProblemCode)[keyof typeof ProblemCode];

export interface ProblemDetails {
  type: string;
  title: string;
  status: number;
  detail: string;
  code: ProblemCode | string;
  instance?: string;
  errors?: Array<{
    path: string;
    message: string;
    code?: string;
  }>;
}

export function createProblemDetails(args: {
  code: ProblemCode | string;
  title: string;
  detail: string;
  status?: number;
  instance?: string;
  errors?: ProblemDetails["errors"];
}): ProblemDetails {
  const problem: ProblemDetails = {
    type: `https://kuzushi.dev/problems/${args.code}`,
    title: args.title,
    status: args.status ?? 400,
    detail: args.detail,
    code: args.code,
  };
  if (args.instance) problem.instance = args.instance;
  if (args.errors?.length) problem.errors = args.errors;
  return problem;
}

export function problemToolResult(problem: ProblemDetails): ToolResult {
  return {
    ok: false,
    output: problem.detail,
    data: { problem },
  };
}
