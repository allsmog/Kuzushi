import type { ServerResponse } from "node:http";
import { classifyError, type ErrorCategory, KuzushiError } from "./errors.js";
import {
  type ProblemDetails as BaseProblemDetails,
  createProblemDetails as createBaseProblemDetails,
} from "./modules/problem-details.js";
import { toErrorMessage } from "./utils.js";

export interface ProblemDetails extends BaseProblemDetails {
  category: ErrorCategory;
  retryable: boolean;
  details?: unknown;
}

export interface ProblemDetailsInput {
  status: number;
  code: string;
  detail: string;
  title?: string;
  type?: string;
  instance?: string;
  details?: unknown;
  category?: ErrorCategory;
  retryable?: boolean;
}

export class HttpError extends Error {
  readonly status: number;
  readonly code: string;
  readonly title?: string;
  readonly details?: unknown;

  constructor(
    status: number,
    code: string,
    message: string,
    opts: { title?: string; details?: unknown } = {},
  ) {
    super(message);
    this.name = "HttpError";
    this.status = status;
    this.code = code;
    this.title = opts.title;
    this.details = opts.details;
  }
}

const STATUS_TITLES: Record<number, string> = {
  400: "Bad Request",
  401: "Unauthorized",
  403: "Forbidden",
  404: "Not Found",
  405: "Method Not Allowed",
  408: "Request Timeout",
  409: "Conflict",
  415: "Unsupported Media Type",
  422: "Unprocessable Entity",
  429: "Too Many Requests",
  500: "Internal Server Error",
  502: "Bad Gateway",
  503: "Service Unavailable",
  504: "Gateway Timeout",
};

const RETRYABLE_CATEGORIES = new Set<ErrorCategory>(["transient", "rate_limit"]);

export function createProblemDetails(input: ProblemDetailsInput): ProblemDetails {
  const status = normalizeStatus(input.status);
  const category = input.category ?? categoryForStatus(status);
  const problem = createBaseProblemDetails({
    code: input.code,
    title: input.title ?? STATUS_TITLES[status] ?? "Error",
    status,
    detail: input.detail,
    instance: input.instance,
  }) as ProblemDetails;
  if (input.type) {
    problem.type = input.type;
  }
  Object.assign(problem, {
    category,
    retryable: input.retryable ?? RETRYABLE_CATEGORIES.has(category),
  });
  if (input.details !== undefined) problem.details = input.details;
  return problem;
}

export function problemFromError(
  error: unknown,
  fallback: Partial<ProblemDetailsInput> = {},
): ProblemDetails {
  if (error instanceof HttpError) {
    return createProblemDetails({
      status: fallback.status ?? error.status,
      code: fallback.code ?? error.code,
      detail: fallback.detail ?? error.message,
      title: fallback.title ?? error.title,
      type: fallback.type,
      instance: fallback.instance,
      details: fallback.details ?? error.details,
    });
  }

  const status = fallback.status ?? statusForError(error);
  const category =
    error instanceof KuzushiError ? error.category : (fallback.category ?? classifyError(error));
  return createProblemDetails({
    status,
    code: fallback.code ?? codeForCategory(category, status),
    detail: fallback.detail ?? toErrorMessage(error),
    title: fallback.title,
    type: fallback.type,
    instance: fallback.instance,
    details: fallback.details,
    category,
  });
}

export function writeProblemDetails(res: ServerResponse, problem: ProblemDetails): void {
  res.writeHead(problem.status, { "Content-Type": "application/problem+json" });
  res.end(`${JSON.stringify(problem)}\n`);
}

export function statusForErrorCategory(category: ErrorCategory): number {
  switch (category) {
    case "auth":
      return 401;
    case "budget":
      return 402;
    case "rate_limit":
      return 429;
    case "validation":
      return 400;
    case "transient":
      return 503;
    case "fatal":
      return 500;
  }
}

function normalizeStatus(status: number): number {
  return Number.isInteger(status) && status >= 400 && status <= 599 ? status : 500;
}

function categoryForStatus(status: number): ErrorCategory {
  if (status === 401 || status === 403) return "auth";
  if (status === 429) return "rate_limit";
  if (status >= 400 && status < 500) return "validation";
  if (status === 502 || status === 503 || status === 504) return "transient";
  return "fatal";
}

function statusForError(error: unknown): number {
  const category = error instanceof KuzushiError ? error.category : classifyError(error);
  return statusForErrorCategory(category);
}

function codeForCategory(category: ErrorCategory, status: number): string {
  if (status === 404) return "not_found";
  switch (category) {
    case "auth":
      return "auth_error";
    case "budget":
      return "budget_exceeded";
    case "rate_limit":
      return "rate_limited";
    case "validation":
      return "validation_error";
    case "transient":
      return "transient_error";
    case "fatal":
      return "internal_error";
  }
}
