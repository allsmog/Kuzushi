import { describe, expect, it } from "vitest";
import { AuthError, RateLimitError, TransientError } from "../src/errors.js";
import { createProblemDetails, HttpError, problemFromError } from "../src/http-error-response.js";

describe("HTTP problem details", () => {
  it("creates a stable parseable problem shape", () => {
    expect(
      createProblemDetails({
        status: 404,
        code: "not_found",
        detail: "No route matched GET /missing.",
        instance: "/missing",
      }),
    ).toEqual({
      type: "https://kuzushi.dev/problems/not_found",
      title: "Not Found",
      status: 404,
      detail: "No route matched GET /missing.",
      code: "not_found",
      category: "validation",
      retryable: false,
      instance: "/missing",
    });
  });

  it("maps typed HTTP errors without leaking stack traces", () => {
    const problem = problemFromError(new HttpError(422, "invalid_input", "repoRoot is required"));

    expect(problem).toMatchObject({
      type: "https://kuzushi.dev/problems/invalid_input",
      title: "Unprocessable Entity",
      status: 422,
      detail: "repoRoot is required",
      code: "invalid_input",
      category: "validation",
      retryable: false,
    });
    expect(JSON.stringify(problem)).not.toContain("stack");
  });

  it("maps Kuzushi error categories to client-facing HTTP status and retryability", () => {
    expect(problemFromError(new AuthError("missing token"))).toMatchObject({
      status: 401,
      code: "auth_error",
      category: "auth",
      retryable: false,
    });
    expect(problemFromError(new RateLimitError("429 too many requests"))).toMatchObject({
      status: 429,
      code: "rate_limited",
      category: "rate_limit",
      retryable: true,
    });
    expect(problemFromError(new TransientError("upstream unavailable"))).toMatchObject({
      status: 503,
      code: "transient_error",
      category: "transient",
      retryable: true,
    });
  });
});
