const HTTP_STATUS_MIN = 100;
const HTTP_STATUS_MAX = 599;

const PUBLIC_FAILURES = Object.freeze({
  allowance_refused: "Investigation allowance refused this request; finish and report or review the remaining work.",
  authentication: "Provider authentication failed.",
  bridge_internal: "Bridge operation failed; raw error details were suppressed.",
  cancelled: "Bridge operation was cancelled.",
  mcp_timeout: "MCP tool request timed out.",
  mcp_unavailable:
    "Restore the missing code-analysis component: from source run `cargo build --workspace`; otherwise reinstall Kuzushi.",
  provider_rejected: "Provider rejected the request.",
  provider_response_invalid: "Provider returned an invalid response.",
  provider_unavailable: "Provider is temporarily unavailable.",
  rate_limited: "Provider rate limited the request.",
  sdk_client_validation:
    "Provider SDK rejected incompatible client-side invocation parameters before sending.",
  timeout: "Provider request timed out.",
  transport: "Provider request failed before a response was received.",
});

const STATUS_ERROR_CLASSES = new Map([
  [401, "authentication"],
  [403, "authentication"],
  [408, "timeout"],
  [425, "rate_limited"],
  [429, "rate_limited"],
]);

export class BridgePublicError extends Error {
  constructor(errorClass, status, options) {
    super(publicFailureMessage(errorClass, status), options);
    this.name = "BridgePublicError";
    this.errorClass = allowedErrorClass(errorClass) ?? "bridge_internal";
    this.status = httpStatus(status);
  }
}

export function providerHttpError(status) {
  return new BridgePublicError(errorClassForStatus(status), status);
}

export async function providerResponseError(response) {
  const error = providerHttpError(response.status);
  try {
    const payload = JSON.parse((await response.text()).slice(0, 16_384));
    error.detail = unavailableModelDetail(error.errorClass, payload);
  } catch {
    // A missing or malformed error body must not hide the known HTTP status.
  }
  return error;
}

export function invalidProviderResponseError() {
  return new BridgePublicError("provider_response_invalid");
}

export function bridgeErrorResponse(error) {
  const failure = classifyBridgeError(error);
  const retryAfterSeconds = retryAfterSecondsFromError(error);
  const detail = bridgeErrorDetail(error, failure.errorClass);
  return {
    ok: false,
    error: publicFailureMessage(failure.errorClass, failure.status),
    errorClass: failure.errorClass,
    ...(failure.status === undefined ? {} : { status: failure.status }),
    ...(retryAfterSeconds === undefined ? {} : { retryAfterSeconds }),
    ...(detail === undefined ? {} : { detail }),
  };
}

const ADAPTIVE_THINKING_DETAIL =
  "temperature is incompatible with adaptive thinking; omit the pinned temperature";
const MODEL_UNAVAILABLE_DETAIL =
  "The selected model is unavailable for this provider or account. Choose an available model explicitly.";
export const CONTEXT_OVERFLOW_DETAIL =
  "The request exceeded the model's context window. Narrow the investigation or choose a model with a larger window.";

function unavailableModelDetail(errorClass, payload) {
  if (errorClass !== "provider_rejected") return undefined;
  const message = payload?.error?.message ?? payload?.detail;
  const text = typeof message === "string" ? message.toLowerCase() : "";
  const unavailable = /\bmodel(?: ['"][^'"]{1,128}['"])? is not supported\b/.test(text);
  return payload?.error?.code === "model_not_found" || unavailable
    ? MODEL_UNAVAILABLE_DETAIL
    : undefined;
}

/** Only canonical operator guidance crosses the durable protocol. Raw SDK and
 * provider messages may contain proprietary source even after secret redaction. */
export function bridgeErrorDetail(error, errorClass) {
  if (error instanceof BridgePublicError && errorClass === "provider_rejected") {
    return error.detail === MODEL_UNAVAILABLE_DETAIL ? MODEL_UNAVAILABLE_DETAIL : undefined;
  }
  if (errorClass === "provider_rejected" && isContextOverflow(error)) return CONTEXT_OVERFLOW_DETAIL;
  if (errorClass !== "sdk_client_validation") return undefined;
  const message = boundedLower(error?.message);
  return message.includes("temperature") && message.includes("thinking")
    ? ADAPTIVE_THINKING_DETAIL
    : undefined;
}

// LangChain names the provider's "prompt is too long" rejection; match only
// that name or the provider's fixed phrase, never echo the body.
function isContextOverflow(error) {
  const name = boundedLower(error?.name);
  return name === "contextoverflowerror" || boundedLower(error?.message).includes("prompt is too long");
}

const RETRY_AFTER_MAX_SECONDS = 300;

/** Provider-declared wait before the next attempt (rate limits). Only the
 * delta-seconds form is honored; HTTP-date values are ignored rather than
 * trusting clock math on an adversarial header. */
function retryAfterSecondsFromError(error) {
  const headers = error?.headers ?? error?.response?.headers ?? error?.cause?.headers;
  const raw =
    typeof headers?.get === "function" ? headers.get("retry-after") : headers?.["retry-after"];
  const seconds = Number(typeof raw === "string" ? raw.trim() : raw);
  if (!Number.isInteger(seconds) || seconds <= 0) return undefined;
  return Math.min(seconds, RETRY_AFTER_MAX_SECONDS);
}

function classifyBridgeError(error) {
  const status = statusFromError(error);
  const trustedClass = error instanceof BridgePublicError ? error.errorClass : undefined;
  if (trustedClass === "mcp_timeout" || explicitMcpTimeoutClass(error)) {
    return { errorClass: "mcp_timeout" };
  }
  if (trustedClass) return { errorClass: trustedClass, status };
  if (status !== undefined) return { errorClass: errorClassForStatus(status), status };
  return { errorClass: errorClassFromShape(error) };
}

function explicitMcpTimeoutClass(error) {
  const name = boundedLower(error?.name);
  const code = boundedLower(error?.code ?? error?.cause?.code);
  return mcpTimeoutClass(name, code);
}

function statusFromError(error) {
  return [error?.status, error?.statusCode, error?.response?.status, error?.cause?.status]
    .map(httpStatus)
    .find((status) => status !== undefined);
}

function errorClassFromShape(error) {
  const name = boundedLower(error?.name);
  const code = boundedLower(error?.code ?? error?.cause?.code);
  const message = boundedLower(error?.message);
  return (
    cancellationClass(name, message) ??
    mcpTimeoutClass(name, code) ??
    rateLimitClass(name, message) ??
    timeoutClass(code, message) ??
    transportClass(name, code, message) ??
    authenticationClass(message) ??
    sdkClientValidationClass(name, message) ??
    "bridge_internal"
  );
}

// Provider SDKs sometimes reject absent local credentials before making a
// request and expose neither an HTTP status nor a stable error code. Keep the
// match deliberately narrow and surface only the generic public auth message.
function authenticationClass(message) {
  const missingCredential =
    message.includes("missing credentials") ||
    message.includes("missing api key") ||
    message.includes("api key not found");
  return missingCredential ? "authentication" : undefined;
}

// LangChain provider adapters validate invocation params client-side (e.g.
// `temperature` pinned on an adaptive-thinking-only model) and throw before
// any network call. Without this class the failure lands in bridge_internal
// and the actionable cause is invisible to the operator.
function sdkClientValidationClass(name, message) {
  const validationName = name.includes("invocationparam") || name.includes("invalidargument");
  const validationMessage =
    message.includes("invocation param") ||
    message.includes("not compatible with") ||
    (message.includes("temperature") && message.includes("thinking"));
  return validationName || validationMessage ? "sdk_client_validation" : undefined;
}

// Some SDK layers wrap provider 429s (e.g. `RateLimitCapacityError`) without
// exposing an HTTP status field; classify by shape so the runtime's
// transient-failure retry policy still engages.
function rateLimitClass(name, message) {
  const rateLimitedName = name.includes("ratelimit");
  const rateLimitedMessage =
    message.includes("resource_exhausted") || message.startsWith("429 ") || message.includes(" 429 ");
  return rateLimitedName || rateLimitedMessage ? "rate_limited" : undefined;
}

function mcpTimeoutClass(name, code) {
  const marked = name === "mcptooltimeouterror" || code === "kuzushi_mcp_tool_timeout";
  return marked ? "mcp_timeout" : undefined;
}

function cancellationClass(name, message) {
  return name === "aborterror" || message.includes("cancelled") ? "cancelled" : undefined;
}

function timeoutClass(code, message) {
  return code.includes("timeout") || message.includes("timed out") ? "timeout" : undefined;
}

function transportClass(name, code, message) {
  const networkCode = ["econnreset", "econnrefused", "enotfound", "enetunreach"].includes(code);
  const fetchFailure = name === "typeerror" && message.includes("fetch");
  return networkCode || fetchFailure ? "transport" : undefined;
}

function errorClassForStatus(status) {
  return STATUS_ERROR_CLASSES.get(status) ??
    (status >= 500 ? "provider_unavailable" : "provider_rejected");
}

function publicFailureMessage(errorClass, status) {
  const base = PUBLIC_FAILURES[allowedErrorClass(errorClass) ?? "bridge_internal"];
  const safeStatus = httpStatus(status);
  return safeStatus === undefined ? base : `${base.slice(0, -1)} (HTTP ${safeStatus}).`;
}

function allowedErrorClass(value) {
  return typeof value === "string" && Object.hasOwn(PUBLIC_FAILURES, value) ? value : undefined;
}

function httpStatus(value) {
  const status = Number(value);
  return Number.isInteger(status) && status >= HTTP_STATUS_MIN && status <= HTTP_STATUS_MAX
    ? status
    : undefined;
}

function boundedLower(value) {
  return typeof value === "string" ? value.slice(0, 512).toLowerCase() : "";
}
