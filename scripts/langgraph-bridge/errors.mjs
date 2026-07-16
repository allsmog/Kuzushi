const HTTP_STATUS_MIN = 100;
const HTTP_STATUS_MAX = 599;

const PUBLIC_FAILURES = Object.freeze({
  authentication: "Provider authentication failed.",
  bridge_internal: "Bridge operation failed; raw error details were suppressed.",
  cancelled: "Bridge operation was cancelled.",
  provider_rejected: "Provider rejected the request.",
  provider_response_invalid: "Provider returned an invalid response.",
  provider_unavailable: "Provider is temporarily unavailable.",
  rate_limited: "Provider rate limited the request.",
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
  constructor(errorClass, status) {
    super(publicFailureMessage(errorClass, status));
    this.name = "BridgePublicError";
    this.errorClass = allowedErrorClass(errorClass) ?? "bridge_internal";
    this.status = httpStatus(status);
  }
}

export function providerHttpError(status) {
  return new BridgePublicError(errorClassForStatus(status), status);
}

export function invalidProviderResponseError() {
  return new BridgePublicError("provider_response_invalid");
}

export function bridgeErrorResponse(error) {
  const failure = classifyBridgeError(error);
  return {
    ok: false,
    error: publicFailureMessage(failure.errorClass, failure.status),
    errorClass: failure.errorClass,
    ...(failure.status === undefined ? {} : { status: failure.status }),
  };
}

function classifyBridgeError(error) {
  const status = statusFromError(error);
  const trustedClass = error instanceof BridgePublicError ? error.errorClass : undefined;
  if (trustedClass) return { errorClass: trustedClass, status };
  if (status !== undefined) return { errorClass: errorClassForStatus(status), status };
  return { errorClass: errorClassFromShape(error) };
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
    timeoutClass(code, message) ??
    transportClass(name, code, message) ??
    "bridge_internal"
  );
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
