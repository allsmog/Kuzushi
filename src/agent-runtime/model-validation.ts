import { toErrorMessage } from "../utils.js";
import { parsePiAiModelSpec } from "./model-spec.js";

/**
 * Validate a model override string for the pi-ai runtime.
 *
 * Accepts only `provider:modelId` format — the runtime is single-backend
 * (pi-ai) so no per-backend branching is needed. Returns `null` on success
 * or a human-readable error message describing why the input is invalid.
 */
export function validateModelOverride(model: string): string | null {
  const value = model.trim();
  if (value.length === 0) {
    return "model must be non-empty";
  }
  try {
    parsePiAiModelSpec(value);
    return null;
  } catch (err) {
    return toErrorMessage(err);
  }
}

export function describeModelOverrideFormat(): string {
  return "Model override for this session. pi-ai expects provider:<model>.";
}

export function assertRuntimeModelCompatible(model: string): void {
  const error = validateModelOverride(model);
  if (!error) return;
  throw new Error(
    [
      `Model "${model}" is not a valid pi-ai model spec.`,
      error,
      "Choose a compatible model explicitly with /model use, --model, or config set model.",
      "Kuzushi will not silently switch models or providers.",
    ].join(" "),
  );
}

export function assertRuntimeModelSelection(model: string, fallbackModel?: string): void {
  assertRuntimeModelCompatible(model);
  if (!fallbackModel || fallbackModel.trim().length === 0) return;
  throw new Error(
    [
      `Fallback model "${fallbackModel}" was provided.`,
      "Automatic model fallback is disabled because Kuzushi must not switch models without operator consent.",
      "Choose the intended model explicitly with /model use, --model, or config set model.",
    ].join(" "),
  );
}
