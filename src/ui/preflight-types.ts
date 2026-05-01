export interface ConfigConfirmData {
  model: string;
  tasks: string[];
  severity?: string[];
  concurrency?: number;
  verify?: boolean;
  pocHarness?: boolean;
  preset?: string;
  budget?: number;
}

/** Provider ids aligned with pi-ai's builtin providers. */
export type ProviderId =
  | "anthropic"
  | "openai"
  | "google"
  | "mistral"
  | "groq"
  | "cerebras"
  | "xai"
  | "openrouter"
  | "bedrock"
  | "ollama"
  | "inherited";

export type CredentialChoice =
  | { kind: "api-key"; providerId: ProviderId; value: string; baseUrl?: string; persist: boolean }
  | { kind: "base-url"; providerId: ProviderId; baseUrl: string; apiKey?: string; persist: boolean }
  | { kind: "inherited"; providerId?: ProviderId };

export interface WizardResult {
  preset: string;
  /** Default model — first selected in the multi-select pool. */
  model?: string;
  /** Operator-curated pool of models the shell's `/model` switcher offers. */
  availableModels?: string[];
  verify?: boolean;
  pocHarness?: boolean;
  severity?: string[];
  saveLocation?: "project" | "global" | "none";
}
