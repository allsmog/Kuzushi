import type { VendorAssessmentProfile } from "./types.js";

export const DEFAULT_VENDOR_ASSESSMENT_PROFILE = "enterprise-ai";

const ENTERPRISE_AI_PROFILE: VendorAssessmentProfile = {
  id: DEFAULT_VENDOR_ASSESSMENT_PROFILE,
  displayName: "Enterprise AI",
  description:
    "AI vendor security review profile for identity, model security, privacy, legal, and integration risk.",
  criticalIntegrations: [
    "Salesforce",
    "Snowflake",
    "Ironclad",
    "Workday",
    "NetSuite",
    "G Suite",
    "Zoom",
  ],
  requiredArtifacts: [
    "security questionnaire",
    "use case statement",
    "integration and data-flow inventory",
    "architecture or data-flow diagram",
  ],
  rubric: {
    domains: [
      "Secure Integration & Identity",
      "AI Model & Infrastructure Security",
      "Privacy & Data Protection",
      "Legal, IP & Compliance",
    ],
    baselineQuestions: [
      "Where are access tokens, refresh tokens, API keys, and service credentials stored, and what encryption protects them at rest?",
      "What OAuth scopes, API permissions, and write capabilities does each integration require, and which are optional?",
      "Which vendor roles can access customer data or credentials, and are those accesses break-glass, ticketed, and audited?",
      "Which actions are deterministic user actions versus AI-generated actions, and what prevents prompt injection from causing unintended writes?",
      "What tenant-isolation controls exist beyond application-layer authorization?",
      "Which data fields are redacted before reaching model providers or downstream processors?",
      "Which model providers receive data, what retention terms apply, and is customer data excluded from training?",
      "How do deletion and subject-rights requests cascade through caches, backups, logs, and sub-processors?",
      "Can the vendor provide a current data-flow diagram with auth method, data class, and network path per flow?",
    ],
  },
};

const PROFILES: Record<string, VendorAssessmentProfile> = {
  [ENTERPRISE_AI_PROFILE.id]: ENTERPRISE_AI_PROFILE,
};

export function getVendorAssessmentProfile(profileId?: string): VendorAssessmentProfile {
  const id = profileId?.trim() || DEFAULT_VENDOR_ASSESSMENT_PROFILE;
  return PROFILES[id] ?? ENTERPRISE_AI_PROFILE;
}

export function listVendorAssessmentProfiles(): VendorAssessmentProfile[] {
  return Object.values(PROFILES);
}
