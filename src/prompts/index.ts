export {
  antiHallucinationModule,
  confidenceEscalationModule,
  frameworkAwarenessModule,
  falseDismissalModule,
  bypassExhaustionModule,
  proofLevelModule,
  knowledgeInjectionModule,
  composePromptModules,
  type AntiHallucinationOpts,
} from "./modules.js";

export { renderTemplate, validateTemplate, type TemplateContext } from "./template.js";
export { buildTriageContext, buildVerifyContext } from "./context.js";
export type { TriageTemplateContext, VerifyTemplateContext } from "./context.js";
export {
  TRIAGE_TEMPLATE,
  BATCH_TRIAGE_HEADER_TEMPLATE,
  BATCH_TRIAGE_FINDING_TEMPLATE,
  BATCH_TRIAGE_FOOTER_TEMPLATE,
} from "./templates/triage.js";
export {
  VERIFY_TEMPLATE,
  VERIFY_ARCHITECTURAL_TEMPLATE,
  BATCH_VERIFY_HEADER_TEMPLATE,
  BATCH_VERIFY_FINDING_TEMPLATE,
  BATCH_VERIFY_FOOTER_TEMPLATE,
} from "./templates/verify.js";
