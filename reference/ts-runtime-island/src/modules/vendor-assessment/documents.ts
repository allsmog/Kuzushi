/**
 * Vendor-assessment document attachment — thin shim over the shared
 * attachment subsystem (`src/modules/_shared/attachments`). Vendor's
 * domain-specific filename heuristics are expressed as a `KindSpec` and the
 * actual parsing / kind inference / mime detection lives in the shared
 * package, alongside the threat-model / context / carlini-threat-hunt KBs.
 */

import {
  type KindSpec,
  type AttachDocumentInput as SharedAttachDocumentInput,
  attachDocument as sharedAttachDocument,
  inferKind as sharedInferKind,
} from "../_shared/attachments/index.js";
import type { VendorAssessmentDocument, VendorAssessmentDocumentKind } from "./types.js";

export const VENDOR_KIND_SPEC: KindSpec<VendorAssessmentDocumentKind> = {
  moduleId: "vendor-assessment",
  default: "other",
  kinds: [
    "questionnaire",
    "diagram",
    "transcript",
    "contract",
    "policy",
    "security-report",
    "other",
  ],
  inference: [
    { kind: "questionnaire", pattern: /\b(questionnaire|assessment|intake|survey)\b/ },
    { kind: "diagram", pattern: /\b(diagram|dfd|architecture|arch|flow)\b/ },
    { kind: "transcript", pattern: /\b(transcript|notes|call|meeting)\b/ },
    { kind: "contract", pattern: /\b(contract|terms|dpa|msa|order)\b/ },
    { kind: "policy", pattern: /\b(policy|privacy|security|subprocessor)\b/ },
    { kind: "security-report", pattern: /\b(soc|iso|audit|pentest|pen-test|report)\b/ },
  ],
  label: (kind) => kind,
};

/** Backwards-compatible input shape (matches the original module signature). */
export type AttachDocumentInput = SharedAttachDocumentInput;

/** Domain-typed re-export of the shared inference helper. */
export function inferDocumentKind(source: string, override?: string): VendorAssessmentDocumentKind {
  return sharedInferKind(source, override, VENDOR_KIND_SPEC);
}

/**
 * Attach a vendor document. Delegates to the shared attachment parser using
 * `VENDOR_KIND_SPEC` so the vendor module shares the same parser/PDF/image/
 * size-cap branches as the other KB-enabled modules.
 */
export function attachDocument(input: AttachDocumentInput): VendorAssessmentDocument {
  return sharedAttachDocument(input, VENDOR_KIND_SPEC);
}
