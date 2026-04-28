import type {
  AttachmentDocument,
  AttachmentStatus,
  KindSpec,
} from "../_shared/attachments/index.js";

export type VendorAssessmentDocumentKind =
  | "questionnaire"
  | "diagram"
  | "transcript"
  | "contract"
  | "policy"
  | "security-report"
  | "other";

/** Re-export of the shared status enum so callers don't have to import twice. */
export type VendorAssessmentDocumentStatus = AttachmentStatus;

/**
 * Vendor-assessment documents are now an alias of the shared
 * `AttachmentDocument<K>` shape. Persisted layout is unchanged because the
 * fields are identical — vendor just picks the kind enum.
 */
export type VendorAssessmentDocument = AttachmentDocument<VendorAssessmentDocumentKind>;

/** Convenience re-export — vendor's KindSpec lives in `documents.ts`. */
export type VendorAssessmentKindSpec = KindSpec<VendorAssessmentDocumentKind>;

export interface VendorAssessmentScope {
  vendorName?: string;
  productName?: string;
  primaryDomain?: string;
  useCase?: string;
  profile: string;
  dataClasses: string[];
  integrations: string[];
  documents: VendorAssessmentDocument[];
  updatedAt: string;
}

export interface VendorAssessmentProfile {
  id: string;
  displayName: string;
  description: string;
  criticalIntegrations: string[];
  requiredArtifacts: string[];
  rubric: {
    domains: string[];
    baselineQuestions: string[];
  };
}

export interface VendorAssessmentCompletenessGate {
  useCase: "yes" | "partial" | "no";
  integrations: "yes" | "partial" | "no";
  architectureDiagram: "yes" | "partial" | "no";
  missingArtifacts: string[];
  failed: boolean;
}

export interface VendorAssessmentReportJson {
  runId: string;
  generatedAt: string;
  profile: string;
  mode: "document-backed" | "intake";
  confidence: "document-backed" | "intake" | "low";
  vendor: {
    name?: string;
    product?: string;
    domain?: string;
  };
  overallRisk: "Critical" | "High" | "Medium" | "Low";
  criticalIntegrations: string[];
  completenessGate: VendorAssessmentCompletenessGate;
  documents: Array<{
    id: string;
    title: string;
    kind: VendorAssessmentDocumentKind;
    status: VendorAssessmentDocumentStatus;
    source: string;
    warnings: string[];
  }>;
  weaknesses: Array<{
    id: string;
    severity: "Critical" | "High" | "Medium" | "Low";
    confidence: "High" | "Medium" | "Low";
    summary: string;
  }>;
  mitigations: string[];
  questions: string[];
  artifacts: {
    scopePath: string;
    reportPath: string;
    reportJsonPath: string;
    promptsDir: string;
  };
  validation: {
    appendixParsed: boolean;
    warnings: string[];
  };
}

export interface VendorAssessmentHomeSlice {
  scopePath?: string;
  vendorName?: string;
  profile: string;
  confidence: "empty" | "document-backed" | "intake" | "low";
  documents: Array<{
    title: string;
    kind: VendorAssessmentDocumentKind;
    status: VendorAssessmentDocumentStatus;
    detail: string;
  }>;
  missingArtifacts: string[];
  lastRun?: {
    runId: string;
    overallRisk: VendorAssessmentReportJson["overallRisk"];
    reportPath: string;
  };
}
