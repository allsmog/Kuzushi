const snapshotMarkerShapeSpecs = [
  { path: ["properties", "runId"], type: "string" },
  { path: ["properties", "status"], ref: "#/definitions/runStatus" },
  { path: ["properties", "runStatus"], ref: "#/definitions/runStatus" },
  { path: ["properties", "summary"], type: "string" },
  { path: ["properties", "artifacts"], type: "array" },
  { path: ["properties", "warnings"], type: "array", itemType: "string" },
  { path: ["properties", "errors"], type: "array", itemType: "string" },
];

const fieldShapeSpecs = {
  "schemas/run.context.schema.json": [
    ...snapshotMarkerShapeSpecs,
    { path: ["properties", "context"], type: "object" },
    { path: ["properties", "contextSnapshot"], type: "object" },
    { path: ["properties", "filesIndexed"], type: "integer", minimum: 0 },
    { path: ["properties", "repoContext"], type: "object" },
    { path: ["properties", "repositoryInventory"], ref: "#/definitions/repositoryInventory" },
    { path: ["properties", "attackSurfaceMap"], ref: "#/definitions/attackSurfaceMap" },
    { path: ["properties", "fileIndex"], ref: "#/definitions/fileIndex" },
    { path: ["properties", "appModel"], ref: "#/definitions/appModel" },
    {
      path: ["definitions", "repositoryInventory", "properties", "routesControllers"],
      type: "array",
      itemRef: "#/definitions/inventoryRoute",
    },
    {
      path: ["definitions", "attackSurfaceMap", "properties", "surfaces"],
      type: "array",
      itemRef: "#/definitions/attackSurface",
    },
    {
      path: ["definitions", "attackSurface", "properties", "method"],
      ref: "#/definitions/routeMethod",
    },
    { path: ["definitions", "fileIndex", "properties", "totalFiles"], type: "integer", minimum: 0 },
    { path: ["definitions", "fileIndex", "properties", "truncated"], type: "boolean" },
    { path: ["definitions", "fileIndex", "properties", "patternMatches"], type: "object" },
    {
      path: ["definitions", "appModel", "properties", "routes"],
      type: "array",
      itemRef: "#/definitions/appRoute",
    },
    { path: ["definitions", "appModel", "properties", "outboundClients"], type: "array" },
    { path: ["definitions", "appModel", "properties", "serviceBoundaries"], type: "array" },
    { path: ["definitions", "appModel", "properties", "dataStores"], type: "array" },
    { path: ["definitions", "appModel", "properties", "backgroundJobs"], type: "array" },
    { path: ["definitions", "appRoute", "properties", "id"], type: "string" },
    { path: ["definitions", "appRoute", "properties", "source"], type: "string" },
  ],
  "schemas/run.findings.schema.json": [
    ...snapshotMarkerShapeSpecs,
    { path: ["items"], ref: "#/definitions/finding" },
    { path: ["properties", "coreFindings"], type: "array", itemRef: "#/definitions/finding" },
    { path: ["properties", "core_findings"], type: "array", itemRef: "#/definitions/finding" },
    { path: ["properties", "findings"], type: "array", itemRef: "#/definitions/finding" },
    { path: ["definitions", "finding", "properties", "id"], type: "string" },
    { path: ["definitions", "finding", "properties", "fingerprint"], type: "string" },
    { path: ["definitions", "finding", "properties", "tool"], type: "string" },
    { path: ["definitions", "finding", "properties", "ruleId"], type: "string" },
    { path: ["definitions", "finding", "properties", "rule_id"], type: "string" },
    { path: ["definitions", "finding", "properties", "title"], type: "string" },
    { path: ["definitions", "finding", "properties", "message"], type: "string" },
    { path: ["definitions", "finding", "properties", "filePath"], type: "string" },
    { path: ["definitions", "finding", "properties", "file_path"], type: "string" },
    { path: ["definitions", "finding", "properties", "startLine"], type: "integer", minimum: 1 },
    { path: ["definitions", "finding", "properties", "start_line"], type: "integer", minimum: 1 },
    { path: ["definitions", "finding", "properties", "endLine"], type: "integer", minimum: 1 },
    { path: ["definitions", "finding", "properties", "end_line"], type: "integer", minimum: 1 },
    { path: ["definitions", "finding", "properties", "severity"], ref: "#/definitions/severity" },
    {
      path: ["definitions", "finding", "properties", "confidence"],
      ref: "#/definitions/confidence",
    },
    {
      path: ["definitions", "finding", "properties", "staticProofState"],
      ref: "#/definitions/proofState",
    },
    {
      path: ["definitions", "finding", "properties", "static_proof_state"],
      ref: "#/definitions/proofState",
    },
    {
      path: ["definitions", "finding", "properties", "proofState"],
      ref: "#/definitions/proofState",
    },
    {
      path: ["definitions", "finding", "properties", "proof_state"],
      ref: "#/definitions/proofState",
    },
    {
      path: ["definitions", "finding", "properties", "properties"],
      ref: "#/definitions/findingProperties",
    },
    { path: ["definitions", "finding", "properties", "cwe"], types: ["string", "array"] },
    {
      path: ["definitions", "finding", "properties", "evidence"],
      types: ["string", "array", "object"],
    },
    { path: ["definitions", "finding", "properties", "suppressed"], type: "boolean" },
    { path: ["definitions", "finding", "properties", "snoozedUntil"], type: "string" },
    { path: ["definitions", "finding", "properties", "snoozed_until"], type: "string" },
    { path: ["definitions", "finding", "properties", "remediation"], type: "string" },
    { path: ["definitions", "finding", "properties", "references"], type: "array" },
    {
      path: ["definitions", "findingProperties", "properties", "staticProofState"],
      ref: "#/definitions/proofState",
    },
    {
      path: ["definitions", "findingProperties", "properties", "static_proof_state"],
      ref: "#/definitions/proofState",
    },
    {
      path: ["definitions", "findingProperties", "properties", "proofState"],
      ref: "#/definitions/proofState",
    },
    {
      path: ["definitions", "findingProperties", "properties", "proof_state"],
      ref: "#/definitions/proofState",
    },
    { path: ["definitions", "confidence", "anyOf", 1], type: "number", minimum: 0, maximum: 1 },
    { path: ["definitions", "confidence", "anyOf", 2], type: "integer", minimum: 0, maximum: 100 },
  ],
  "schemas/run.proof.schema.json": [
    ...snapshotMarkerShapeSpecs,
    { path: ["properties", "proof"], type: "object" },
    { path: ["properties", "proofs"], types: ["object", "array"] },
    { path: ["properties", "verification"], type: "object" },
    { path: ["properties", "source"], type: "string" },
    { path: ["properties", "kind"], ref: "#/definitions/proofKind" },
    { path: ["properties", "proofLevel"], ref: "#/definitions/proofLevel" },
    { path: ["properties", "proof_level"], ref: "#/definitions/proofLevel" },
    { path: ["properties", "proofVerdict"], ref: "#/definitions/proofVerdict" },
    { path: ["properties", "proof_verdict"], ref: "#/definitions/proofVerdict" },
    { path: ["properties", "runtimeVerification"], type: "boolean" },
    { path: ["properties", "runtime_verification"], type: "boolean" },
    { path: ["properties", "countsByState"], type: "object" },
    { path: ["properties", "counts_by_state"], type: "object" },
    { path: ["properties", "verified"], type: "integer", minimum: 0 },
    { path: ["properties", "verifiedCount"], type: "integer", minimum: 0 },
    { path: ["properties", "verified_count"], type: "integer", minimum: 0 },
    { path: ["properties", "results"], type: "array" },
    { path: ["properties", "verificationResults"], type: "array" },
    { path: ["properties", "verification_results"], type: "array" },
    { path: ["properties", "findings"], type: "array", itemRef: "#/definitions/proofFinding" },
    { path: ["definitions", "proofFinding", "properties", "fingerprint"], type: "string" },
    { path: ["definitions", "proofFinding", "properties", "tool"], type: "string" },
    { path: ["definitions", "proofFinding", "properties", "ruleId"], type: "string" },
    { path: ["definitions", "proofFinding", "properties", "rule_id"], type: "string" },
    { path: ["definitions", "proofFinding", "properties", "filePath"], type: "string" },
    { path: ["definitions", "proofFinding", "properties", "file_path"], type: "string" },
    {
      path: ["definitions", "proofFinding", "properties", "startLine"],
      type: "integer",
      minimum: 1,
    },
    {
      path: ["definitions", "proofFinding", "properties", "start_line"],
      type: "integer",
      minimum: 1,
    },
    {
      path: ["definitions", "proofFinding", "properties", "staticProofState"],
      ref: "#/definitions/proofState",
    },
    {
      path: ["definitions", "proofFinding", "properties", "static_proof_state"],
      ref: "#/definitions/proofState",
    },
  ],
  "schemas/run.recommendations.schema.json": [
    ...snapshotMarkerShapeSpecs,
    { path: ["properties", "data"], ref: "#/definitions/recommendationReport" },
    { path: ["properties", "recommendationReport"], ref: "#/definitions/recommendationReport" },
    { path: ["properties", "ok"], type: "boolean" },
    { path: ["properties", "target"], type: "string" },
    { path: ["properties", "availableToolCount"], type: "integer", minimum: 0 },
    { path: ["properties", "recommendedToolCount"], type: "integer", minimum: 0 },
    { path: ["properties", "skippedMissingTools"], type: "array", itemType: "string" },
    {
      path: ["properties", "recommendations"],
      type: "array",
      itemRef: "#/definitions/recommendation",
    },
    { path: ["definitions", "recommendation", "properties", "moduleId"], type: "string" },
    { path: ["definitions", "recommendation", "properties", "tool"], type: "string" },
    { path: ["definitions", "recommendation", "properties", "reason"], type: "string" },
    {
      path: ["definitions", "recommendation", "properties", "signals"],
      type: "array",
      itemType: "string",
    },
    {
      path: ["definitions", "recommendation", "properties", "priority"],
      ref: "#/definitions/priority",
    },
    { path: ["definitions", "recommendation", "properties", "requiresRuntime"], type: "boolean" },
    { path: ["definitions", "recommendation", "properties", "nextInput"], type: "object" },
    { path: ["definitions", "recommendationReport", "properties", "summary"], type: "string" },
    { path: ["definitions", "recommendationReport", "properties", "signals"], type: "object" },
    { path: ["definitions", "recommendationReport", "properties", "ok"], type: "boolean" },
    {
      path: ["definitions", "recommendationReport", "properties", "capabilities"],
      ref: "#/definitions/capabilities",
    },
    {
      path: ["definitions", "capabilities", "properties", "availableToolCount"],
      type: "integer",
      minimum: 0,
    },
    {
      path: ["definitions", "capabilities", "properties", "recommendedToolCount"],
      type: "integer",
      minimum: 0,
    },
    {
      path: ["definitions", "capabilities", "properties", "skippedMissingTools"],
      type: "array",
      itemType: "string",
    },
    {
      path: ["definitions", "recommendationReport", "properties", "recommendations"],
      type: "array",
      itemRef: "#/definitions/recommendation",
    },
    {
      path: ["definitions", "recommendationReport", "properties", "warnings"],
      type: "array",
      itemType: "string",
    },
    {
      path: ["definitions", "recommendationReport", "properties", "errors"],
      type: "array",
      itemType: "string",
    },
    {
      path: ["definitions", "recommendationReport", "properties", "recommendationReport"],
      ref: "#/definitions/recommendationReport",
    },
    { path: ["properties", "signals"], type: "object" },
    { path: ["properties", "capabilities"], ref: "#/definitions/capabilities" },
  ],
  "schemas/run.attack-surface.schema.json": [
    ...snapshotMarkerShapeSpecs,
    { path: ["properties", "surfaces"], type: "array", itemRef: "#/definitions/surface" },
    { path: ["properties", "entries"], type: "array", itemRef: "#/definitions/surface" },
    { path: ["properties", "attackSurfaces"], type: "array", itemRef: "#/definitions/surface" },
    { path: ["properties", "attack_surfaces"], type: "array", itemRef: "#/definitions/surface" },
    { path: ["properties", "surfaceCount"], type: "integer", minimum: 0 },
    { path: ["properties", "surface_count"], type: "integer", minimum: 0 },
    { path: ["properties", "total"], type: "integer", minimum: 0 },
    { path: ["properties", "highRisk"], type: "integer", minimum: 0 },
    { path: ["properties", "high_risk"], type: "integer", minimum: 0 },
    { path: ["properties", "maxRiskScore"], type: "integer", minimum: 0 },
    { path: ["properties", "max_risk_score"], type: "integer", minimum: 0 },
    { path: ["properties", "byRiskTier"], type: "object" },
    { path: ["properties", "by_risk_tier"], type: "object" },
    { path: ["properties", "byKind"], type: "object" },
    { path: ["properties", "by_kind"], type: "object" },
    { path: ["properties", "risk"], type: "object" },
    { path: ["properties", "rank"], type: "integer", minimum: 0 },
    { path: ["properties", "score"], type: "integer", minimum: 0 },
    { path: ["properties", "tier"], ref: "#/definitions/riskTier" },
    { path: ["properties", "reasons"], type: "array", itemType: "string" },
    { path: ["properties", "kind"], ref: "#/definitions/surfaceKind" },
    { path: ["properties", "method"], ref: "#/definitions/routeMethod" },
    { path: ["definitions", "surface", "properties", "id"], type: "string" },
    { path: ["definitions", "surface", "properties", "path"], type: "string" },
    { path: ["definitions", "surface", "properties", "line"], type: "integer", minimum: 1 },
    { path: ["definitions", "surface", "properties", "kind"], ref: "#/definitions/surfaceKind" },
    { path: ["definitions", "surface", "properties", "language"], type: "string" },
    { path: ["definitions", "surface", "properties", "framework"], type: "string" },
    { path: ["definitions", "surface", "properties", "title"], type: "string" },
    { path: ["definitions", "surface", "properties", "evidence"], type: "string" },
    { path: ["definitions", "surface", "properties", "method"], ref: "#/definitions/routeMethod" },
    { path: ["definitions", "surface", "properties", "boundary"], type: "string" },
    { path: ["definitions", "surface", "properties", "risk"], ref: "#/definitions/risk" },
    { path: ["definitions", "surface", "properties", "metadata"], type: "object" },
    { path: ["definitions", "risk", "properties", "rank"], type: "integer", minimum: 0 },
    { path: ["definitions", "risk", "properties", "score"], type: "integer", minimum: 0 },
    { path: ["definitions", "risk", "properties", "tier"], ref: "#/definitions/riskTier" },
    { path: ["definitions", "risk", "properties", "reasons"], type: "array", itemType: "string" },
  ],
  "schemas/run.threat-model.schema.json": [
    ...snapshotMarkerShapeSpecs,
    { path: ["properties", "document"], type: "object" },
    { path: ["properties", "version"], type: "string" },
    { path: ["properties", "methodology"], ref: "#/definitions/methodology" },
    { path: ["properties", "dfd"], ref: "#/definitions/dfd" },
    { path: ["properties", "nodes"], type: "array" },
    { path: ["properties", "flows"], type: "array" },
    { path: ["properties", "trustBoundaries"], type: "array" },
    { path: ["properties", "trust_boundaries"], type: "array" },
    { path: ["properties", "threats"], type: "array", itemRef: "#/definitions/threat" },
    { path: ["properties", "relatedCwe"], ref: "#/definitions/stringList" },
    { path: ["properties", "related_cwe"], ref: "#/definitions/stringList" },
    { path: ["properties", "cwe"], ref: "#/definitions/stringList" },
    { path: ["properties", "attackSurface"], ref: "#/definitions/attackSurfaceHandoff" },
    { path: ["properties", "narrative"], ref: "#/definitions/narrative" },
    { path: ["properties", "degradation"], type: "object" },
    { path: ["definitions", "dfd", "properties", "nodes"], type: "array" },
    { path: ["definitions", "dfd", "properties", "flows"], type: "array" },
    { path: ["definitions", "dfd", "properties", "trustBoundaries"], type: "array" },
    { path: ["definitions", "dfd", "properties", "trust_boundaries"], type: "array" },
    { path: ["definitions", "threat", "properties", "id"], type: "string" },
    {
      path: ["definitions", "threat", "properties", "relatedCwe"],
      ref: "#/definitions/stringList",
    },
    {
      path: ["definitions", "threat", "properties", "related_cwe"],
      ref: "#/definitions/stringList",
    },
    { path: ["definitions", "threat", "properties", "cwe"], ref: "#/definitions/stringList" },
    { path: ["definitions", "attackSurfaceHandoff", "properties", "entryPoints"], type: "array" },
    { path: ["definitions", "attackSurfaceHandoff", "properties", "roleGates"], type: "array" },
    { path: ["definitions", "attackSurfaceHandoff", "properties", "externalSinks"], type: "array" },
    {
      path: ["definitions", "attackSurfaceHandoff", "properties", "trustedCallers"],
      type: "array",
    },
    {
      path: ["definitions", "narrative", "properties", "inputCategories"],
      ref: "#/definitions/inputCategories",
    },
    {
      path: ["definitions", "narrative", "properties", "input_categories"],
      ref: "#/definitions/inputCategories",
    },
    { path: ["definitions", "narrative", "properties", "attackerStories"], type: "array" },
    { path: ["definitions", "narrative", "properties", "criticalityBuckets"], type: "object" },
    {
      path: ["definitions", "narrative", "properties", "outOfScope"],
      type: "array",
      itemType: "string",
    },
    {
      path: ["definitions", "inputCategories", "properties", "attackerControlled"],
      ref: "#/definitions/stringList",
    },
    {
      path: ["definitions", "inputCategories", "properties", "attacker_controlled"],
      ref: "#/definitions/stringList",
    },
    {
      path: ["definitions", "inputCategories", "properties", "operatorControlled"],
      ref: "#/definitions/stringList",
    },
    {
      path: ["definitions", "inputCategories", "properties", "operator_controlled"],
      ref: "#/definitions/stringList",
    },
    {
      path: ["definitions", "inputCategories", "properties", "developerControlled"],
      ref: "#/definitions/stringList",
    },
    {
      path: ["definitions", "inputCategories", "properties", "developer_controlled"],
      ref: "#/definitions/stringList",
    },
    {
      path: ["definitions", "inputCategories", "properties", "externalServices"],
      ref: "#/definitions/stringList",
    },
    {
      path: ["definitions", "inputCategories", "properties", "external_services"],
      ref: "#/definitions/stringList",
    },
    {
      path: ["definitions", "inputCategories", "properties", "credentialFlows"],
      ref: "#/definitions/stringList",
    },
    {
      path: ["definitions", "inputCategories", "properties", "credential_flows"],
      ref: "#/definitions/stringList",
    },
    {
      path: ["definitions", "inputCategories", "properties", "authorizationFlows"],
      ref: "#/definitions/stringList",
    },
    {
      path: ["definitions", "inputCategories", "properties", "authorization_flows"],
      ref: "#/definitions/stringList",
    },
    {
      path: ["definitions", "inputCategories", "properties", "fileIngestFlows"],
      ref: "#/definitions/stringList",
    },
    {
      path: ["definitions", "inputCategories", "properties", "file_ingest_flows"],
      ref: "#/definitions/stringList",
    },
    {
      path: ["definitions", "inputCategories", "properties", "dataEgressFlows"],
      ref: "#/definitions/stringList",
    },
    {
      path: ["definitions", "inputCategories", "properties", "data_egress_flows"],
      ref: "#/definitions/stringList",
    },
    {
      path: ["definitions", "inputCategories", "properties", "callbackFlows"],
      ref: "#/definitions/stringList",
    },
    {
      path: ["definitions", "inputCategories", "properties", "callback_flows"],
      ref: "#/definitions/stringList",
    },
    {
      path: ["definitions", "inputCategories", "properties", "sandboxBoundary"],
      ref: "#/definitions/stringList",
    },
    {
      path: ["definitions", "inputCategories", "properties", "sandbox_boundary"],
      ref: "#/definitions/stringList",
    },
    {
      path: ["definitions", "inputCategories", "properties", "assumptions"],
      ref: "#/definitions/stringList",
    },
    { path: ["definitions", "stringList"], type: "array", itemType: "string" },
  ],
};

export function checkFieldShapeSpecs(relativeFile, schema, schemaNode) {
  return (fieldShapeSpecs[relativeFile] ?? []).flatMap((spec) =>
    checkFieldShape(relativeFile, schema, schemaNode, spec),
  );
}

function checkFieldShape(relativeFile, schema, schemaNode, spec) {
  const node = schemaNode(schema, spec.path);
  return [
    checkTypeShape(relativeFile, node, spec),
    spec.ref ? checkRef(relativeFile, node, spec) : null,
    spec.minimum === undefined ? null : checkMinimum(relativeFile, node, spec),
    spec.maximum === undefined ? null : checkMaximum(relativeFile, node, spec),
    spec.itemType ? checkItemShape(relativeFile, node, spec) : null,
    spec.itemRef ? checkItemRef(relativeFile, node, spec) : null,
  ].filter(Boolean);
}

function checkTypeShape(relativeFile, node, spec) {
  if (spec.ref || (!spec.type && !spec.types)) return null;
  const expected = spec.types ?? [spec.type];
  const actual = Array.isArray(node?.type) ? node.type : [node?.type];
  return expected.every((type) => actual.includes(type))
    ? null
    : `${relativeFile}: ${spec.path.join(".")} must be ${expected.join("|")}`;
}

function checkRef(relativeFile, node, spec) {
  return node?.$ref === spec.ref
    ? null
    : `${relativeFile}: ${spec.path.join(".")} must reference ${spec.ref}`;
}

function checkMinimum(relativeFile, node, spec) {
  return node?.minimum === spec.minimum
    ? null
    : `${relativeFile}: ${spec.path.join(".")} minimum must be ${spec.minimum}`;
}

function checkMaximum(relativeFile, node, spec) {
  return node?.maximum === spec.maximum
    ? null
    : `${relativeFile}: ${spec.path.join(".")} maximum must be ${spec.maximum}`;
}

function checkItemShape(relativeFile, node, spec) {
  return node?.items?.type === spec.itemType
    ? null
    : `${relativeFile}: ${spec.path.join(".")} items must be ${spec.itemType}`;
}

function checkItemRef(relativeFile, node, spec) {
  return node?.items?.$ref === spec.itemRef
    ? null
    : `${relativeFile}: ${spec.path.join(".")} items must reference ${spec.itemRef}`;
}
