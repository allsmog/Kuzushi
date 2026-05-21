const narrativeFlowAliases = [
  ["credentialFlows", "credential_flows"],
  ["authorizationFlows", "authorization_flows"],
  ["fileIngestFlows", "file_ingest_flows"],
  ["dataEgressFlows", "data_egress_flows"],
  ["callbackFlows", "callback_flows"],
];

export function checkThreatModelNarrativeFlowAliases(relativeFile, schema) {
  if (relativeFile !== "schemas/run.threat-model.schema.json") return [];
  return [
    ...checkNarrativeContainerAliases(relativeFile, schema),
    ...narrativeFlowAliases.flatMap(([camel, snake]) =>
      checkNarrativeFlowAlias(relativeFile, schema, camel, snake),
    ),
  ];
}

function checkNarrativeContainerAliases(relativeFile, schema) {
  return [
    hasRef(schema, ["properties", "narrative"], "#/definitions/narrative")
      ? null
      : `${relativeFile}: narrative schema must use definitions/narrative`,
    hasRef(schema, ["definitions", "narrative", "properties", "inputCategories"], "#/definitions/inputCategories")
      ? null
      : `${relativeFile}: narrative schema must preserve inputCategories`,
    hasRef(schema, ["definitions", "narrative", "properties", "input_categories"], "#/definitions/inputCategories")
      ? null
      : `${relativeFile}: narrative schema must preserve input_categories`,
  ].filter(Boolean);
}

function checkNarrativeFlowAlias(relativeFile, schema, camel, snake) {
  return [camel, snake]
    .filter((field) =>
      !hasRef(schema, ["definitions", "inputCategories", "properties", field], "#/definitions/stringList")
    )
    .map((field) => `${relativeFile}: narrative input category schema must preserve ${field}`);
}

function hasRef(schema, nodePath, expectedRef) {
  return schemaNode(schema, nodePath)?.$ref === expectedRef;
}

function schemaNode(schema, nodePath) {
  return nodePath.reduce((node, segment) => {
    if (Array.isArray(node) && Number.isInteger(segment)) return node[segment];
    return isPlainObject(node) ? node[segment] : undefined;
  }, schema);
}

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
