const fieldShapeSpecs = {};

export function checkFieldShapeSpecs(relativeFile, schema, schemaNode) {
  const specs = fieldShapeSpecs[relativeFile];
  if (specs === undefined) return [];
  if (!Array.isArray(specs)) {
    return [`field shape helper drift: ${relativeFile} specs must be an array`];
  }
  if (specs.length === 0) return [`field shape missing: ${relativeFile}`];
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
  if (!node) return `field shape missing: ${relativeFile}: ${spec.path.join(".")}`;
  const expected = spec.types ?? [spec.type];
  const actual = Array.isArray(node?.type) ? node.type : [node?.type];
  return expected.every((type) => actual.includes(type))
    ? null
    : `field shape type mismatch: ${relativeFile}: ${spec.path.join(".")} must be ${expected.join("|")}`;
}

function checkRef(relativeFile, node, spec) {
  if (!node) return `field shape missing ref: ${relativeFile}: ${spec.path.join(".")}`;
  return node?.$ref === spec.ref
    ? null
    : `field shape ref mismatch: ${relativeFile}: ${spec.path.join(".")} must reference ${spec.ref}`;
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
  if (!node?.items) {
    return `field shape missing item ref: ${relativeFile}: ${spec.path.join(".")}`;
  }
  return node?.items?.type === spec.itemType
    ? null
    : `field shape item ref mismatch: ${relativeFile}: ${spec.path.join(".")} items must be ${spec.itemType}`;
}

function checkItemRef(relativeFile, node, spec) {
  if (!node?.items) {
    return `field shape missing item ref: ${relativeFile}: ${spec.path.join(".")}`;
  }
  return node?.items?.$ref === spec.itemRef
    ? null
    : `field shape item ref mismatch: ${relativeFile}: ${spec.path.join(".")} items must reference ${spec.itemRef}`;
}
