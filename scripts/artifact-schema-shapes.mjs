const fieldShapeSpecs = {};

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
