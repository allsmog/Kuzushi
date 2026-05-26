export function rustFunctionBody(source, name) {
  const signature = source.indexOf(`fn ${name}`);
  if (signature === -1) return null;
  const openBrace = source.indexOf("{", signature);
  if (openBrace === -1) return null;
  const closeBrace = matchingBraceIndex(source, openBrace);
  return closeBrace === -1 ? null : source.slice(openBrace, closeBrace + 1);
}

export function rustStringArrayConstant(source, name) {
  const body = rustArrayConstantBody(source, name);
  return body === null ? null : rustStringLiterals(body);
}

export function rustArrayConstantBody(source, name) {
  const expression = new RegExp(
    `(?:pub\\(crate\\)\\s+)?const\\s+${name}\\s*:\\s*&?\\s*\\[[^\\]]+\\]\\s*=\\s*&?\\s*\\[([\\s\\S]*?)\\];`,
  );
  const match = source.match(expression);
  return match?.[1] ?? null;
}

export function rustStringConstants(source, names) {
  return Object.fromEntries(
    names.map((name) => [name, rustStringConstant(source, name)]),
  );
}

function rustStringConstant(source, name) {
  return source.match(new RegExp(`const ${name}: &str = "([^"]+)"`))?.[1];
}

function rustStringLiterals(source) {
  return [...source.matchAll(/"([^"]+)"/g)].map((entry) => entry[1]);
}

export function rustCanonicalRunArtifactSpecs(source, name) {
  const expression = new RegExp(
    `(?:pub\\(crate\\)\\s+)?const\\s+${name}\\s*:\\s*\\[[^\\]]+\\]\\s*=\\s*\\[([\\s\\S]*?)\\];`,
  );
  const match = source.match(expression);
  if (!match) return null;
  return [...match[1].matchAll(/CanonicalRunArtifactSpec\s*\{([\s\S]*?)\}/g)].map((entry) =>
    rustCanonicalRunArtifactSpec(entry[1]),
  );
}

function rustCanonicalRunArtifactSpec(body) {
  return {
    path: rustStructStringField(body, "leaf"),
    label: rustStructStringField(body, "label"),
    kind: rustStructStringField(body, "kind"),
  };
}

function rustStructStringField(body, field) {
  const match = body.match(new RegExp(`${field}\\s*:\\s*"([^"]+)"`));
  if (!match) throw new Error(`missing Rust string field ${field}`);
  return match[1];
}

function matchingBraceIndex(source, openBrace) {
  let depth = 0;
  for (let index = openBrace; index < source.length; index += 1) {
    depth += braceDepthDelta(source[index]);
    if (depth === 0) return index;
  }
  return -1;
}

function braceDepthDelta(char) {
  if (char === "{") return 1;
  if (char === "}") return -1;
  return 0;
}
