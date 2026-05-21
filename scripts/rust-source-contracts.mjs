export function rustFunctionBody(source, name) {
  const signature = source.indexOf(`fn ${name}`);
  if (signature === -1) return null;
  const openBrace = source.indexOf("{", signature);
  if (openBrace === -1) return null;
  const closeBrace = matchingBraceIndex(source, openBrace);
  return closeBrace === -1 ? null : source.slice(openBrace, closeBrace + 1);
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
