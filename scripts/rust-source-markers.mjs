export function hasActiveRustModule(source, moduleName) {
  const declaration = new RegExp(`^\\s*mod\\s+${moduleName}\\s*;\\s*$`, "m");
  return declaration.test(rustCodeOnly(source));
}

function rustCodeOnly(source) {
  let code = "";
  let index = 0;
  while (index < source.length) {
    const ignoredLength = rustIgnoredTokenLength(source, index);
    if (ignoredLength > 0) {
      code += source.slice(index, index + ignoredLength).replace(/[^\n]/g, " ");
      index += ignoredLength;
      continue;
    }
    code += source[index];
    index += 1;
  }
  return code;
}

function rustIgnoredTokenLength(source, index) {
  return Math.max(
    rustLineCommentLength(source, index),
    rustBlockCommentLength(source, index),
    rustRawStringLength(source, index),
    rustQuotedLiteralLength(source, index),
  );
}

function rustLineCommentLength(source, index) {
  const match = source.slice(index).match(/^\/\/[^\n]*(?:\n|$)/);
  return match?.[0].length ?? 0;
}

function rustBlockCommentLength(source, index) {
  if (!source.startsWith("/*", index)) return 0;
  let cursor = index + 2;
  let depth = 1;
  while (depth > 0) {
    const nextOpen = source.indexOf("/*", cursor);
    const nextClose = source.indexOf("*/", cursor);
    if (nextClose < 0) return source.length - index;
    const opensFirst = nextOpen >= 0 && nextOpen < nextClose;
    depth += opensFirst ? 1 : -1;
    cursor = (opensFirst ? nextOpen : nextClose) + 2;
  }
  return cursor - index;
}

function rustRawStringLength(source, index) {
  const prefix = source.slice(index).match(/^r(#{0,255})"/);
  if (!prefix) return 0;
  const delimiter = `"${prefix[1]}`;
  const end = source.indexOf(delimiter, index + prefix[0].length);
  return (end < 0 ? source.length : end + delimiter.length) - index;
}

function rustQuotedLiteralLength(source, index) {
  const match = source
    .slice(index)
    .match(/^(?:"(?:\\[\s\S]|[^"\\])*"|'(?:\\(?:u\{[0-9A-Fa-f_]+\}|[\s\S])|[^'\\\r\n])')/);
  return match?.[0].length ?? 0;
}
