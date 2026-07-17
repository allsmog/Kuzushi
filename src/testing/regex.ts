/** Test a regular expression without leaking global/sticky cursor state across calls. */
export function repeatableRegexTest(expression: RegExp, value: string): boolean {
  if (!expression.global && !expression.sticky) return expression.test(value);
  expression.lastIndex = 0;
  const isolated = new RegExp(expression.source, expression.flags);
  isolated.lastIndex = 0;
  try {
    return isolated.test(value);
  } finally {
    isolated.lastIndex = 0;
    expression.lastIndex = 0;
  }
}
