#!/usr/bin/env node
// Cyclomatic complexity per function/method for the TS source tree.
//
// Also classifies each function as:
//   dispatch — most of its cc comes from one switch/if-ladder on a single key.
//              Tedious but low-risk; refactor to a handler map if you care.
//   logic    — cc is spread across genuine branching. Real refactor candidate.
//
// Usage: node scripts/cyclomatic.mjs [dir] [--top N] [--min N] [--json]
//        [--logic-only] [--dispatch-only] [--dispatch-threshold 0.6]

import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import ts from "typescript";

const args = process.argv.slice(2);
const rootDir = args.find((a) => !a.startsWith("--")) ?? "src";
const topN = Number(flagValue("--top") ?? 30);
const minCc = Number(flagValue("--min") ?? 1);
const asJson = args.includes("--json");
const logicOnly = args.includes("--logic-only");
const dispatchOnly = args.includes("--dispatch-only");
const dispatchThreshold = Number(flagValue("--dispatch-threshold") ?? 0.6);

function flagValue(flag) {
  const i = args.indexOf(flag);
  return i === -1 ? undefined : args[i + 1];
}

function walkFs(dir, out = []) {
  for (const name of readdirSync(dir)) {
    if (name === "node_modules" || name.startsWith(".")) continue;
    const p = join(dir, name);
    const st = statSync(p);
    if (st.isDirectory()) walkFs(p, out);
    else if (/\.(ts|tsx)$/.test(name) && !/\.d\.ts$/.test(name)) out.push(p);
  }
  return out;
}

const INCREMENTS = new Set([
  ts.SyntaxKind.IfStatement,
  ts.SyntaxKind.ForStatement,
  ts.SyntaxKind.ForInStatement,
  ts.SyntaxKind.ForOfStatement,
  ts.SyntaxKind.WhileStatement,
  ts.SyntaxKind.DoStatement,
  ts.SyntaxKind.CaseClause,
  ts.SyntaxKind.CatchClause,
  ts.SyntaxKind.ConditionalExpression,
]);

function isFunctionLike(node) {
  return (
    ts.isFunctionDeclaration(node) ||
    ts.isFunctionExpression(node) ||
    ts.isArrowFunction(node) ||
    ts.isMethodDeclaration(node) ||
    ts.isGetAccessor(node) ||
    ts.isSetAccessor(node) ||
    ts.isConstructorDeclaration(node)
  );
}

function nameFor(node, sf) {
  if (ts.isConstructorDeclaration(node)) {
    const cls =
      node.parent && ts.isClassDeclaration(node.parent) ? node.parent.name?.text : undefined;
    return cls ? `${cls}.constructor` : "constructor";
  }
  if (node.name) {
    if (ts.isClassDeclaration(node.parent) || ts.isClassExpression(node.parent)) {
      const cls = node.parent.name?.text ?? "<anon>";
      return `${cls}.${node.name.getText(sf)}`;
    }
    return node.name.getText(sf);
  }
  // anon function/arrow: try variable declaration or property assignment
  const p = node.parent;
  if (p && ts.isVariableDeclaration(p) && p.name) return p.name.getText(sf);
  if (p && ts.isPropertyAssignment(p) && p.name) return p.name.getText(sf);
  return "<anonymous>";
}

function computeCc(fnNode) {
  let cc = 1;
  const visit = (n) => {
    if (n !== fnNode && isFunctionLike(n)) return; // skip nested fns; they're counted separately
    if (INCREMENTS.has(n.kind)) cc += 1;
    if (ts.isBinaryExpression(n)) {
      const op = n.operatorToken.kind;
      if (
        op === ts.SyntaxKind.AmpersandAmpersandToken ||
        op === ts.SyntaxKind.BarBarToken ||
        op === ts.SyntaxKind.QuestionQuestionToken
      ) {
        cc += 1;
      }
    }
    ts.forEachChild(n, visit);
  };
  ts.forEachChild(fnNode, visit);
  return cc;
}

// Returns the LHS text if the condition looks like `<expr> === <literal>` or
// `<expr> == <literal>`; otherwise null. We treat this as one "arm" of a
// dispatch ladder when multiple sibling ifs share the same LHS.
function dispatchLhs(condition, sf) {
  if (!ts.isBinaryExpression(condition)) return null;
  const op = condition.operatorToken.kind;
  if (op !== ts.SyntaxKind.EqualsEqualsEqualsToken && op !== ts.SyntaxKind.EqualsEqualsToken) {
    return null;
  }
  const isLiteral = (n) =>
    ts.isStringLiteralLike(n) ||
    ts.isNumericLiteral(n) ||
    n.kind === ts.SyntaxKind.TrueKeyword ||
    n.kind === ts.SyntaxKind.FalseKeyword ||
    n.kind === ts.SyntaxKind.NullKeyword;
  if (isLiteral(condition.right)) return condition.left.getText(sf);
  if (isLiteral(condition.left)) return condition.right.getText(sf);
  return null;
}

// Count arms in an else-if ladder rooted at `ifStmt` that all test the same
// LHS. Returns 0 if the ladder's root doesn't match the given lhsText.
function countLadderArms(ifStmt, lhsText, sf) {
  let count = 0;
  let cur = ifStmt;
  while (cur && ts.isIfStatement(cur)) {
    const lhs = dispatchLhs(cur.expression, sf);
    if (lhs === lhsText) count += 1;
    else break; // ladder broken
    cur = cur.elseStatement;
  }
  return count;
}

// Walk a function body looking for the single largest dispatch construct:
// either a `switch` (count case clauses) or a run of sibling `if` statements
// that all compare the same LHS to a literal. Returns { arms, kind } of the
// winning construct — arms is the number of branches it contributes to cc.
function analyzeDispatch(fnNode, sf) {
  let best = { arms: 0, kind: "none" };
  const consider = (arms, kind) => {
    if (arms > best.arms) best = { arms, kind };
  };

  const visitBlock = (block) => {
    if (!block || !ts.isBlock(block)) return;
    const stmts = block.statements;

    // Switch statements anywhere in this block.
    for (const s of stmts) {
      if (ts.isSwitchStatement(s)) {
        const cases = s.caseBlock.clauses.filter(ts.isCaseClause).length;
        consider(cases, "switch");
      }
    }

    // Sibling `if`-ladder: longest run of consecutive ifs sharing the same LHS.
    let i = 0;
    while (i < stmts.length) {
      const s = stmts[i];
      if (ts.isIfStatement(s)) {
        const lhs = dispatchLhs(s.expression, sf);
        if (lhs !== null) {
          let armsInRun = 0;
          let j = i;
          while (j < stmts.length && ts.isIfStatement(stmts[j])) {
            const inner = countLadderArms(stmts[j], lhs, sf);
            if (inner === 0) break;
            armsInRun += inner;
            j += 1;
          }
          consider(armsInRun, "if-ladder");
          i = Math.max(j, i + 1);
          continue;
        }
      }
      i += 1;
    }
  };

  // The function body is either a Block or (for arrow fns) an expression.
  const body = fnNode.body;
  if (body && ts.isBlock(body)) {
    visitBlock(body);
    // Also scan one level of child blocks (e.g. `try { switch(...) {} }`).
    for (const stmt of body.statements) {
      const inner = stmt;
      if (ts.isTryStatement(inner)) visitBlock(inner.tryBlock);
    }
  }
  return best;
}

const files = walkFs(rootDir);
const results = [];

for (const file of files) {
  const src = readFileSync(file, "utf8");
  const sf = ts.createSourceFile(file, src, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
  const relPath = relative(process.cwd(), file);
  const visit = (node) => {
    if (isFunctionLike(node)) {
      const cc = computeCc(node);
      const { line } = sf.getLineAndCharacterOfPosition(node.getStart(sf));
      const dispatch = analyzeDispatch(node, sf);
      // Dispatch fraction: how much of (cc - 1) comes from the winning construct.
      // We subtract the base 1 so a cc=1 function isn't flagged.
      const branches = Math.max(cc - 1, 0);
      const dispatchFrac = branches > 0 ? dispatch.arms / branches : 0;
      // Classify as dispatch if either:
      //  (a) the construct dominates cc (fraction ≥ threshold, arms ≥ 3), OR
      //  (b) the construct has 8+ arms — enough parallel branches that a
      //      table/handler-map refactor is justified even when each arm
      //      contains its own validation logic (e.g. setConfigValue).
      const category =
        (dispatchFrac >= dispatchThreshold && dispatch.arms >= 3) || dispatch.arms >= 8
          ? "dispatch"
          : "logic";
      results.push({
        file: relPath,
        line: line + 1,
        name: nameFor(node, sf),
        cc,
        dispatchArms: dispatch.arms,
        dispatchKind: dispatch.kind,
        dispatchFrac,
        category,
      });
    }
    ts.forEachChild(node, visit);
  };
  visit(sf);
}

results.sort((a, b) => b.cc - a.cc);

let filtered = results.filter((r) => r.cc >= minCc);
if (logicOnly) filtered = filtered.filter((r) => r.category === "logic");
if (dispatchOnly) filtered = filtered.filter((r) => r.category === "dispatch");
const total = filtered.length;
const histogram = filtered.reduce((acc, r) => {
  const bucket =
    r.cc >= 41 ? "41+" : r.cc >= 21 ? "21-40" : r.cc >= 11 ? "11-20" : r.cc >= 6 ? "6-10" : "1-5";
  acc[bucket] = (acc[bucket] ?? 0) + 1;
  return acc;
}, {});

// Category counts across the filtered set, for the header line.
const dispatchCount = filtered.filter((r) => r.category === "dispatch").length;
const logicCount = filtered.filter((r) => r.category === "logic").length;

if (asJson) {
  console.log(
    JSON.stringify(
      { total, histogram, dispatchCount, logicCount, top: filtered.slice(0, topN) },
      null,
      2,
    ),
  );
} else {
  console.log(`\nCyclomatic complexity — ${rootDir} (${files.length} files, ${total} functions)\n`);
  console.log("Distribution:");
  for (const b of ["1-5", "6-10", "11-20", "21-40", "41+"]) {
    const n = histogram[b] ?? 0;
    const pct = total ? ((n / total) * 100).toFixed(1) : "0.0";
    console.log(`  cc ${b.padEnd(5)} ${String(n).padStart(5)}  (${pct}%)`);
  }
  const filterLabel = logicOnly ? " [logic only]" : dispatchOnly ? " [dispatch only]" : "";
  console.log(
    `\nTop ${Math.min(topN, filtered.length)} most complex${filterLabel}  ` +
      `(dispatch=${dispatchCount}, logic=${logicCount})`,
  );
  console.log(
    `  cc   kind         arms    function                                        location`,
  );
  console.log(
    `  ---  -----------  -------  ----------------------------------------------  --------`,
  );
  for (const r of filtered.slice(0, topN)) {
    const name = r.name.length > 46 ? `${r.name.slice(0, 43)}...` : r.name.padEnd(46);
    const kind =
      r.category === "dispatch" ? `[${r.dispatchKind}]`.padEnd(11) : "[logic]    ".padEnd(11);
    const armsCell = r.category === "dispatch" ? `${r.dispatchArms} arms` : "—";
    console.log(
      `  ${String(r.cc).padStart(3)}  ${kind}  ${armsCell.padStart(7)}  ${name}  ${r.file}:${r.line}`,
    );
  }
  console.log("");
}
