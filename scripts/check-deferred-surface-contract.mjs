#!/usr/bin/env node
import { readFileSync } from "node:fs";
import path from "node:path";

const repo = process.cwd();

const registrationFile =
  "crates/kuzushi-core/src/modules/builtins/with_v2_builtins/builtin_registration.rs";
const systemsModuleFile = "crates/kuzushi-core/src/modules/carlini_threat_hunt_module.rs";
const pluginAdaptersFile = "crates/kuzushi-core/src/modules/plugin_adapters/register_modules.rs";
const recommenderFile = "crates/kuzushi-core/src/capabilities/module_recommender/rule_catalog.rs";
const registryTestsFile = "crates/kuzushi-core/src/modules/registry/tests.rs";
const sastTasksFile = "crates/kuzushi-tui/src/app/sast_tasks/valid_sast_task_ids.rs";
const packageFile = "package.json";
const readmeFile = "README.md";
const portPlanFile = "docs/PORT_PLAN.md";

const deferredRegistrations = [
  "carlini_threat_hunt_module()",
  "full_mode_module()",
  "deep_audit_module()",
  "pwn_module()",
  "taint_iris_module()",
  "threat_leads_module()",
  "uaf_hunt_module()",
  "offense_module()",
  "vendor_assessment::module()",
  "chrome_rce::module()",
  "visible_when(",
  "module.deferred()",
];

const pluginDeferredRegistrations = [
  "vuln_scout_module().with_executor(executor)",
  "tob_module().with_executor(executor)",
  "shinsa_module().with_executor(executor)",
  "module.deferred()",
];

const hiddenModuleNeedles = [
  '"carlini-threat-hunt"',
  '"classifier-gate"',
  '"chrome-rce"',
  '"context-lite"',
  '"deep-audit"',
  '"exploit-chain"',
  '"full-mode"',
  '"offense"',
  '"pipeline"',
  '"prompt-armor"',
  '"pwn"',
  '"shinsa"',
  '"systems-hunt"',
  '"taint-iris"',
  '"threat-leads"',
  '"tob"',
  '"uaf-hunt"',
  '"vendor-assessment"',
  '"vuln-scout"',
];

const exactOnlyToolNeedles = [
  '"carlini-threat-hunt:run"',
  '"classifier-gate:score"',
  '"chrome-rce:scan"',
  '"chrome-rce:review-trigger"',
  '"deep-audit:run"',
  '"exploit-chain:scan"',
  '"full-mode:hunt"',
  '"offense:chain"',
  '"pwn:reverse"',
  '"prompt-armor:scan"',
  '"prompt-armor:analyze"',
  '"prompt-armor:attack"',
  '"prompt-armor:diff"',
  '"prompt-armor:report"',
  '"prompt-armor:config"',
  '"shinsa:scan"',
  '"shinsa:quick-check"',
  '"shinsa:nist-scan"',
  '"shinsa:nist-quick-check"',
  '"shinsa:frameworks"',
  '"taint-iris:hunt"',
  '"tob:audit"',
  '"tob:skills"',
  '"threat-leads:build"',
  '"threat-leads:read"',
  '"uaf-hunt:hunt"',
  '"vendor-assessment:assess"',
  '"vuln-scout:audit"',
];

const hiddenDagNodeNeedles = [
  '"systems-hunt:systems-context-gatherer"',
  '"systems-hunt:systems-invariant-extract"',
  '"systems-hunt:systems-trigger-synth"',
  '"systems-hunt:systems-hunt"',
  '"systems-hunt:deep-semantic-cwe-select"',
  '"systems-hunt:deep-semantic-hunt"',
];

const recommenderForbiddenTools = [
  "carlini-threat-hunt:",
  "classifier-gate:",
  "chrome-rce:",
  "deep-audit:",
  "exploit-chain:",
  "full-mode:",
  "offense:",
  "pipeline:",
  "pwn:",
  "prompt-armor:",
  "shinsa:",
  "systems-hunt:",
  "taint-iris:",
  "threat-leads:",
  "tob:",
  "uaf-hunt:",
  "vendor-assessment:",
  "vuln-scout:",
];

const optionalAdapterPackages = [
  "@kuzushi/tob-skills",
  "@kuzushi/vuln-scout",
  "promptarmor-plugin",
  "shinsa-plugin",
];

const deferredDocNeedles = [
  "systems-hunt:*` entries are internal DAG",
  "`carlini-threat-hunt`",
  "`uaf-hunt`",
  "`classifier-gate`",
  "hidden exact-invocation plugin-backed",
  "internally registered DAG nodes",
];

const failures = [
  ...missingNeedles(registrationFile, deferredRegistrations),
  ...missingNeedles(pluginAdaptersFile, pluginDeferredRegistrations),
  ...missingNeedles(systemsModuleFile, ['hidden_module(\n        "systems-hunt"']),
  ...missingNeedles(registryTestsFile, hiddenModuleNeedles),
  ...missingNeedles(registryTestsFile, exactOnlyToolNeedles),
  ...missingNeedles(registryTestsFile, hiddenDagNodeNeedles),
  ...missingNeedles(registryTestsFile, ["is_registered_dag_node"]),
  ...missingNeedles(readmeFile, deferredDocNeedles.slice(0, 3)),
  ...missingNeedles(portPlanFile, deferredDocNeedles.slice(2)),
  ...forbiddenNeedles(recommenderFile, recommenderForbiddenTools),
  ...deferredPackageDependencyFailures(),
  ...systemsHuntTaskFailures(),
];

if (failures.length > 0) {
  console.error("Deferred surface contract failed:");
  for (const failure of failures) console.error(`- ${failure}`);
  process.exit(1);
}

console.log("deferred surface contract passed");

function readRepoFile(file) {
  return readFileSync(path.join(repo, file), "utf8");
}

function missingNeedles(file, needles) {
  const source = readRepoFile(file);
  return needles
    .filter((needle) => !source.includes(needle))
    .map((needle) => `${file} must mention ${needle}`);
}

function forbiddenNeedles(file, needles) {
  const source = readRepoFile(file);
  return needles
    .filter((needle) => source.includes(`tool: "${needle}`))
    .map((needle) => `${file} must not recommend deferred tool prefix ${needle}`);
}

function deferredPackageDependencyFailures() {
  const pkg = JSON.parse(readRepoFile(packageFile));
  return optionalAdapterPackages
    .flatMap((name) => [
      Object.hasOwn(pkg.dependencies ?? {}, name)
        ? `${packageFile} must not install deferred adapter package ${name} as a default dependency`
        : null,
      Object.hasOwn(pkg.optionalDependencies ?? {}, name)
        ? null
        : `${packageFile} must keep deferred adapter package ${name} in optionalDependencies`,
    ])
    .filter(Boolean);
}

function systemsHuntTaskFailures() {
  const source = readRepoFile(sastTasksFile);
  const task = source.match(/SastTaskCapability \{[\s\S]*?id: "systems-hunt",[\s\S]*?\n {4}\},/);
  if (!task) return [`${sastTasksFile} must keep systems-hunt as an explicit task row`];
  return [
    task[0].includes("default_enabled: false")
      ? null
      : `${sastTasksFile} systems-hunt task must not be default-enabled`,
    task[0].includes("deferred exact opt-in")
      ? null
      : `${sastTasksFile} systems-hunt task notes must say deferred exact opt-in`,
  ].filter(Boolean);
}
