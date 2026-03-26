import { existsSync, readFileSync, writeFileSync, mkdirSync } from "node:fs";
import path from "node:path";
import chalk from "chalk";
import { createInterface } from "node:readline";
import { projectConfigPath } from "../../config/paths.js";

interface ProjectProfile {
  languages: string[];
  frameworks: string[];
  recommendedScanners: string[];
  recommendedTasks: string[];
}

function detectProject(repoRoot: string): ProjectProfile {
  const languages: string[] = [];
  const frameworks: string[] = [];
  const recommendedScanners: string[] = ["semgrep"];
  const recommendedTasks: string[] = [
    "context-gatherer",
    "context-enricher",
    "app-model-build",
    "threat-scenario-build",
    "secrets-crypto-detect",
    "code-config-detect",
  ];

  // Node.js
  if (existsSync(path.join(repoRoot, "package.json"))) {
    languages.push("JavaScript/TypeScript");
    try {
      const pkg = JSON.parse(readFileSync(path.join(repoRoot, "package.json"), "utf-8"));
      const allDeps = { ...pkg.dependencies, ...pkg.devDependencies };
      if (allDeps["express"] || allDeps["fastify"] || allDeps["koa"]) frameworks.push("Node.js web server");
      if (allDeps["react"] || allDeps["next"]) frameworks.push("React");
      if (allDeps["vue"]) frameworks.push("Vue");
      if (allDeps["angular"] || allDeps["@angular/core"]) frameworks.push("Angular");
    } catch { /* ignore parse errors */ }
  }

  // Python
  if (existsSync(path.join(repoRoot, "requirements.txt")) || existsSync(path.join(repoRoot, "pyproject.toml"))) {
    languages.push("Python");
    try {
      const reqs = existsSync(path.join(repoRoot, "requirements.txt"))
        ? readFileSync(path.join(repoRoot, "requirements.txt"), "utf-8")
        : "";
      if (reqs.includes("django") || reqs.includes("Django")) frameworks.push("Django");
      if (reqs.includes("flask") || reqs.includes("Flask")) frameworks.push("Flask");
      if (reqs.includes("fastapi") || reqs.includes("FastAPI")) frameworks.push("FastAPI");
    } catch { /* ignore */ }
  }

  // Go
  if (existsSync(path.join(repoRoot, "go.mod"))) {
    languages.push("Go");
  }

  // Java
  if (existsSync(path.join(repoRoot, "pom.xml")) || existsSync(path.join(repoRoot, "build.gradle"))) {
    languages.push("Java");
    recommendedScanners.push("codeql");
  }

  // Rust
  if (existsSync(path.join(repoRoot, "Cargo.toml"))) {
    languages.push("Rust");
  }

  // Ruby
  if (existsSync(path.join(repoRoot, "Gemfile"))) {
    languages.push("Ruby");
    try {
      const gemfile = readFileSync(path.join(repoRoot, "Gemfile"), "utf-8");
      if (gemfile.includes("rails")) frameworks.push("Rails");
    } catch { /* ignore */ }
  }

  // PHP
  if (existsSync(path.join(repoRoot, "composer.json"))) {
    languages.push("PHP");
  }

  // Web apps get additional tasks
  if (frameworks.some((f) => f.includes("web") || f.includes("Django") || f.includes("Flask")
    || f.includes("FastAPI") || f.includes("Rails") || f.includes("Express") || f.includes("React"))) {
    recommendedTasks.push("ssrf-detect");
  }

  // Add taint analysis for supported languages
  if (languages.some((l) => l.includes("Java") || l.includes("Python") || l.includes("JavaScript"))) {
    recommendedTasks.push("taint-analysis-preflight", "taint-analysis-label", "taint-analysis-run");
  }

  // Add crypto detection
  recommendedTasks.push("crypto-behavioral-test");

  if (languages.length === 0) {
    languages.push("unknown");
  }

  return { languages, frameworks, recommendedScanners, recommendedTasks };
}

type Profile = "quick" | "standard" | "thorough";

interface ProfileConfig {
  description: string;
  scanners: string[];
  enabledTasks: string[];
  verify: boolean;
  pocHarness: boolean;
  enableClassifier: boolean;
}

function getProfileConfig(profile: Profile, detected: ProjectProfile): ProfileConfig {
  const base = {
    scanners: detected.recommendedScanners,
    enabledTasks: detected.recommendedTasks,
    enableClassifier: true,
  };

  switch (profile) {
    case "quick":
      return {
        ...base,
        description: "Semgrep scan with classifier, no AI triage verification",
        verify: false,
        pocHarness: false,
      };
    case "standard":
      return {
        ...base,
        description: "Full scan with AI triage and classifier",
        verify: false,
        pocHarness: false,
      };
    case "thorough":
      return {
        ...base,
        description: "Full scan with verification, PoC harness generation, and classifier",
        scanners: [...new Set([...detected.recommendedScanners, "agentic"])],
        verify: true,
        pocHarness: true,
      };
  }
}

async function promptUser(question: string, defaultValue = ""): Promise<string> {
  if (!process.stdin.isTTY) {
    return defaultValue;
  }
  const rl = createInterface({ input: process.stdin, output: process.stdout });
  return new Promise((resolve) => {
    rl.question(question, (answer) => {
      rl.close();
      resolve(answer.trim());
    });
  });
}

export async function runInit(repoRoot: string): Promise<void> {
  const resolved = path.resolve(repoRoot);
  console.log("");
  console.log(chalk.bold("  Kuzushi Project Setup"));
  console.log(chalk.bold("─".repeat(60)));
  console.log("");

  // Check for existing config
  const configFile = projectConfigPath(resolved);
  if (existsSync(configFile)) {
    console.log(`  ${chalk.yellow("Config already exists:")} ${configFile}`);
    const overwrite = await promptUser("  Overwrite? [y/N] ", "n");
    if (overwrite.toLowerCase() !== "y") {
      console.log("  Aborted.");
      return;
    }
    console.log("");
  }

  // Detect project
  const detected = detectProject(resolved);

  console.log(`  ${chalk.cyan("Detected languages:")}  ${detected.languages.join(", ")}`);
  if (detected.frameworks.length > 0) {
    console.log(`  ${chalk.cyan("Detected frameworks:")} ${detected.frameworks.join(", ")}`);
  }
  console.log(`  ${chalk.cyan("Scanners:")}            ${detected.recommendedScanners.join(", ")}`);
  console.log("");

  // Profile selection
  console.log("  Select a scanning profile:");
  console.log("");
  console.log(`  ${chalk.bold("1.")} ${chalk.green("quick")}     — Semgrep only, classifier filter, fast and cheap`);
  console.log(`  ${chalk.bold("2.")} ${chalk.cyan("standard")}  — Full triage with AI, good balance of speed and depth`);
  console.log(`  ${chalk.bold("3.")} ${chalk.magenta("thorough")} — + agentic scanner, verification, PoC harness generation`);
  console.log("");

  const profileChoice = await promptUser("  Choose [1/2/3] (default: 2): ", "2");
  const profileMap: Record<string, Profile> = { "1": "quick", "2": "standard", "3": "thorough", "": "standard" };
  const profile = profileMap[profileChoice] ?? "standard";

  const profileConfig = getProfileConfig(profile, detected);
  console.log("");
  console.log(`  ${chalk.green("Profile:")} ${profile} — ${profileConfig.description}`);

  // Build minimal config (only non-default values)
  const config: Record<string, unknown> = {};

  if (profileConfig.scanners.length > 1 || !profileConfig.scanners.includes("semgrep")) {
    config.scanners = profileConfig.scanners;
  }

  if (profileConfig.verify) {
    config.verify = true;
  }

  if (profileConfig.pocHarness) {
    config.pocHarness = true;
  }

  // Only include enabledTasks if they differ from defaults
  const defaultTasks = [
    "context-gatherer", "context-enricher", "app-model-build",
    "threat-scenario-build", "secrets-crypto-detect", "crypto-behavioral-test",
    "code-config-detect", "taint-analysis-preflight", "taint-analysis-label",
    "taint-analysis-run",
  ];
  const taskSet = new Set(profileConfig.enabledTasks);
  const defaultSet = new Set(defaultTasks);
  const hasExtraTasks = [...taskSet].some((t) => !defaultSet.has(t));
  const hasMissingTasks = [...defaultSet].some((t) => !taskSet.has(t));
  if (hasExtraTasks || hasMissingTasks) {
    config.enabledTasks = profileConfig.enabledTasks;
  }

  // Write config
  const configDir = path.dirname(configFile);
  if (!existsSync(configDir)) {
    mkdirSync(configDir, { recursive: true });
  }
  writeFileSync(configFile, JSON.stringify(config, null, 2) + "\n");

  console.log("");
  console.log(`  ${chalk.green("Config written to:")} ${configFile}`);
  console.log("");
  console.log(`  ${chalk.dim("Run your first scan:")}`);
  console.log(`  ${chalk.bold("npx kuzushi .")}`);
  console.log("");
  console.log(chalk.bold("─".repeat(60)));
}
