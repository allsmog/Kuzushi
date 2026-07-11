const DEFAULT_LIMITS_BY_MODE = {
  quick: { deadlineMs: 30_000, cpuSeconds: 30, artifactBytes: 4_194_304, maxCrashes: 4 },
  standard: {
    deadlineMs: 180_000,
    cpuSeconds: 180,
    artifactBytes: 16_777_216,
    maxCrashes: 16,
  },
  deep: {
    deadlineMs: 600_000,
    cpuSeconds: 600,
    artifactBytes: 67_108_864,
    maxCrashes: 64,
  },
};

export default {
  id: "agentic-fuzz",
  name: "Agentic Fuzz",
  kind: "offense",
  description: "Run brokered fuzz jobs through KWP without ambient execution.",
  tools: [
    {
      name: "agentic-fuzz:hunt",
      description: "Select a fuzz target and run it through the host fuzz executor.",
      headless: true,
      runtimeRequirement: "never",
      phase: "hunt",
      effect: "workspace-write",
      approval: "none",
      workspaceRequirement: "required",
      inputSchema: {
        type: "object",
        additionalProperties: false,
        properties: {
          mode: {
            type: "string",
            enum: ["quick", "standard", "deep"],
            default: "quick",
            description: "Fuzzing budget profile.",
          },
          engine: {
            type: "string",
            default: "property-tests",
            description: "Host-mounted fuzz engine.",
          },
          language: {
            type: "string",
            default: "javascript",
            description: "Target language passed to the fuzz executor.",
          },
          projectPath: {
            type: "string",
            default: ".",
            description: "Workspace-relative project path.",
          },
          harnessPath: {
            type: "string",
            description: "Workspace-relative fuzz harness path.",
          },
          targetId: {
            type: "string",
            default: "default",
            description: "Stable target id for artifact layout.",
          },
          outputPath: {
            type: "string",
            description: "Workspace-relative fuzz log artifact path.",
          },
          planPath: {
            type: "string",
            description: "Workspace-relative target plan artifact path.",
          },
          useSymcc: {
            type: "boolean",
            default: false,
            description: "Call the host-mounted symcc MCP alias before fuzzing.",
          },
          symccOutputPath: {
            type: "string",
            description: "Workspace-relative SymCC output artifact path.",
          },
          allowNetworkDuringFuzz: {
            type: "boolean",
            default: false,
            description: "Request network access for the fuzz job.",
          },
          createFindings: {
            type: "boolean",
            default: false,
            description: "Persist findings for returned crashes when granted.",
          },
          inputs: {
            type: "object",
            description: "Additional fuzz executor inputs.",
          },
          limits: {
            type: "object",
            description: "Per-run fuzz limits.",
          },
        },
        required: ["harnessPath"],
      },
      async run(input, ctx) {
        const normalized = normalizeInput(input);
        const plan = targetPlan(normalized);
        const planArtifact = await writeTargetPlan(ctx, normalized.planPath, plan);
        const symcc = await maybeRunSymcc(ctx, normalized);
        const fuzz = await runFuzz(ctx, normalized);
        const artifacts = collectArtifacts([planArtifact], symcc, fuzz);
        const verifiedArtifacts = await recordArtifacts(ctx, artifacts);
        const findings = crashFindings(
          fuzz.crashes ?? [],
          verifiedArtifacts,
          normalized.harnessPath,
        );
        const createdFindings = await maybeCreateFindings(ctx, normalized, findings);

        return {
          status: "completed",
          output: `agentic-fuzz:hunt completed with ${fuzz.crashes?.length ?? 0} crash(es)`,
          data: {
            plan,
            symcc,
            fuzz,
            findingsCreated: createdFindings?.created ?? 0,
          },
          artifacts: verifiedArtifacts,
          findings,
        };
      },
    },
  ],
};

function normalizeInput(input) {
  const mode = enumInput(input, "mode", ["quick", "standard", "deep"], "quick");
  const targetId = safeSegment(stringInput(input, "targetId", "default"));
  const limits = { ...DEFAULT_LIMITS_BY_MODE[mode], ...objectInput(input, "limits") };
  const outputPath = stringInput(
    input,
    "outputPath",
    `agentic-fuzz/runs/${targetId}/stdout.txt`,
  );
  return {
    mode,
    targetId,
    engine: stringInput(input, "engine", "property-tests"),
    language: stringInput(input, "language", "javascript"),
    projectPath: stringInput(input, "projectPath", "."),
    harnessPath: requiredString(input, "harnessPath"),
    outputPath,
    planPath: stringInput(input, "planPath", "agentic-fuzz/target-plan.json"),
    symccOutputPath: stringInput(
      input,
      "symccOutputPath",
      `agentic-fuzz/symcc/${targetId}/instrumented.txt`,
    ),
    useSymcc: booleanInput(input, "useSymcc", false),
    allowNetworkDuringFuzz: booleanInput(input, "allowNetworkDuringFuzz", false),
    createFindings: booleanInput(input, "createFindings", false),
    inputs: { ...objectInput(input, "inputs"), outputPath },
    limits,
  };
}

function targetPlan(input) {
  return {
    module: "agentic-fuzz",
    action: "hunt",
    mode: input.mode,
    target: {
      id: input.targetId,
      language: input.language,
      projectPath: input.projectPath,
      harnessPath: input.harnessPath,
    },
    engine: input.engine,
    brokeredCapabilities: {
      fs: ["workspace.write"],
      fuzz: [input.engine],
      mcp: input.useSymcc ? ["symcc:compile"] : [],
      artifacts: ["write"],
    },
  };
}

async function writeTargetPlan(ctx, path, plan) {
  requireHandle(ctx.fs, "ctx.fs");
  await ctx.fs.writeText("workspace", path, `${JSON.stringify(plan, null, 2)}\n`);
  return { path, mediaType: "application/json" };
}

async function maybeRunSymcc(ctx, input) {
  if (!input.useSymcc) return null;
  requireHandle(ctx.mcp, "ctx.mcp");
  return await ctx.mcp.call(
    "symcc",
    "compile",
    {
      projectPath: input.projectPath,
      harnessPath: input.harnessPath,
      output: input.symccOutputPath,
    },
    {
      artifactBytes: input.limits.artifactBytes,
      cpuSeconds: input.limits.cpuSeconds,
    },
  );
}

async function runFuzz(ctx, input) {
  requireHandle(ctx.fuzz, "ctx.fuzz");
  return await ctx.fuzz.run({
    engine: input.engine,
    target: {
      language: input.language,
      projectPath: input.projectPath,
      harnessPath: input.harnessPath,
    },
    inputs: input.inputs,
    limits: input.limits,
    sandbox: {
      network: input.allowNetworkDuringFuzz,
      readOnlySource: true,
    },
  });
}

function collectArtifacts(seedArtifacts, symcc, fuzz) {
  return [
    ...seedArtifacts,
    ...artifactRefs(symcc?.artifacts),
    ...artifactRefs(symcc?._kuzushi?.artifacts),
    ...artifactRefs(fuzz?.artifacts),
  ];
}

async function recordArtifacts(ctx, artifacts) {
  if (artifacts.length === 0) return [];
  requireHandle(ctx.artifacts, "ctx.artifacts");
  const result = await ctx.artifacts.record(artifacts);
  return result.artifacts ?? [];
}

async function maybeCreateFindings(ctx, input, findings) {
  if (!input.createFindings || findings.length === 0) return null;
  requireHandle(ctx.findings, "ctx.findings");
  return await ctx.findings.create(findings);
}

function crashFindings(crashes, artifacts, harnessPath) {
  return crashes.map((value, index) => {
    const crash = value && typeof value === "object" ? value : {};
    return {
      title: stringInput(crash, "title", `Fuzz crash ${index + 1}`),
      severity: stringInput(crash, "severity", "high"),
      confidence: stringInput(crash, "confidence", "medium"),
      filePath: stringInput(crash, "filePath", harnessPath),
      startLine: 1,
      vulnSource: "fuzzing",
      ruleId: "agentic-fuzz:crash",
      message: stringInput(
        crash,
        "message",
        "Brokered fuzzing returned a crash candidate.",
      ),
      references: artifacts.map((artifact) => artifact.path),
      reproduction: crash.reproduction ?? null,
    };
  });
}

function artifactRefs(value) {
  return Array.isArray(value)
    ? value.filter((artifact) => artifact && typeof artifact.path === "string")
    : [];
}

function requireHandle(handle, name) {
  if (!handle || typeof handle !== "object") {
    throw new Error(`${name} is required for agentic-fuzz:hunt`);
  }
}

function stringInput(input, key, fallback) {
  const value = input?.[key];
  return typeof value === "string" && value.trim() !== "" ? value : fallback;
}

function requiredString(input, key) {
  const value = stringInput(input, key, "");
  if (!value) throw new Error(`${key} is required`);
  return value;
}

function booleanInput(input, key, fallback) {
  return typeof input?.[key] === "boolean" ? input[key] : fallback;
}

function objectInput(input, key) {
  const value = input?.[key];
  return value && typeof value === "object" && !Array.isArray(value) ? value : {};
}

function enumInput(input, key, allowed, fallback) {
  const value = input?.[key];
  return allowed.includes(value) ? value : fallback;
}

function safeSegment(value) {
  return value.replace(/[^a-zA-Z0-9_.-]/g, "_") || "default";
}
