const fullCommitRef = /^[0-9a-f]{40}$/;

/** Every slug is still installed and executed on its own release runner. */
export const releasePlatforms = Object.freeze([
  { runner: "ubuntu-24.04", slug: "linux-x64" },
  { runner: "ubuntu-24.04-arm", slug: "linux-arm64" },
  { runner: "macos-15-intel", slug: "darwin-x64" },
  { runner: "macos-14", slug: "darwin-arm64" },
  { runner: "windows-2025", slug: "win32-x64" },
]);

/**
 * darwin-x64 is cross-compiled from the Apple silicon runner instead of paying
 * for a 10x-billed Intel macOS build host, so it has no native-build row of its
 * own. Every other slug is still built on a runner of its own architecture.
 */
export const releaseCrossBuilds = Object.freeze([
  {
    runner: "macos-14",
    hostSlug: "darwin-arm64",
    slug: "darwin-x64",
    target: "x86_64-apple-darwin",
  },
]);

/**
 * The owner's self-hosted Apple silicon runner. Every darwin leg stays eligible
 * for it, but releases default to the hosted images named in `releasePlatforms`;
 * `hosted: false` (or `KUZUSHI_RELEASE_SELF_HOSTED=true`) opts one run in.
 */
export const selfHostedMacLabels = Object.freeze(["self-hosted", "macOS", "ARM64", "kuzushi-mac"]);

/** The one `runs-on` form every self-hosted-eligible matrix job must use. */
export const selfHostedMatrixRunsOn =
  `runs-on: \${{ fromJSON(matrix.self_hosted && !inputs.hosted && '${JSON.stringify(selfHostedMacLabels)}'` +
  ` || format('["{0}"]', matrix.os)) }}`;

/** Darwin legs that must be eligible for the self-hosted runner, per job. */
export const selfHostedDarwinLegs = Object.freeze([
  { job: "native-binaries", slug: "darwin-arm64", rosetta: false },
  { job: "local-tarball-smoke", slug: "darwin-arm64", rosetta: false },
  { job: "local-tarball-smoke", slug: "darwin-x64", rosetta: true },
]);

/**
 * Jobs that hold a publishing credential or a write permission. They stay on
 * GitHub-hosted ubuntu images: a self-hosted runner is a persistent machine,
 * and `NPM_TOKEN` and `contents: write` must never reach one.
 */
export const hostedOnlyCandidateJobs = Object.freeze(["identity", "assemble"]);
export const hostedOnlyPublisherJobs = Object.freeze(["publish-npm", "github-release"]);

const crossBuiltSlugs = new Set(releaseCrossBuilds.map(({ slug }) => slug));

export const releaseNativeBuildPlatforms = Object.freeze(
  releasePlatforms.filter(({ slug }) => !crossBuiltSlugs.has(slug)),
);

export function candidateWorkflowFailures(source) {
  return [
    ...missingTokens(source, "release candidate", candidateRequirements()),
    ...forbiddenTokens(source, "release candidate", candidateForbiddenTokens()),
    ...releaseMatrixFailures(source),
    ...selfHostedDarwinFailures(source),
    ...hostedOnlyJobFailures(source, "release candidate", hostedOnlyCandidateJobs),
  ];
}

/**
 * The published smoke installs from the registry, so it holds no credential.
 * Its darwin legs stay eligible for the self-hosted runner and its darwin-x64
 * leg still has to prove it translated rather than smoked the host payload.
 */
export function publishedSmokeWorkflowFailures(source) {
  return [
    ...missingTokens(source, "published smoke", [
      "hosted:",
      "type: boolean",
      selfHostedMatrixRunsOn,
      "KUZUSHI_SMOKE_SLUG: ${{ matrix.slug }}",
      "KUZUSHI_SMOKE_ALLOW_ROSETTA: ${{ matrix.rosetta }}",
    ]),
    ...forbiddenTokens(source, "published smoke", ["NPM_TOKEN", "contents: write"]),
    ...darwinLegFailures(source, "published smoke", "published-install", [
      { slug: "darwin-arm64", rosetta: false },
      { slug: "darwin-x64", rosetta: true },
    ]),
  ];
}

export function publisherWorkflowFailures(source) {
  return [
    ...hostedOnlyJobFailures(source, "release publisher", hostedOnlyPublisherJobs),
    ...publisherTokenFailures(source),
  ];
}

function publisherTokenFailures(source) {
  return missingTokens(source, "release publisher", [
    "tags:",
    '      - "v*"',
    "uses: ./.github/workflows/release-candidate.yml",
    "release tag must point at current origin/${DEFAULT_BRANCH}",
    'expected_tag="v${version}"',
    "name: release-candidate-artifacts",
    "node scripts/verify-release-artifacts.mjs",
    "node scripts/publish-platform-packages.mjs",
    "Publish verified npm packages with the thin launcher last",
    "uses: ./.github/workflows/published-release-smoke.yml",
  ]);
}

export function platformPublisherFailures(source) {
  return missingTokens(source, "platform publisher", [
    "verifyReleaseManifest",
    '"--tag",',
    '"latest",',
    '"--ignore-scripts",',
    "entry.npmIntegrity",
    'kind }) => kind === "root-npm"',
  ]);
}

export function callGraphActionPinFailures(workflows) {
  return workflows.flatMap(({ name, source }) => externalActionPinFailures(name, source));
}

export function actionlintImageFailures(source) {
  return /rhysd\/actionlint:1\.7\.12@sha256:[0-9a-f]{64}/.test(source)
    ? []
    : ["full CI must pin the actionlint image by SHA-256 digest"];
}

function candidateRequirements() {
  return [
    "workflow_dispatch:",
    "workflow_call:",
    "expected_sha must equal the caller commit",
    "quality_base_ref must precede the candidate",
    "node scripts/check-secrets.mjs --base 0000000000000000000000000000000000000000",
    "node scripts/check-release-source.mjs",
    "needs: identity",
    "uses: ./.github/workflows/ci-full.yml",
    "quality_base_ref: ${{ inputs.quality_base_ref }}",
    "pnpm audit --prod --audit-level high",
    "KUZUSHI_VERIFY_PACK_RELEASE_ASSEMBLY",
    "node scripts/build-release-artifacts.mjs",
    "name: release-candidate-artifacts",
    "node scripts/smoke-release-tarballs.mjs",
    "local-tarball-smoke-${{ matrix.slug }}",
  ];
}

function candidateForbiddenTokens() {
  return ["NPM_TOKEN", "npm publish", "id-token: write", "contents: write", "action-gh-release"];
}

function releaseMatrixFailures(source) {
  return [
    ...missingMatrixRows(source, "native-binaries", releaseNativeBuildPlatforms, "build"),
    ...missingMatrixRows(source, "local-tarball-smoke", releasePlatforms, "install"),
    ...crossBuildFailures(source),
  ];
}

/** Each matrix is checked inside its own job so one job cannot cover another. */
function missingMatrixRows(source, jobName, platforms, action) {
  const section = jobSection(source, jobName);
  return platforms
    .filter(({ runner, slug }) => !section.includes(matrixRow(runner, slug)))
    .map(({ runner, slug }) => `release candidate must ${action} ${slug} on ${runner}`);
}

function jobSection(source, jobName) {
  const start = source.indexOf(`\n  ${jobName}:\n`);
  if (start === -1) return "";
  const next = source.slice(start + 1).search(/\n {2}[a-z][a-z0-9-]*:\n/);
  return next === -1 ? source.slice(start) : source.slice(start, start + 1 + next);
}

/**
 * A cross-built slug must be produced by an explicit target on its host runner
 * and uploaded under its own artifact name, never inherited from the host build.
 */
function crossBuildFailures(source) {
  const section = jobSection(source, "native-binaries");
  return releaseCrossBuilds.flatMap(({ runner, hostSlug, slug, target }) =>
    [
      `${matrixRow(runner, hostSlug)}\n            cross_slug: ${slug}`,
      `            cross_target: ${target}`,
      `rustup target add \${{ matrix.cross_target }}`,
      "KUZUSHI_NATIVE_TARGET: ${{ matrix.cross_target }}",
      "name: release-candidate-native-${{ matrix.cross_slug }}",
    ]
      .filter((token) => !section.includes(token))
      .map((token) => `release candidate must cross-build ${slug} on ${runner} via ${token}`),
  );
}

function matrixRow(runner, slug) {
  return `          - os: ${runner}\n            slug: ${slug}`;
}

/**
 * Every darwin leg must be eligible for the self-hosted runner, and only the
 * darwin-x64 leg may carry the Rosetta opt-in: an arm64 payload smoked under
 * translation would prove nothing about the runner it actually ships to.
 */
function selfHostedDarwinFailures(source) {
  const byJob = new Map();
  for (const { job, slug, rosetta } of selfHostedDarwinLegs) {
    byJob.set(job, [...(byJob.get(job) ?? []), { slug, rosetta }]);
  }
  return [
    ...missingTokens(source, "release candidate", [
      "hosted:",
      "KUZUSHI_SMOKE_ALLOW_ROSETTA: ${{ matrix.rosetta }}",
    ]),
    ...[...byJob].flatMap(([job, legs]) =>
      darwinLegFailures(source, "release candidate", job, legs),
    ),
  ];
}

function darwinLegFailures(source, subject, jobName, legs) {
  const section = jobSection(source, jobName);
  return [
    ...(section.includes(selfHostedMatrixRunsOn)
      ? []
      : [`${subject} ${jobName} must select the self-hosted runner by matrix.self_hosted`]),
    ...legs.flatMap(({ slug, rosetta }) =>
      darwinRowFailures(subject, jobName, section, slug, rosetta),
    ),
  ];
}

function darwinRowFailures(subject, jobName, section, slug, rosetta) {
  const row = darwinRowText(section, slug);
  const failures = [];
  if (!row.includes("self_hosted: true")) {
    failures.push(`${subject} ${jobName} must run ${slug} on the self-hosted runner`);
  }
  if (row.includes('rosetta: "1"') !== rosetta) {
    failures.push(`${subject} ${jobName} ${slug} carries the wrong Rosetta opt-in`);
  }
  return failures;
}

/** The matrix row's own keys, up to the next `- os:` entry or the job's end. */
function darwinRowText(section, slug) {
  const start = section.indexOf(`            slug: ${slug}\n`);
  if (start === -1) return "";
  const rest = section.slice(start);
  const next = rest.search(/\n {10}- os:/);
  return next === -1 ? rest : rest.slice(0, next);
}

/**
 * A self-hosted runner is a persistent machine the owner reuses, so a job that
 * touches `NPM_TOKEN` or `contents: write` must stay on an ephemeral hosted one.
 */
function hostedOnlyJobFailures(source, subject, jobNames) {
  return jobNames.flatMap((jobName) => {
    const section = jobSection(source, jobName);
    if (!section) return [`${subject} is missing the ${jobName} job`];
    if (!section.includes("runs-on: ubuntu-24.04")) {
      return [`${subject} ${jobName} must pin a GitHub-hosted ubuntu runner`];
    }
    return selfHostedMacLabels.some((label) => section.includes(`"${label}"`))
      ? [`${subject} ${jobName} must never run on the self-hosted runner`]
      : [];
  });
}

function externalActionPinFailures(workflowName, source) {
  return actionUses(source)
    .filter((specifier) => !specifier.startsWith("./"))
    .filter((specifier) => !fullCommitRef.test(specifier.slice(specifier.lastIndexOf("@") + 1)))
    .map((specifier) => `${workflowName} action must use a full commit pin: ${specifier}`);
}

function actionUses(source) {
  return [...source.matchAll(/^\s*-?\s*uses:\s+([^\s#]+)/gm)].map((match) => match[1]);
}

function missingTokens(source, subject, tokens) {
  return tokens
    .filter((token) => !source.includes(token))
    .map((token) => `${subject} must contain ${token}`);
}

function forbiddenTokens(source, subject, tokens) {
  return tokens
    .filter((token) => source.includes(token))
    .map((token) => `${subject} must not contain ${token}`);
}
