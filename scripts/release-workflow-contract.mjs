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

const crossBuiltSlugs = new Set(releaseCrossBuilds.map(({ slug }) => slug));

export const releaseNativeBuildPlatforms = Object.freeze(
  releasePlatforms.filter(({ slug }) => !crossBuiltSlugs.has(slug)),
);

export function candidateWorkflowFailures(source) {
  return [
    ...missingTokens(source, "release candidate", candidateRequirements()),
    ...forbiddenTokens(source, "release candidate", candidateForbiddenTokens()),
    ...releaseMatrixFailures(source),
  ];
}

export function publisherWorkflowFailures(source) {
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
