const fullCommitRef = /^[0-9a-f]{40}$/;

export const releasePlatforms = Object.freeze([
  { runner: "ubuntu-24.04", slug: "linux-x64" },
  { runner: "ubuntu-24.04-arm", slug: "linux-arm64" },
  { runner: "macos-15-intel", slug: "darwin-x64" },
  { runner: "macos-14", slug: "darwin-arm64" },
  { runner: "windows-2025", slug: "win32-x64" },
]);

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
  return releasePlatforms
    .filter(({ runner, slug }) => {
      const entry = `          - os: ${runner}\n            slug: ${slug}`;
      return source.split(entry).length - 1 < 2;
    })
    .map(({ runner, slug }) => `release candidate must build and install ${slug} on ${runner}`);
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
