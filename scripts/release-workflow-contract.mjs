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
    "name: release-candidate-packages",
    "node scripts/publish-platform-packages.mjs",
    "--tag latest",
    "uses: ./.github/workflows/published-release-smoke.yml",
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
    "needs: identity",
    "uses: ./.github/workflows/ci-full.yml",
    "quality_base_ref: ${{ inputs.quality_base_ref }}",
    "pnpm audit --prod --audit-level high",
    "KUZUSHI_VERIFY_PACK_RELEASE_ASSEMBLY",
    "name: release-candidate-packages",
  ];
}

function candidateForbiddenTokens() {
  return ["NPM_TOKEN", "npm publish", "id-token: write", "contents: write", "action-gh-release"];
}

function releaseMatrixFailures(source) {
  return releasePlatforms
    .filter(
      ({ runner, slug }) =>
        !source.includes(`          - os: ${runner}\n            slug: ${slug}`),
    )
    .map(({ runner, slug }) => `release candidate must build ${slug} on ${runner}`);
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
