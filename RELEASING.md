# Releasing Kuzushi

The canonical changelog lives in [CHANGELOG.md](./CHANGELOG.md). Update it as
part of every release commit.

## Prerequisites

- npm login: `npm whoami` should show your username
- Push access to `github.com/allsmog/Kuzushi`
- `NPM_TOKEN` secret set in GitHub repo settings (for automated CI releases)

## Manual Release (from your machine)

```sh
# 1. Make sure release gates pass locally
pnpm check:docs
pnpm quality:architecture
pnpm quality:model-safety
pnpm quality:crap-risk
pnpm test
pnpm check:types
cargo check --workspace
cargo test --workspace
pnpm build:clean
pnpm build:native
pnpm verify:pack

# 2. Bump version (pick one)
npm version patch --no-git-tag-version   # 0.2.0 -> 0.2.1
npm version minor --no-git-tag-version   # 0.2.0 -> 0.3.0
npm version major --no-git-tag-version   # 0.2.0 -> 1.0.0

# 3. Commit and tag
git add package.json CHANGELOG.md
git commit -m "chore: bump version to $(node -p 'require("./package.json").version')"
git tag "v$(node -p 'require("./package.json").version')"

# 4. Push commit + tag (triggers GitHub Release workflow and npm publish)
git push origin main --tags
```

## Automated Release (via CI)

Pushing a `v*` tag triggers `.github/workflows/release.yml` which:

1. Runs the full reusable CI suite, including the hard-blocking e2e npm-wrapper smoke.
2. Builds native binaries for linux-x64, linux-arm64, darwin-x64,
   darwin-arm64, and win32-x64. Required legs block the release; best-effort
   legs are staged when they build.
3. Stages all green native binaries into `native/<platform>-<arch>/`.
4. Runs `pnpm verify:pack` against the staged package.
5. Publishes to npm with the multi-platform native payload (requires
   `NPM_TOKEN` secret).
6. Creates a GitHub Release with changelog, npm tarball, and native archives.

```sh
# If you've already published manually, just push the tag:
git push origin main --tags
```

## Setting up NPM_TOKEN for CI

1. Go to https://www.npmjs.com → Access Tokens → Generate New Token (Classic, Automation type)
2. Go to GitHub repo → Settings → Secrets and variables → Actions
3. Add `NPM_TOKEN` with the token value

## Verifying a release

```sh
npm view kuzushi version          # check published version
npm install -g kuzushi && kuzushi --version   # install and verify
```

## If a version is already published

npm doesn't allow republishing the same version. Bump and try again:

```sh
npm version patch --no-git-tag-version
npm publish --access public
```

## If you need to force-update a tag

```sh
git tag -d v0.2.0
git tag v0.2.0
git push origin v0.2.0 --force
```
