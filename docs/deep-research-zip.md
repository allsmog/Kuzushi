# Deep Research Zip Manifest

Use this manifest when preparing a lean Kuzushi source archive for upload to ChatGPT Pro Deep Research.

## Include

Zip the `Kuzushi/` working tree source as it exists at archive time, including:

- Rust crates under `crates/`
- TypeScript source under `src/`
- CLI/runtime scripts under `bin/` and `scripts/`
- Schemas under `schemas/` and `generated/schemas/`
- Docs, reports, prompts, recipes, findings, benchmarks, tests, assets, examples, and design references that explain the project
- Project metadata and config files such as `Cargo.toml`, `Cargo.lock`, `package.json`, `pnpm-lock.yaml`, `tsconfig.json`, `.github/`, `.husky/`, and lint/test configs

## Exclude

Do not include local/generated/heavy artifacts or secrets:

- `.git/`
- `node_modules/`
- `target/`
- `crates/*/target/`
- `.kuzushi/`
- `crates/*/.kuzushi/`
- `.pnpm-store/`
- `native/`
- `.env`, `.env.*`, and other local environment files
- Build/cache/output folders such as `dist/`, `build/`, `coverage/`, `.cache/`, `.next/`, `.turbo/`
- Logs, local databases, archives, OS junk, and editor metadata

## Command Used

Run this from `/workspace`:

```sh
zip -r Kuzushi-deep-research.zip Kuzushi \
  -x 'Kuzushi/.git/*' \
  -x 'Kuzushi/node_modules/*' \
  -x 'Kuzushi/target/*' \
  -x 'Kuzushi/crates/*/target/*' \
  -x 'Kuzushi/.kuzushi/*' \
  -x 'Kuzushi/crates/*/.kuzushi/*' \
  -x 'Kuzushi/.pnpm-store/*' \
  -x 'Kuzushi/native/*' \
  -x 'Kuzushi/.env' \
  -x 'Kuzushi/.env.*' \
  -x 'Kuzushi/**/.env' \
  -x 'Kuzushi/**/.env.*' \
  -x 'Kuzushi/dist/*' \
  -x 'Kuzushi/build/*' \
  -x 'Kuzushi/coverage/*' \
  -x 'Kuzushi/.cache/*' \
  -x 'Kuzushi/.next/*' \
  -x 'Kuzushi/.turbo/*' \
  -x 'Kuzushi/**/*.log' \
  -x 'Kuzushi/**/*.sqlite' \
  -x 'Kuzushi/**/*.sqlite3' \
  -x 'Kuzushi/**/*.db' \
  -x 'Kuzushi/**/*.zip' \
  -x 'Kuzushi/.DS_Store' \
  -x 'Kuzushi/**/.DS_Store'
```

## Verification

After zipping:

```sh
zipinfo -1 Kuzushi-deep-research.zip | grep -E '(^|/)(\.git|node_modules|target|\.kuzushi|native|\.env|\.pnpm-store)(/|$)'
zipinfo -1 Kuzushi-deep-research.zip | grep -E '\.(sqlite3?|db|log|zip)$'
```

Both commands should print no archive entries.
