# Bug-hunting Android APKs with Kuzushi

Operator-facing walkthrough for using Kuzushi against an Android APK on a
HackerOne (or similar) bug-bounty program. Written with Lyft's HackerOne
program as the concrete example.

> **Authorization first.** This guide assumes you have explicit authorization
> to test the target — typically an active HackerOne program with the mobile
> app in scope. Re-read the program's scope, allowed activities, and any
> version constraints **before each session**.

## Pipeline overview

Kuzushi cannot scan a binary `.apk` directly — its scanners expect a directory
tree of source code. The `android-apk` module bridges that gap:

1. **`android-apk:check-env`** verifies that `jadx`, `apktool`, and `unzip`
   are available.
2. **`android-apk:prepare`** validates the APK, unzips raw resources, and
   decompiles to Java source under `<workspace>/android-decompiled/`.
3. **`android-apk:manifest-scan`** parses the apktool-decoded
   `AndroidManifest.xml` and emits findings for `debuggable`, `allowBackup`,
   cleartext traffic, exported components without permissions, deep links,
   and insecure providers. Also writes
   `<workspace>/android-decompiled/taint-sources.json` listing exported
   entry points — Phase C will feed this into `taint-iris-next`
   automatically.
4. **`android-apk:network-security-config`** parses
   `res/xml/network_security_config.xml` and flags cleartext-permitted
   base/domain configs and user-CA trust anchors.
5. **`android-apk:fileprovider-scan`** parses `res/xml/file_paths.xml` and
   flags broad FileProvider path descriptors (root-path, broad external).
6. **`android-apk:webview-scan`** runs a bundled Semgrep rule pack
   covering WebView/JS-bridge misuse, intent redirection, mutable
   `PendingIntent`, ECB/MD5/SHA-1/static-IV crypto misuse, PII logging,
   and clipboard credential leaks against the decompiled jadx tree.
7. **`android-apk:sast-handoff`** returns the canonical scan target
   plus next-step commands so downstream scanners
   (`semgrep:scan`, `codeql:scan`, `exploit-chain:scan`,
   `agentic-sast:scan`, `taint-iris-next:hunt`, `secret-scan:scan`)
   can be invoked against the right subtrees.
8. **`android-apk:native-libs`** enumerates `.so` files under
   `<workspace>/android-decompiled/raw/lib/<abi>/`, parses their ELF
   dynamic symbols with goblin, and flags dangerous imports
   (`system`/`execve`/`dlopen`/`strcpy`) plus JNI export attack
   surface (`Java_*`).
9. **`android-apk:hybrid-detect`** finds on-disk fingerprints of
   Cordova / React Native / Capacitor / Flutter / Ionic so you know
   when to follow up on the embedded JS/Dart bundle.

The existing scanners (`semgrep:scan`, `codeql:scan`, `secret-scan:scan`,
`exploit-chain:scan`, `agentic-sast:scan`, `taint-iris-next:hunt`,
`triage:run`, `verify:finding`) consume the decompiled tree.

Future work tracked in the plan: full smali fallback for code that's so
heavily obfuscated `jadx` produces unusable Java; deeper revng MCP
integration so native `.so` analysis can identify symbolic taint flows
into JNI exports.

> **HackerOne authorization.** Before each session, walk through
> [docs/hackerone-scope-checklist.md](./hackerone-scope-checklist.md) to
> confirm the app, version, and activities you're about to perform are
> in scope.

## Prerequisites

Install the decompilation toolchain on your machine (or your Kuzushi-on-the-web
container):

- **jadx** — `https://github.com/skylot/jadx/releases` (the `jadx` CLI script)
- **apktool** — `https://apktool.org/`
- **unzip** — standard on macOS/Linux; install via your package manager on
  bare images
- Optional, future phases: `d2j-dex2jar`, `frida`, `revng`, `joern`, `codeql`

Verify they're on PATH:

```bash
kuzushi run android-apk:check-env
```

The tool prints one entry per binary with `found`, `resolvedPath`, and
`versionLine`. Pass explicit binary paths via the tool input if any are
installed somewhere non-standard:

```bash
kuzushi run android-apk:check-env --input '{
  "jadxBin": "/opt/jadx/bin/jadx",
  "apktoolBin": "/usr/local/bin/apktool"
}'
```

## One-command pipeline

`kuzushi scan` auto-detects `.apk` files and routes them through the
android-apk pipeline. Run it directly against your downloaded APK:

```bash
kuzushi scan ./me.lyft.android-2026.42.apk
```

(or equivalently, the explicit form
`kuzushi run android-apk:scan --input '{"apk":"./me.lyft.android-2026.42.apk"}'`).

Both forms validate the APK, decompile it, and run every
android-apk:* scanner plus the sast-handoff bridge in one pass, with a
per-stage breakdown.

Output is shaped like:

```
android-apk:scan: 8 stages, 21 findings, 3 skipped, 22858ms

stages:
  [+] prepare                        findings=0
  [+] manifest-scan                  findings=10
  [x] network-security-config        findings=0   (skipped — no config)
  [x] fileprovider-scan              findings=0   (skipped — no FileProvider)
  [+] webview-scan                   findings=11
  [x] native-libs                    findings=0   (skipped — no .so files)
  [+] hybrid-detect                  findings=0
  [+] sast-handoff                   findings=0
```

Stages that can't run (missing `network_security_config.xml`,
`file_paths.xml`, or `lib/<abi>/`) show up in `warnings` rather than
failing the pipeline — most APKs only ship a subset of these. After
the umbrella finishes, run `kuzushi findings --severity high,critical`
to inspect everything that landed in the findings store, then chase
individual leads through the manual workflow below.

Skip flags (`skipNative`, `skipWebview`, `skipHybrid`) cut runtime when
the corresponding subsystem is missing or you've already inspected it.

## End-to-end workflow (manual, per-tool)

### 1. Authenticate

```bash
kuzushi auth login anthropic
```

One-time. See `kuzushi auth --help` for OAuth vs. env-var token options.

### 2. Confirm scope

Open the program page (e.g. `https://hackerone.com/lyft`) and re-read:

- In-scope assets (the Android app's package name + which surfaces are
  testable)
- Out-of-bounds activities (no DoS, no PII exfiltration beyond your own
  account, no malware distribution, etc.)
- Version constraints (some programs only accept reports against the current
  Play Store release)

Capture today's session scope in your notes; cross-check the APK version
you downloaded against the program's accepted versions.

### 3. Acquire the APK

Out of scope for this tool — you handle acquisition manually:

- Pull from your own device (`adb shell pm path <package>` →
  `adb pull <path>`), or
- Download from a reputable mirror permitted by the program (APKMirror,
  APKPure), or
- Sideload from the Play Store on a personal device

Confirm SHA-256 and version code match what the program lists if it
publishes a canonical hash.

### 4. Prepare a workspace and decompile

```bash
mkdir -p ~/lyft-bug-hunt/workspace
cd ~/lyft-bug-hunt/workspace

kuzushi run android-apk:prepare --input '{
  "apk": "~/lyft-bug-hunt/me.lyft.android-2026.42.apk",
  "decompiler": "both"
}'
```

`decompiler` accepts `jadx`, `apktool`, or `both`. `jadx` produces Java
source under `android-decompiled/jadx/` (best for SAST). `apktool` produces
smali + decoded resources (including a human-readable
`AndroidManifest.xml`) under `android-decompiled/apktool/`. `both` is the
default and recommended.

Output includes paths and suggested next steps:

```json
{
  "ok": true,
  "summary": "android-apk: prepared … into …/android-decompiled",
  "data": {
    "decompiledRoot": "…/android-decompiled",
    "rawDir": "…/android-decompiled/raw",
    "jadxDir": "…/android-decompiled/jadx",
    "apktoolDir": "…/android-decompiled/apktool",
    "nextSteps": [
      "kuzushi scan …/android-decompiled",
      "kuzushi findings --severity high,critical"
    ]
  }
}
```

### 5. Run the scanners

Targeting the decompiled root lets every engine see Java source,
`AndroidManifest.xml`, `strings.xml`, and friends:

```bash
kuzushi scan ./android-decompiled
```

Or run individual engines for faster iteration:

```bash
kuzushi run semgrep:scan       --input '{"target":"./android-decompiled/jadx"}'
kuzushi run secret-scan:scan   --input '{"target":"./android-decompiled/raw"}'
kuzushi run exploit-chain:scan --input '{"target":"./android-decompiled/jadx"}'
```

### 6. Review findings

```bash
kuzushi findings --severity high,critical --limit 50
kuzushi finding F-3
```

In the interactive shell:

```bash
kuzushi shell
> /findings
> /open F-3
> /verify
```

## Working around obfuscation

Production Android apps (Lyft included) ship with R8/ProGuard obfuscation.
`jadx` will produce code with mangled names (`a.b.c`, single-letter methods).
Identifier-based Semgrep patterns miss most things. Mitigations available
today:

- **Structural rules** — Semgrep patterns matched on AST shape (call sites,
  method-chain shapes) survive renaming.
- **Data-flow** — `exploit-chain:scan` and `taint-iris-next:hunt` use
  CodeQL/Joern through their MCP servers. Joern's `joern.taint_paths` is
  agnostic to identifier names; it traces actual edges in the code property
  graph.
- **apktool smali fallback** — when an interesting source location in jadx
  output is fully renamed, drop into
  `android-decompiled/apktool/smali_classes*/…` and read the underlying
  bytecode disassembly.
- **Manifest + resources are unaffected.** Exported components, deeplink
  schemes, permissions, `network_security_config.xml`,
  `file_paths.xml`, `strings.xml` — all readable as-is. Phase B of the
  module adds dedicated scanners for these surfaces; in the meantime you
  can grep them directly.

## What to look for (HackerOne-relevant)

A first-pass triage list for a major-vendor Android app:

- **Exported activities/services/receivers without permissions** — anyone on
  the device can `am start` them. Hunt in `apktool/AndroidManifest.xml`.
- **Deep-link / URI-scheme handlers** — `<intent-filter>` blocks with
  `<data android:scheme=…>`. Each scheme is a potential entry point; trace
  into the handling activity.
- **WebView misconfiguration** — `setJavaScriptEnabled(true)` combined with
  `addJavascriptInterface(...)`, `setAllowFileAccess(true)`, or insecure
  `WebViewClient.shouldOverrideUrlLoading`.
- **File providers with broad paths** — `res/xml/file_paths.xml` with
  `<root-path />` or `<external-path path="." />`.
- **Cleartext traffic / network security config** — `usesCleartextTraffic`
  in the manifest, or `network_security_config.xml` allowing cleartext to
  attacker-reachable domains.
- **Hardcoded secrets** — Firebase API keys, Google Maps keys, OAuth client
  secrets, S3 buckets in `strings.xml` or `res/raw/`.
- **Insecure storage** — `MODE_WORLD_READABLE`, `MODE_WORLD_WRITEABLE`,
  `getExternalStorageDirectory()` for sensitive data.
- **PendingIntent without `FLAG_IMMUTABLE`** — CVE-2020-0294 family on
  affected Android versions.
- **Native code paths** — `lib/*/lib*.so`. Phase D of the module adds
  automated triage; until then, look for JNI exports + dangerous imports
  (`system`, `exec`, `dlopen`) with `nm`/`objdump`.

## What's NOT in Phase A (yet)

- Dedicated `manifest-scan`, `network-security-config`, `fileprovider-scan`,
  `webview-scan`, and `secrets` (Android-tuned) tools — coming in Phase B.
- `sast-handoff` automatic retargeting — Phase C.
- Native `.so` triage and smali-fallback rules — Phase D.

Until then, run the generic scanners manually against
`android-decompiled/jadx` and `android-decompiled/raw` as shown above.

## Reporting

When you find something on Lyft (or any HackerOne program):

1. Reproduce on a vanilla device with the version listed in the program scope.
2. Capture exact steps, traffic captures, screenshots, and the device/OS
   version.
3. Map the issue to a CWE; Kuzushi findings already include `dedup_key` /
   `cwe` when extractable.
4. Submit through HackerOne, not directly to the vendor.

Do **not** test against production user accounts other than your own; do
**not** combine static analysis with live network attacks unless the
program explicitly authorizes it.
