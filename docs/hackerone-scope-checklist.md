# HackerOne scope checklist (per-session)

Use this list before every Kuzushi-on-an-APK session against any HackerOne
program. The static analysis itself is safe, but reporting depends on
staying inside what the program authorizes. Confirm every item — write the
answer in your notes, not just nod through it.

## Program

- [ ] Program URL (`https://hackerone.com/<program>`): ____________________
- [ ] Date you last re-read the policy: ____________________
- [ ] Asset scope includes the Android app for this session? (yes/no): ____
- [ ] Package name (e.g. `me.lyft.android`) is listed as in-scope? ____
- [ ] Version constraints — does the program restrict to current Play Store
      release? Note any version cap or floor: ____________________
- [ ] Out-of-scope activities you'll avoid (DoS, social engineering, mass
      automation, PII exfiltration, account brute force, modifying live
      user data, etc.): ____________________

## APK provenance

- [ ] Source of the APK (sideload from your device / APKMirror /
      APKPure / vendor-published): ____________________
- [ ] SHA-256 of the .apk file: ____________________
- [ ] Version code from `aapt dump badging`: ____________________
- [ ] Cross-checked against what the program lists as testable? ____

## Static analysis only

This Kuzushi run is **static** — it does not talk to production servers,
does not log into accounts, does not exercise the live app. Confirm:

- [ ] No `adb` shell against a logged-in production device with a non-test
      account
- [ ] No traffic interception against production endpoints — if you want to
      proxy, use a test account on a test instance
- [ ] No automated tooling pointed at production APIs

## Reporting bar

Before you submit:

- [ ] Reproduce on a clean device with the in-scope version installed
- [ ] Capture exact steps, traffic, screenshots, device + OS version
- [ ] Map the issue to a CWE (Kuzushi finding includes a CWE if
      extractable; cross-reference)
- [ ] Note any pre-conditions (need to be logged in, need a particular
      device flag, etc.)
- [ ] Submit through HackerOne, not directly to the vendor

## Documenting findings

When opening a HackerOne report based on a Kuzushi finding:

- Quote the Kuzushi rule_id (e.g. `android-apk:exported-activity-no-permission`)
  for repeatability.
- Include the manifest snippet (apktool decoded) showing the offending
  attribute, not just the message — graders verify on the actual file.
- For deeplink chains, include both the manifest filter and the Java
  source that handles the intent (from `android-decompiled/jadx/sources`).
- Attach the `taint-sources.json` written by `android-apk:manifest-scan`
  if your report is about an exported entry point — it shows the full set
  of similar surfaces and helps triagers prioritize.

## Stop conditions

Hit **stop** and re-read the program scope if you find yourself:

- Considering testing against any account except your own
- About to scan a different package than the one explicitly in scope
- Tempted to chain a static finding into a live exploit on production
  infrastructure without explicit authorization
- About to test a server-side endpoint that wasn't listed in scope, just
  because the APK calls it
