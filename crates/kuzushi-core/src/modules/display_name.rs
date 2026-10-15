//! Operator-facing display names for tool registry keys.
//!
//! Registry keys (`campaign:plan`, `agentic-sast:scan`) are dispatcher
//! vocabulary: namespace-colon-noun, no verb, no object. Every surface an
//! operator reads (result cards, receipts, activity rows) must render the
//! curated label instead; keys stay available one level down (replay,
//! logs, `--json`) where grep-ability matters.

/// Curated labels. Sentence-case verb phrases: what the tool does to what.
/// The ratchet test below fails when a registered tool is missing here, so
/// a new tool cannot ship without an operator-readable name.
const CURATED_TOOL_LABELS: &[(&str, &str)] = &[
    ("agentic-sast:scan", "Agentic SAST hunt"),
    ("android-apk:check-env", "Check Android tooling environment"),
    ("android-apk:code-scan", "Scan APK decompiled code"),
    (
        "android-apk:fileprovider-scan",
        "Scan APK FileProvider configs",
    ),
    ("android-apk:hybrid-detect", "Detect APK hybrid frameworks"),
    ("android-apk:manifest-scan", "Scan Android manifest"),
    ("android-apk:native-libs", "Inspect APK native libraries"),
    (
        "android-apk:network-security-config",
        "Check APK network security config",
    ),
    ("android-apk:prepare", "Unpack and decompile APK"),
    ("android-apk:sast-handoff", "Hand APK sources to SAST"),
    ("android-apk:scan", "Scan Android APK"),
    ("bounty:import-burp", "Import Burp capture"),
    ("bounty:import-har", "Import HAR capture"),
    ("campaign:coverage", "Show campaign coverage"),
    ("campaign:plan", "Plan campaign jobs"),
    (
        "campaign:approve-allowance",
        "Approve investigation allowance",
    ),
    ("campaign:study", "Draft bounded scan study"),
    ("campaign:context-study", "Draft context generation study"),
    ("campaign:context-map", "Review generated Map"),
    ("campaign:allowance", "Show investigation allowance"),
    ("campaign:status", "Show campaign status"),
    ("cargo-audit:scan", "Audit Rust dependencies"),
    ("carlini-threat-hunt:run", "Run adversarial threat hunt"),
    ("catalog:modules", "List modules"),
    ("catalog:tools", "List tools"),
    ("chrome-rce:review-trigger", "Review Chrome RCE trigger"),
    ("chrome-rce:scan", "Scan for Chrome RCE patterns"),
    (
        "classifier-gate:score",
        "Score finding with classifier gate",
    ),
    ("codeql:create-db", "Create CodeQL database"),
    ("codeql:scan", "Run CodeQL scan"),
    ("config:show", "Show configuration"),
    ("context-lite:index", "Build lightweight context index"),
    ("context:build", "Build project context"),
    ("coverage:baselines", "List scan baselines"),
    ("coverage:recommend", "Recommend scan coverage"),
    ("coverage:sweep", "Sweep coverage baselines"),
    ("cpg:build", "Build code property graph"),
    ("fuzz:run", "Run fuzzing campaign (AFE)"),
    ("fuzz:author", "Author fuzz harnesses"),
    ("fuzz:import", "Import fuzzing findings"),
    ("fuzz:prove", "Prove finding impact"),
    ("fuzz:sweep", "Sweep corpus under MSan/TSan"),
    ("fuzz:differential", "Differential corpus replay"),
    ("fuzz:status", "Fuzzing workspace status"),
    ("deep-audit:run", "Run deep audit"),
    ("dep-hygiene:check", "Check dependency hygiene"),
    ("engagement:aim", "Save legacy harness metadata"),
    ("entry-points:extract", "Extract entry points"),
    ("exploit-chain:scan", "Scan for exploit chains"),
    ("findings:chains", "Show finding chains"),
    ("findings:ground", "Re-ground finding citations"),
    (
        "fleet:diff-findings",
        "Diff fleet findings across revisions",
    ),
    ("fleet:findings", "Query fleet findings"),
    ("fleet:ingest", "Rebuild fleet corpus"),
    ("fleet:register", "Register fleet target"),
    ("fleet:status", "Show fleet status"),
    ("findings:dismiss", "Dismiss a finding"),
    ("findings:review-source", "Review current source"),
    ("findings:list", "List findings"),
    ("full-mode:hunt", "Full-depth hunt"),
    ("govulncheck:scan", "Scan Go dependencies"),
    ("iac-scan:scan", "Scan infrastructure-as-code"),
    ("license-scan:scan", "Scan dependency licenses"),
    ("module-recommender:recommend", "Recommend modules"),
    (
        "ndiff:extract-fix-pattern",
        "Draft advisory pattern from supplied diff",
    ),
    ("ndiff:fetch-cve", "Fetch CVE advisory"),
    ("ndiff:hunt-variants", "Search advisory-guided observations"),
    (
        "offense-review:threat-hunt",
        "Discover actor-guided observations",
    ),
    ("offense:chain", "Build offensive chain"),
    ("pack:lint", "Lint scanner pack"),
    ("pack:scopes", "Review scan scopes"),
    ("pack:suggest-shards", "Suggest campaign shards"),
    ("pack:suggest-scopes", "Suggest scan scopes with AI"),
    ("patch:finding", "Draft patch for finding"),
    ("patch:reverify", "Re-verify patched finding"),
    (
        "pipeline:approval-before-verification",
        "Gate verification on approval",
    ),
    ("pipeline:taint-cwe-select", "Select taint CWE targets"),
    ("pipeline:task-selector", "Select pipeline tasks"),
    ("prompt-armor:analyze", "Analyze prompt-injection exposure"),
    ("prompt-armor:attack", "Attack prompts for injection"),
    ("prompt-armor:config", "Show prompt-armor config"),
    ("prompt-armor:diff", "Diff prompt-armor results"),
    ("prompt-armor:report", "Report prompt-armor results"),
    ("prompt-armor:scan", "Scan prompts for injection"),
    ("pwn:auto-solve", "Auto-solve pwn target"),
    ("pwn:calibrate-local", "Calibrate local pwn environment"),
    ("pwn:exploit-run", "Run exploit candidate"),
    ("pwn:heap-uaf-scan", "Scan binary for heap use-after-free"),
    ("pwn:menu-probe", "Probe binary menu interface"),
    ("pwn:profile-binary", "Profile target binary"),
    ("pwn:reverse", "Reverse-engineer binary"),
    ("pwn:run-candidates", "Run exploit candidates"),
    ("pwn:state", "Show pwn session state"),
    ("randori:pasta", "Run PASTA threat analysis"),
    ("randori:threat-model", "Build randori threat model"),
    ("recon:http-fingerprint", "Fingerprint HTTP services"),
    ("recon:import", "Import recon export"),
    ("recon:nmap", "Run nmap scan"),
    ("recon:subdomain", "Enumerate subdomains"),
    ("report:build", "Build report"),
    ("report:sarif", "Export SARIF report"),
    ("router:show", "Show tool routing"),
    ("sast:scan", "Run SAST scan"),
    ("sbom-scan:scan", "Scan software bill of materials"),
    ("secret-scan:scan", "Scan for secrets"),
    ("semgrep:scan", "Run Semgrep scan"),
    ("shinsa:frameworks", "List compliance frameworks"),
    ("shinsa:nist-quick-check", "Quick NIST compliance check"),
    ("shinsa:nist-scan", "Run NIST compliance scan"),
    ("shinsa:quick-check", "Quick compliance check"),
    ("shinsa:scan", "Run compliance scan"),
    ("suppress:add", "Add suppression rule"),
    ("suppress:list", "List suppression rules"),
    ("suppress:remove", "Remove suppression rule"),
    (
        "systems-hunt:deep-semantic-cwe-select",
        "Select CWEs for deep semantic hunt",
    ),
    ("systems-hunt:deep-semantic-hunt", "Deep semantic hunt"),
    (
        "systems-hunt:systems-context-gatherer",
        "Gather systems context",
    ),
    ("systems-hunt:systems-hunt", "Hunt systems-level bugs"),
    (
        "systems-hunt:systems-invariant-extract",
        "Extract system invariants",
    ),
    (
        "systems-hunt:systems-trigger-synth",
        "Synthesize trigger inputs",
    ),
    ("taint-iris-next:catalog", "Catalog taint sources and sinks"),
    (
        "taint-iris-next:codeql-db",
        "Prepare CodeQL database for taint hunt",
    ),
    ("taint-iris-next:dataflow-plan", "Plan dataflow queries"),
    (
        "taint-iris-next:finding-review",
        "Discover taint candidates",
    ),
    ("taint-iris-next:hunt", "Hunt taint flows (IRIS next)"),
    ("taint-iris-next:import-sinks", "Import sink definitions"),
    (
        "taint-iris-next:source-sink-trace",
        "Trace source-to-sink flow",
    ),
    ("taint-iris:hunt", "Hunt taint flows (IRIS)"),
    ("threat-intel:apply", "Catalog dispatch"),
    ("threat-intel:discover", "Discover threat intel"),
    ("threat-intel:harvest", "Draft advisory catalog"),
    ("threat-intel:list", "List threat intel"),
    (
        "threat-intel:research",
        "Look up advisories and draft catalog",
    ),
    ("threat-leads:build", "Build threat leads"),
    ("threat-leads:read", "Read threat leads"),
    ("threat-model:build", "Build threat model"),
    (
        "threat-model:regenerate",
        "Regenerate selected context text",
    ),
    ("threat-model:models", "List threat models"),
    ("threat-model:activate", "Activate threat model"),
    ("threat-model:revisions", "List threat-model revisions"),
    ("threat-model:diff", "Diff threat-model revisions"),
    ("threat-model:restore", "Restore threat-model revision"),
    ("threat-model:adopt", "Adopt threat-model mirror edits"),
    ("threat-model:import", "Import threat model"),
    ("threat-model:revise", "Edit an exact context copy"),
    (
        "threat-model:methodologies",
        "List threat-model methodologies",
    ),
    ("threat-model:read", "Read threat model"),
    ("threat-model:verify", "Verify threat model"),
    ("tob:audit", "Run Trail of Bits audit checklist"),
    ("tob:skills", "List Trail of Bits skills"),
    ("trace:expand", "Draft data-flow claims"),
    ("triage:chain-hunt", "Propose finding relationships"),
    ("triage:dedupe", "Dedupe findings corpus"),
    ("triage:run", "Triage findings"),
    ("uaf-hunt:hunt", "Hunt use-after-free bugs"),
    ("variant:hunt", "Search related observations"),
    ("variant:lift-pattern", "Draft source pattern"),
    ("vendor-assessment:assess", "Assess vendor"),
    ("vendor-assessment:attach", "Attach vendor evidence"),
    (
        "vendor-assessment:prompts",
        "Show vendor assessment prompts",
    ),
    ("vendor-assessment:scope", "Scope vendor assessment"),
    ("verify:exploit", "Verify exploit"),
    ("verify:finding", "Verify finding"),
    ("vuln-scout:audit", "Run vulnerability scout audit"),
    ("wasm-plugin:analyze", "Analyze WASM plugin"),
    ("worklist:rank", "Rank risk worklist"),
    ("workspace:export-findings", "Export findings"),
    ("workspace:import-findings", "Import findings"),
    ("workspace:status", "Show workspace status"),
    ("x-ray:read", "Read x-ray results"),
    ("x-ray:run", "Run x-ray analysis"),
    ("x-ray:x-ray", "X-ray the repository"),
];

/// Operator label for a tool key: curated when known, humanized otherwise
/// (dynamic KWP modules register keys we cannot enumerate at build time).
pub fn tool_display_name(key: &str) -> String {
    if let Some((_, label)) = CURATED_TOOL_LABELS
        .iter()
        .find(|(curated, _)| *curated == key)
    {
        return (*label).to_string();
    }
    humanize_tool_key(key)
}

/// `namespace:verb-noun` → "Namespace verb noun". Good enough that a
/// dynamic module without a curated entry still reads as words.
fn humanize_tool_key(key: &str) -> String {
    let words = key
        .split([':', '-', '_'])
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>()
        .join(" ");
    let mut chars = words.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => key.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn humanizer_turns_keys_into_words() {
        assert_eq!(humanize_tool_key("campaign:plan"), "Campaign plan");
        assert_eq!(humanize_tool_key("agentic-sast:scan"), "Agentic sast scan");
    }

    /// Every registered tool must have a curated operator label. The
    /// humanizer is only a fallback for dynamic modules; builtin tools get
    /// deliberate names so receipts read as sentences.
    #[test]
    fn every_registered_tool_has_a_curated_display_name() {
        let curated: std::collections::BTreeSet<&str> =
            CURATED_TOOL_LABELS.iter().map(|(key, _)| *key).collect();
        let mut missing = Vec::new();
        let mut seen = std::collections::BTreeSet::new();
        for module in crate::modules::ModuleRegistry::with_v2_builtins().all_modules() {
            for tool in module.tools() {
                seen.insert(tool.name.clone());
                if !curated.contains(tool.name.as_str()) {
                    missing.push(tool.name.clone());
                }
            }
        }
        missing.sort();
        missing.dedup();
        assert!(
            missing.is_empty(),
            "registered tools without a curated display name (add to \
             CURATED_TOOL_LABELS with a sentence-case verb phrase):\n{}",
            missing.join("\n")
        );
        let stale: Vec<&str> = CURATED_TOOL_LABELS
            .iter()
            .map(|(key, _)| *key)
            .filter(|key| !seen.contains(*key))
            .collect();
        assert!(stale.is_empty(), "stale CURATED_TOOL_LABELS: {stale:?}");
    }

    /// Labels must be operator language: non-empty, no registry-key colon,
    /// sentence case.
    #[test]
    fn curated_labels_read_as_sentences() {
        for (key, label) in CURATED_TOOL_LABELS {
            assert!(!label.is_empty(), "{key}: empty label");
            assert!(
                !label.contains(':'),
                "{key}: label {label:?} leaks registry-key punctuation"
            );
            assert!(
                label.chars().next().is_some_and(char::is_uppercase),
                "{key}: label {label:?} is not sentence case"
            );
            assert_ne!(label, key, "{key}: label must differ from the registry key");
        }
    }
}
