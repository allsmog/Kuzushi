use crate::InterruptionView;

pub(super) struct InterruptionContent {
    pub(super) title: &'static str,
    pub(super) headline: &'static str,
    pub(super) summary: &'static str,
    pub(super) sections: Vec<InterruptionSection>,
    pub(super) commands: Vec<&'static str>,
}

pub(super) struct InterruptionSection {
    pub(super) title: &'static str,
    pub(super) rows: Vec<&'static str>,
}

pub(super) fn interruption_content(view: InterruptionView) -> InterruptionContent {
    match view {
        InterruptionView::BudgetHardStop => budget_hard_stop_content(),
        InterruptionView::BudgetStop => budget_stop_content(),
        InterruptionView::NoBinary => no_binary_content(),
        InterruptionView::NoModel => no_model_content(),
        InterruptionView::NoPlugin => no_plugin_content(),
        InterruptionView::NetworkDown => network_down_content(),
        InterruptionView::RateLimited => rate_limited_content(),
    }
}

fn budget_hard_stop_content() -> InterruptionContent {
    content(
        "BUDGET CAP",
        "Budget cap hit; run is paused with checkpointed state.",
        "Kuzushi keeps the partial findings and waits for an explicit cap decision.",
        vec![
            section(
                "STATE AT PAUSE",
                &[
                    "checkpoint written under .kuzushi/v3/runs/<runId>/",
                    "partial findings remain available for triage and export",
                    "raising the cap is an audited operator action",
                ],
            ),
            section(
                "CHOICES",
                &[
                    "resume with a raised cap when the extra spend is intentional",
                    "finalize best-effort output from the current frame",
                    "abandon the work-in-progress while keeping durable findings",
                ],
            ),
        ],
        &["cost", "resume <runId>", "story", "activity"],
    )
}

fn budget_stop_content() -> InterruptionContent {
    content(
        "BUDGET HARD STOP",
        "Run budget reached; active work is halted before more model calls.",
        "The stop is deliberate. No actor, provider, or model is swapped automatically.",
        vec![
            section(
                "STATE PRESERVED",
                &[
                    "run summary, trace, input JSON, and result JSON stay on disk",
                    "transcript frames are flushed before the halt is surfaced",
                    "sandbox or worker cleanup follows the normal cancellation path",
                ],
            ),
            section(
                "WHAT BURNED THE BUDGET",
                &[
                    "inspect cost to see session totals and tool-level spend",
                    "open story or activity to find the last completed frame",
                ],
            ),
        ],
        &["cost", "activity", "story", "config"],
    )
}

fn no_binary_content() -> InterruptionContent {
    content(
        "NO BINARY",
        "Tool refused because a required scanner binary is unavailable.",
        "Kuzushi does not silently switch to another scanner when a binary is missing.",
        vec![
            section(
                "PROBE",
                &[
                    "check PATH and the tool descriptor options first",
                    "doctor reports scanner preflight failures in one place",
                    "per-run binary overrides must flow through declared tool options",
                ],
            ),
            section(
                "FIX",
                &[
                    "install the missing binary or point the tool option at it",
                    "block the task explicitly if the scanner is out of scope",
                ],
            ),
        ],
        &[
            "doctor",
            "tools codeql",
            "options codeql:scan",
            "task block codeql",
        ],
    )
}

fn no_model_content() -> InterruptionContent {
    content(
        "NO MODEL CONFIGURED",
        "Agentic tool refused because no compatible model is configured.",
        "No-silent-fallback policy is active; Kuzushi will not choose a replacement model.",
        vec![
            section(
                "WHY",
                &[
                    "runtime-backed tools need an operator-selected model",
                    "provider credentials must match the selected model/runtime",
                    "target-local model files are rejected by policy",
                ],
            ),
            section(
                "FIX",
                &[
                    "pick a model through model or config before dispatch",
                    "authenticate the provider with auth when credentials are missing",
                ],
            ),
        ],
        &["model <n>", "auth", "config", "doctor"],
    )
}

fn no_plugin_content() -> InterruptionContent {
    content(
        "NO PLUGIN",
        "Tool refused because an optional plugin gate is not configured.",
        "Plugin-backed modules need operator-owned paths or installed bundles before dispatch.",
        vec![
            section(
                "REASON",
                &[
                    "the module depends on an operator-supplied plugin or skills directory",
                    "missing plugin state is blocking, not an opportunity to emulate the tool",
                ],
            ),
            section(
                "FIX",
                &[
                    "install or configure the plugin at the documented boundary",
                    "run doctor to enumerate every plugin gate before retrying",
                ],
            ),
        ],
        &["doctor", "modules", "config", "tools tob"],
    )
}

fn network_down_content() -> InterruptionContent {
    content(
        "NETWORK DOWN",
        "Cloud-bound model calls are paused after a network failure.",
        "Same-model transport retries may continue; model/provider fallback still needs consent.",
        vec![
            section(
                "REACHABILITY",
                &[
                    "the shell records the failure source and keeps existing run state durable",
                    "local-only resume is available only after the operator chooses it",
                    "proxy and CA changes belong in config, not ad hoc target state",
                ],
            ),
            section(
                "YOUR OPTIONS",
                &[
                    "wait for the configured retry path to recover",
                    "open doctor for reachability and credential checks",
                    "edit proxy or CA configuration, then retry the paused run",
                ],
            ),
        ],
        &["doctor", "config", "activity", "resume <runId>"],
    )
}

fn rate_limited_content() -> InterruptionContent {
    content(
        "RATE LIMITED",
        "Provider returned a throttle response; affected model work is paused.",
        "Retry keeps the same model object. Switching models is an explicit operator action.",
        vec![
            section(
                "SCOPE",
                &[
                    "affected runs should be checkpointed before backoff",
                    "local verify or scan work can continue if it does not need the throttled model",
                ],
            ),
            section(
                "AUTOMATIC RESPONSE",
                &[
                    "backoff is recorded in the transcript and activity view",
                    "budget state is unchanged by a temporary throttle",
                ],
            ),
        ],
        &["activity", "resume <runId>", "cost", "model <n>"],
    )
}

fn content(
    title: &'static str,
    headline: &'static str,
    summary: &'static str,
    sections: Vec<InterruptionSection>,
    commands: &[&'static str],
) -> InterruptionContent {
    InterruptionContent {
        title,
        headline,
        summary,
        sections,
        commands: commands.to_vec(),
    }
}

fn section(title: &'static str, rows: &[&'static str]) -> InterruptionSection {
    InterruptionSection {
        title,
        rows: rows.to_vec(),
    }
}
