use super::*;

pub(super) fn options() -> Vec<OptionSpec> {
    let defaults = crate::findings::DedupeLedgerLimits::default();
    [
        ("maxLedgerObservations", "max_ledger_observations", defaults.max_observations as i64, 100_000,
         "Maximum recorded observations inspected before dedupe candidate selection. Excess history refuses before inference; it is never silently truncated."),
        ("maxLedgerBytes", "max_ledger_bytes", defaults.max_bytes as i64, 134_217_728,
         "Maximum UTF-8 bytes inspected across raw observations and their projected finding/source JSON before inference. This is not a bound on all SQLite memory."),
        ("maxLedgerReadMs", "max_ledger_read_ms", defaults.read_ms as i64, 60_000,
         "Cooperative SQL read deadline in milliseconds. Lock waits and bounded decoding can finish later; cancellation and read limits still apply."),
        ("maxJudgePromptBytes", "max_judge_prompt_bytes", 131_072, 524_288,
         "Maximum UTF-8 bytes of system and user text per judge or confirmation prompt. Excess metadata refuses before inference; an oversized confirmation is dropped without a request. This excludes transport framing and output tokens."),
        ("maxConfirmationBytes", "max_confirmation_bytes", 262_144, 8_388_608,
         "Aggregate source-byte allowance for optional confirmations. Each literal path is read once through a contained regular-file handle. Oversized or unavailable files drop their group without confirmation; failed reads conservatively retain their reservation."),
    ].into_iter().map(|(name, alias, default, maximum, description)| {
        opt(name, OptionType::Int, description).aliases(&[alias])
            .default(json!(default)).integer_range(1, maximum).advanced()
    }).collect()
}
