//! Durable, round-trippable disclosure of the verification stage ladder.
//!
//! `verify:finding` can run up to three model tiers: a cheap plausibility gate,
//! the full-strength panel, and — only on an even panel split — a different
//! operator-named tie-break model. That structure is invisible in the bare
//! exploitable/not-exploitable verdict, so we fold it into one compact note
//! line (`stages: …`) stored in the finding's verification notes. The line is
//! human-readable and parses back losslessly for the Prove card.

/// Stable sentinel prefix. Any note that starts with it is a stage disclosure;
/// anything else parses to `None`.
pub const STAGE_NOTE_SENTINEL: &str = "stages: ";

const STAGE_SPLIT_MARKER: &str = "split";

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VerificationStageDisclosure {
    /// Cheap plausibility-gate model, when a gate ran.
    pub gate: Option<String>,
    /// Number of panel passes combined by consensus (0 when single-tier).
    pub panel_passes: u32,
    /// The panel vote was an even split (the one verdict a tie-break revisits).
    pub split: bool,
    /// Different tie-break model that resolved the split, when one ran.
    pub escalation: Option<String>,
    /// Short token when a requested escalation was refused (`same-model` /
    /// `invalid-spec`); the split verdict then stood unchanged.
    pub refused: Option<String>,
}

/// Render the disclosure to one line under 90 columns. Model specs carry no
/// spaces, so a space-separated grammar round-trips cleanly.
pub fn format_stage_note(disclosure: &VerificationStageDisclosure) -> String {
    let mut parts = vec![format!("passes={}", disclosure.panel_passes)];
    push_stage_parts(&mut parts, disclosure);
    format!("{STAGE_NOTE_SENTINEL}{}", parts.join(" "))
}

fn push_stage_parts(parts: &mut Vec<String>, disclosure: &VerificationStageDisclosure) {
    if disclosure.split {
        parts.push(STAGE_SPLIT_MARKER.to_string());
    }
    push_opt(parts, "gate", &disclosure.gate);
    push_opt(parts, "escalated", &disclosure.escalation);
    push_opt(parts, "refused", &disclosure.refused);
}

fn push_opt(parts: &mut Vec<String>, key: &str, value: &Option<String>) {
    if let Some(value) = value {
        parts.push(format!("{key}={value}"));
    }
}

/// Parse a stage note back into its disclosure. Returns `None` for any line
/// that is not a stage note (no sentinel) or is malformed.
pub fn parse_stage_note(line: &str) -> Option<VerificationStageDisclosure> {
    let rest = line.trim().strip_prefix(STAGE_NOTE_SENTINEL)?;
    let mut disclosure = VerificationStageDisclosure::default();
    let mut saw_passes = false;
    for token in rest.split(' ') {
        if !apply_stage_token(&mut disclosure, token, &mut saw_passes) {
            return None;
        }
    }
    saw_passes.then_some(disclosure)
}

fn apply_stage_token(
    disclosure: &mut VerificationStageDisclosure,
    token: &str,
    saw_passes: &mut bool,
) -> bool {
    if let Some(raw) = token.strip_prefix("passes=") {
        return match raw.parse() {
            Ok(passes) => {
                disclosure.panel_passes = passes;
                *saw_passes = true;
                true
            }
            Err(_) => false,
        };
    }
    apply_stage_marker(disclosure, token)
}

fn apply_stage_marker(disclosure: &mut VerificationStageDisclosure, token: &str) -> bool {
    if token == STAGE_SPLIT_MARKER {
        disclosure.split = true;
        return true;
    }
    assign_stage_model(disclosure, token)
}

fn assign_stage_model(disclosure: &mut VerificationStageDisclosure, token: &str) -> bool {
    assign_field(&mut disclosure.gate, token, "gate=")
        || assign_field(&mut disclosure.escalation, token, "escalated=")
        || assign_field(&mut disclosure.refused, token, "refused=")
}

fn assign_field(slot: &mut Option<String>, token: &str, prefix: &str) -> bool {
    match token.strip_prefix(prefix) {
        Some(value) => {
            *slot = Some(value.to_string());
            true
        }
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(disclosure: VerificationStageDisclosure) {
        let note = format_stage_note(&disclosure);
        assert!(note.len() < 90, "note too long: {note} ({} cols)", note.len());
        assert_eq!(parse_stage_note(&note), Some(disclosure));
    }

    #[test]
    fn round_trips_a_gated_escalated_split() {
        round_trip(VerificationStageDisclosure {
            gate: Some("anthropic:cheap".to_string()),
            panel_passes: 2,
            split: true,
            escalation: Some("openai:bigger".to_string()),
            refused: None,
        });
    }

    #[test]
    fn round_trips_a_refused_split() {
        round_trip(VerificationStageDisclosure {
            gate: None,
            panel_passes: 2,
            split: true,
            escalation: None,
            refused: Some("same-model".to_string()),
        });
    }

    #[test]
    fn round_trips_a_plain_multipass_panel() {
        round_trip(VerificationStageDisclosure {
            gate: None,
            panel_passes: 3,
            split: false,
            escalation: None,
            refused: None,
        });
    }

    #[test]
    fn unrelated_text_is_not_a_stage_note() {
        assert_eq!(parse_stage_note("static model exploitability review"), None);
        assert_eq!(parse_stage_note("stages: gate=x"), None); // no passes= token
        assert_eq!(parse_stage_note("stages: passes=two"), None);
    }
}
