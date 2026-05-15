use super::proof_ladder::ProofLadderKind;

#[derive(Clone, Copy)]
pub(in crate::findings) struct ProofLadderText {
    pub(in crate::findings) stage: &'static str,
    pub(in crate::findings) label: &'static str,
    pub(in crate::findings) reason: &'static str,
    pub(in crate::findings) next_step: &'static str,
}

const SUSPECTED_PROOF_LADDER: ProofLadderText = ProofLadderText {
    stage: "suspected",
    label: "suspected - needs source grounding or verification",
    reason: "scanner signal has not been promoted with inspectable proof",
    next_step: "open the finding, collect code evidence, then verify if warranted",
};

const PROOF_LADDER_TEXTS: &[(ProofLadderKind, ProofLadderText)] = &[
    (
        ProofLadderKind::Patched,
        ProofLadderText {
            stage: "patched",
            label: "patched - remediation evidence recorded",
            reason: "latest patch result is sound or verified",
            next_step: "review the PR comment and keep post-patch verification attached",
        },
    ),
    (
        ProofLadderKind::RuntimeVerified,
        ProofLadderText {
            stage: "verified",
            label: "verified - empirical runtime evidence recorded",
            reason: "runtime verification reproduced exploitability",
            next_step: "patch the finding and re-run verification",
        },
    ),
    (
        ProofLadderKind::PathLinked,
        ProofLadderText {
            stage: "path_linked",
            label: "path-linked - static source/sink evidence recorded",
            reason: "static evidence links a source to a sink or sanitizer assessment",
            next_step: "run verify:finding or attach runtime evidence",
        },
    ),
    (
        ProofLadderKind::SourceGrounded,
        ProofLadderText {
            stage: "source_grounded",
            label: "source-grounded - code evidence recorded",
            reason: "the finding cites source evidence but not a verified path",
            next_step: "collect source/sink path evidence or verify runtime behavior",
        },
    ),
    (
        ProofLadderKind::Rejected,
        ProofLadderText {
            stage: "rejected",
            label: "rejected - evidence does not support exploitability",
            reason: "triage or static proof rejected the issue",
            next_step: "suppress with expiry if the operator accepts the evidence",
        },
    ),
    (ProofLadderKind::Suspected, SUSPECTED_PROOF_LADDER),
];

pub(in crate::findings) fn proof_ladder_text(kind: ProofLadderKind) -> ProofLadderText {
    PROOF_LADDER_TEXTS
        .iter()
        .find_map(|(candidate, text)| (*candidate == kind).then_some(*text))
        .unwrap_or(SUSPECTED_PROOF_LADDER)
}
