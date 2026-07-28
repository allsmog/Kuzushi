use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub(crate) const MAX_EMPIRICAL_CASE_BYTES: usize = 4 * 1024;
pub(crate) const MAX_EMPIRICAL_CASES: usize = 5;
pub(crate) const MAX_EMPIRICAL_TOTAL_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum EmpiricalInputCaseKind {
    OriginalAttack,
    BenignControl,
    Variant,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum EmpiricalCaseExpectation {
    Exploited,
    CleanExit,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct EmpiricalCaseOracle {
    pub(crate) vulnerable: EmpiricalCaseExpectation,
    pub(crate) patched: EmpiricalCaseExpectation,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct EmpiricalInputCase {
    pub(crate) id: String,
    pub(crate) kind: EmpiricalInputCaseKind,
    pub(crate) payload: Vec<u8>,
    pub(crate) oracle: EmpiricalCaseOracle,
}

pub(super) fn calibrated_empirical_cases(original: &[u8]) -> Result<Vec<EmpiricalInputCase>> {
    ensure_original_payload(original)?;
    let attack_oracle = attack_oracle();
    let mut cases = vec![
        attack_case(
            "original",
            EmpiricalInputCaseKind::OriginalAttack,
            original,
            &attack_oracle,
        ),
        control_case(original.len()),
    ];
    for (index, offset) in [0, original.len() / 2, original.len() - 1]
        .into_iter()
        .enumerate()
    {
        cases.push(variant_case(original, index, offset, &attack_oracle));
    }
    validate_empirical_cases(&cases)?;
    Ok(cases)
}

fn ensure_original_payload(original: &[u8]) -> Result<()> {
    anyhow::ensure!(!original.is_empty(), "empirical attack payload is empty");
    anyhow::ensure!(
        original.len() <= MAX_EMPIRICAL_CASE_BYTES,
        "empirical attack payload exceeds its case bound"
    );
    Ok(())
}

fn attack_oracle() -> EmpiricalCaseOracle {
    EmpiricalCaseOracle {
        vulnerable: EmpiricalCaseExpectation::Exploited,
        patched: EmpiricalCaseExpectation::CleanExit,
    }
}

fn attack_case(
    id: &str,
    kind: EmpiricalInputCaseKind,
    payload: &[u8],
    oracle: &EmpiricalCaseOracle,
) -> EmpiricalInputCase {
    EmpiricalInputCase {
        id: id.to_string(),
        kind,
        payload: payload.to_vec(),
        oracle: oracle.clone(),
    }
}

fn control_case(payload_len: usize) -> EmpiricalInputCase {
    EmpiricalInputCase {
        id: "control".to_string(),
        kind: EmpiricalInputCaseKind::BenignControl,
        payload: vec![0; payload_len],
        oracle: EmpiricalCaseOracle {
            vulnerable: EmpiricalCaseExpectation::CleanExit,
            patched: EmpiricalCaseExpectation::CleanExit,
        },
    }
}

fn variant_case(
    original: &[u8],
    index: usize,
    offset: usize,
    oracle: &EmpiricalCaseOracle,
) -> EmpiricalInputCase {
    let mut payload = original.to_vec();
    payload[offset] ^= 1_u8 << index;
    attack_case(
        &format!("variant-{}", index + 1),
        EmpiricalInputCaseKind::Variant,
        &payload,
        oracle,
    )
}

pub(super) fn validate_empirical_cases(cases: &[EmpiricalInputCase]) -> Result<()> {
    anyhow::ensure!(
        (3..=MAX_EMPIRICAL_CASES).contains(&cases.len()),
        "empirical reproducer case count is out of bounds"
    );
    ensure_case_roles(cases)?;
    let mut total = 0_usize;
    let mut ids = BTreeSet::new();
    for case in cases {
        total = validate_case(case, &mut ids, total)?;
    }
    anyhow::ensure!(
        total <= MAX_EMPIRICAL_TOTAL_BYTES,
        "empirical case payloads exceed the total bound"
    );
    Ok(())
}

fn ensure_case_roles(cases: &[EmpiricalInputCase]) -> Result<()> {
    let originals = count_kind(cases, EmpiricalInputCaseKind::OriginalAttack);
    let controls = count_kind(cases, EmpiricalInputCaseKind::BenignControl);
    let variants = count_kind(cases, EmpiricalInputCaseKind::Variant);
    anyhow::ensure!(
        originals == 1 && controls == 1 && (1..=3).contains(&variants),
        "empirical reproducer does not contain one original, one control, and one to three variants"
    );
    Ok(())
}

fn count_kind(cases: &[EmpiricalInputCase], kind: EmpiricalInputCaseKind) -> usize {
    cases.iter().filter(|case| case.kind == kind).count()
}

fn validate_case<'a>(
    case: &'a EmpiricalInputCase,
    ids: &mut BTreeSet<&'a str>,
    total: usize,
) -> Result<usize> {
    anyhow::ensure!(
        !case.id.trim().is_empty() && case.id.len() <= 32,
        "invalid empirical case id"
    );
    anyhow::ensure!(ids.insert(case.id.as_str()), "duplicate empirical case id");
    anyhow::ensure!(
        !case.payload.is_empty() && case.payload.len() <= MAX_EMPIRICAL_CASE_BYTES,
        "empirical case payload is out of bounds"
    );
    let total = total
        .checked_add(case.payload.len())
        .context("empirical case size overflow")?;
    validate_case_oracle(case)?;
    Ok(total)
}

fn validate_case_oracle(case: &EmpiricalInputCase) -> Result<()> {
    let expected = match case.kind {
        EmpiricalInputCaseKind::BenignControl => EmpiricalCaseExpectation::CleanExit,
        EmpiricalInputCaseKind::OriginalAttack | EmpiricalInputCaseKind::Variant => {
            EmpiricalCaseExpectation::Exploited
        }
    };
    anyhow::ensure!(
        case.oracle.vulnerable == expected
            && case.oracle.patched == EmpiricalCaseExpectation::CleanExit,
        "empirical case oracle does not match its calibrated role"
    );
    Ok(())
}
