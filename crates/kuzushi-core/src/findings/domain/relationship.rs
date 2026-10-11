//! Finding relationships group evidence without changing identities or verdicts.
use super::*;

pub const FINDING_RELATIONSHIP_SUBJECT: &str = "finding-relationship-v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingRelationshipKind {
    Duplicate,
    RelatedVariant,
    Uncertain,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingRelationshipState {
    Proposed,
    Accepted,
    Rejected,
    Removed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FindingRelationshipEndpoint {
    pub stable_key: String,
    pub fingerprint: String,
    pub finding_id: i64,
    pub run_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FindingRelationship {
    pub schema_version: u32,
    pub id: String,
    pub revision: u64,
    pub kind: FindingRelationshipKind,
    pub state: FindingRelationshipState,
    pub from: FindingRelationshipEndpoint,
    pub to: FindingRelationshipEndpoint,
    pub note: String,
    pub author: String,
    pub confidence: Option<f64>,
}

impl FindingRelationship {
    pub fn new(
        from: FindingRelationshipEndpoint,
        to: FindingRelationshipEndpoint,
        kind: FindingRelationshipKind,
        note: String,
        author: String,
    ) -> Result<Self> {
        let id = relationship_id(&from, &to, kind)?;
        let relationship = Self {
            schema_version: 1,
            id,
            revision: 1,
            kind,
            state: FindingRelationshipState::Proposed,
            from,
            to,
            note,
            author,
            confidence: None,
        };
        relationship.validate()?;
        Ok(relationship)
    }

    pub fn validate(&self) -> Result<()> {
        anyhow::ensure!(
            self.schema_version == 1 && self.revision > 0,
            "unsupported relationship revision"
        );
        anyhow::ensure!(
            self.from.stable_key != self.to.stable_key,
            "relationship requires two distinct finding identities"
        );
        validate_endpoint(&self.from)?;
        validate_endpoint(&self.to)?;
        anyhow::ensure!(
            self.id == relationship_id(&self.from, &self.to, self.kind)?,
            "relationship identity or recorded source binding changed"
        );
        validate_note(&self.note)?;
        validate_authority(self)?;
        validate_confidence(self.confidence)
    }

    pub fn review(
        &self,
        state: FindingRelationshipState,
        note: String,
        expected_revision: u64,
    ) -> Result<Self> {
        anyhow::ensure!(
            self.revision == expected_revision,
            "relationship changed; refresh before deciding"
        );
        anyhow::ensure!(
            state != FindingRelationshipState::Proposed,
            "review must accept, reject or remove the relationship"
        );
        let mut reviewed = self.clone();
        reviewed.revision = self
            .revision
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("relationship revision exhausted"))?;
        reviewed.state = state;
        reviewed.note = note;
        reviewed.author = "human".into();
        reviewed.validate()?;
        Ok(reviewed)
    }
}

fn relationship_id(
    from: &FindingRelationshipEndpoint,
    to: &FindingRelationshipEndpoint,
    kind: FindingRelationshipKind,
) -> Result<String> {
    let value = serde_json::to_vec(&(from, to, kind))?;
    Ok(format!("rel_{}", blake3::hash(&value).to_hex()))
}

fn validate_endpoint(endpoint: &FindingRelationshipEndpoint) -> Result<()> {
    anyhow::ensure!(
        endpoint.finding_id > 0,
        "relationship finding reference is missing"
    );
    anyhow::ensure!(
        !endpoint.stable_key.trim().is_empty() && !endpoint.fingerprint.trim().is_empty(),
        "relationship identity is missing"
    );
    Ok(())
}

fn validate_note(note: &str) -> Result<()> {
    anyhow::ensure!(
        !note.trim().is_empty(),
        "relationship reason cannot be empty"
    );
    anyhow::ensure!(note.len() <= 4096, "relationship reason exceeds 4096 bytes");
    Ok(())
}

fn validate_authority(relationship: &FindingRelationship) -> Result<()> {
    anyhow::ensure!(
        matches!(relationship.author.as_str(), "human" | "model"),
        "relationship author must be human or model"
    );
    anyhow::ensure!(
        relationship.state == FindingRelationshipState::Proposed || relationship.author == "human",
        "only an operator can accept or undo a relationship"
    );
    Ok(())
}

fn validate_confidence(confidence: Option<f64>) -> Result<()> {
    if let Some(confidence) = confidence {
        anyhow::ensure!(
            confidence.is_finite() && (0.0..=1.0).contains(&confidence),
            "relationship confidence must be finite and within 0..1"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn endpoint(key: &str, id: i64) -> FindingRelationshipEndpoint {
        FindingRelationshipEndpoint {
            stable_key: key.into(),
            fingerprint: format!("fp-{key}"),
            finding_id: id,
            run_id: Some("source-run".into()),
        }
    }
    #[test]
    fn review_is_reversible_and_does_not_rebind_the_recorded_source() {
        let proposal = FindingRelationship::new(
            endpoint("a", 1),
            endpoint("b", 2),
            FindingRelationshipKind::Duplicate,
            "Same observation".into(),
            "model".into(),
        )
        .unwrap();
        let accepted = proposal
            .review(
                FindingRelationshipState::Accepted,
                "Reviewed both".into(),
                1,
            )
            .unwrap();
        let removed = accepted
            .review(
                FindingRelationshipState::Removed,
                "Different causes".into(),
                2,
            )
            .unwrap();
        assert_eq!(proposal.from, removed.from);
        assert_eq!(proposal.to, removed.to);
        assert_eq!(proposal.id, removed.id);
        assert_eq!(removed.revision, 3);
        assert!(accepted
            .review(FindingRelationshipState::Rejected, "Stale editor".into(), 1)
            .is_err());
        let mut changed = removed;
        changed.from.run_id = Some("another-source".into());
        assert!(changed.validate().is_err());
    }
    #[test]
    fn invalid_authority_empty_notes_and_nonfinite_confidence_are_rejected() {
        let mut value = FindingRelationship::new(
            endpoint("a", 1),
            endpoint("b", 2),
            FindingRelationshipKind::Uncertain,
            "Uncertain link".into(),
            "model".into(),
        )
        .unwrap();
        value.state = FindingRelationshipState::Accepted;
        assert!(value.validate().is_err());
        value.state = FindingRelationshipState::Proposed;
        value.confidence = Some(f64::NAN);
        assert!(value.validate().is_err());
        value.confidence = None;
        value.note.clear();
        assert!(value.validate().is_err());
    }
}
