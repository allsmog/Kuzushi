use super::*;
use anyhow::Context;

pub(crate) const FINDING_LESSON_SUBJECT: &str = "finding-lesson-v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LessonState {
    Draft,
    Accepted,
    Rejected,
    Retired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LessonContent {
    pub title: String,
    pub text: String,
    pub applicability: String,
    pub limitations: String,
}

impl LessonContent {
    pub fn validate(&self) -> Result<()> {
        for (label, text, limit) in [
            ("title", &self.title, 256),
            ("lesson", &self.text, 8192),
            ("applicability", &self.applicability, 2048),
            ("limitations", &self.limitations, 2048),
        ] {
            anyhow::ensure!(
                !text.trim().is_empty() && text.len() <= limit,
                "Lesson {label} must contain 1 to {limit} bytes"
            );
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LessonOrigin {
    pub target: String,
    pub finding: FindingRelationshipEndpoint,
    pub decision: ReviewDecisionRecord,
    pub observation_seq: u64,
    pub snapshot_hash: String,
    pub source_git: Option<crate::RunTargetGitMetadata>,
}

impl LessonOrigin {
    pub fn validate(&self) -> Result<()> {
        anyhow::ensure!(
            self.finding.finding_id > 0
                && !self.finding.fingerprint.is_empty()
                && !self.target.is_empty(),
            "Lesson origin is missing"
        );
        anyhow::ensure!(
            self.decision.decision.author == TriageAuthor::Human
                && self.decision.decision.verdict == ReviewDecisionVerdict::Confirmed,
            "A lesson requires an explicitly human-confirmed finding"
        );
        anyhow::ensure!(
            self.decision.finding_id == self.finding.finding_id,
            "Lesson confirmation belongs to a different generation"
        );
        let provenance = self
            .decision
            .provenance
            .as_ref()
            .context("Lesson confirmation provenance is missing")?;
        let watermark = provenance
            .read_watermark
            .context("Lesson confirmation watermark is missing")?;
        anyhow::ensure!(
            self.observation_seq > 0
                && self.observation_seq <= watermark
                && !self.snapshot_hash.is_empty(),
            "Lesson source is not bound to the confirmed observation"
        );
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LessonRef {
    pub lesson_id: String,
    pub revision: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LessonGeneration {
    pub model: String,
    pub run_id: Option<String>,
    pub prompt_sha256: String,
    pub source_capture: String,
    pub input_bytes: usize,
    pub synthesis_requests: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_evidence_ref: Option<String>,
}

impl LessonGeneration {
    fn validate(&self) -> Result<()> {
        validate_source_evidence_ref(self.source_evidence_ref.as_deref())?;
        anyhow::ensure!(
            !self.model.trim().is_empty() && self.model.len() <= 512,
            "Lesson generation model is missing or invalid"
        );
        let hash = self
            .prompt_sha256
            .strip_prefix("sha256:")
            .context("Lesson prompt digest is invalid")?;
        anyhow::ensure!(
            hash.len() == 64 && hash.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "Lesson prompt digest is invalid"
        );
        anyhow::ensure!(
            self.synthesis_requests == 1 && self.input_bytes > 0 && self.input_bytes <= 128 * 1024,
            "Lesson generation bounds are invalid"
        );
        anyhow::ensure!(
            matches!(
                self.source_capture.as_str(),
                "included" | "not_recorded" | "unavailable_or_over_limit"
            ),
            "Lesson source capture state is invalid"
        );
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FindingLesson {
    pub schema_version: u32,
    pub id: String,
    pub revision: u64,
    pub state: LessonState,
    pub content: LessonContent,
    pub origin: LessonOrigin,
    pub author: String,
    pub review_note: Option<String>,
    pub generation: Option<LessonGeneration>,
}

impl FindingLesson {
    pub fn draft(
        id: String,
        content: LessonContent,
        origin: LessonOrigin,
        generation: Option<LessonGeneration>,
    ) -> Result<Self> {
        let author = if generation.is_some() {
            "model"
        } else {
            "operator"
        }
        .into();
        let record = Self {
            schema_version: 1,
            id,
            revision: 1,
            state: LessonState::Draft,
            content,
            origin,
            author,
            review_note: None,
            generation,
        };
        record.validate()?;
        Ok(record)
    }

    pub fn validate(&self) -> Result<()> {
        anyhow::ensure!(
            self.schema_version == 1 && self.revision > 0,
            "Unsupported lesson revision"
        );
        uuid::Uuid::parse_str(
            self.id
                .strip_prefix("lesson_")
                .context("Invalid lesson id")?,
        )?;
        self.origin.validate()?;
        self.content.validate()?;
        if let Some(generation) = &self.generation {
            generation.validate()?;
        }
        anyhow::ensure!(
            matches!(self.author.as_str(), "operator" | "model"),
            "Invalid lesson authority"
        );
        if self.state != LessonState::Draft {
            anyhow::ensure!(
                self.author == "operator",
                "Only an operator can review a lesson"
            );
            validate_review_note(self.review_note.as_deref().unwrap_or_default())?;
        }
        Ok(())
    }

    pub fn reference(&self) -> Result<LessonRef> {
        Ok(LessonRef {
            lesson_id: self.id.clone(),
            revision: self.revision,
            sha256: crate::options::prompt_content_sha256(&serde_json::to_string(self)?),
        })
    }

    pub fn revise(&self, reference: &LessonRef, content: LessonContent) -> Result<Self> {
        self.require_reference(reference)?;
        anyhow::ensure!(content != self.content, "No lesson text changed");
        let mut revised = self.next_revision()?;
        revised.content = content;
        revised.state = LessonState::Draft;
        revised.author = "operator".into();
        revised.review_note = None;
        revised.validate()?;
        Ok(revised)
    }

    pub fn review(&self, reference: &LessonRef, state: LessonState, note: String) -> Result<Self> {
        self.require_reference(reference)?;
        anyhow::ensure!(
            state != LessonState::Draft,
            "Review must accept, reject or retire a lesson"
        );
        validate_review_note(&note)?;
        let mut reviewed = self.next_revision()?;
        reviewed.state = state;
        reviewed.author = "operator".into();
        reviewed.review_note = Some(note);
        reviewed.validate()?;
        Ok(reviewed)
    }

    fn require_reference(&self, reference: &LessonRef) -> Result<()> {
        anyhow::ensure!(
            &self.reference()? == reference,
            "Lesson changed; refresh before editing or reviewing"
        );
        Ok(())
    }

    fn next_revision(&self) -> Result<Self> {
        let mut revised = self.clone();
        revised.revision = self
            .revision
            .checked_add(1)
            .context("Lesson revision exhausted")?;
        Ok(revised)
    }
}

fn validate_review_note(note: &str) -> Result<()> {
    anyhow::ensure!(
        !note.trim().is_empty() && note.len() <= 4096,
        "Lesson review reason must contain 1 to 4096 bytes"
    );
    Ok(())
}

fn validate_source_evidence_ref(reference: Option<&str>) -> Result<()> {
    let Some(reference) = reference else {
        return Ok(());
    };
    let hash = reference
        .strip_prefix("lesson-source:")
        .context("Invalid lesson source reference")?;
    anyhow::ensure!(
        hash.len() == 64 && hash.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "Invalid lesson source reference"
    );
    Ok(())
}
