use super::*;

impl FindingStore {
    pub fn list_review_decisions(&self, finding_id: i64) -> Result<Vec<ReviewDecisionRecord>> {
        let mut stmt = self.conn.prepare(
            r#"
            select id, finding_id, identity_id, decision_verdict, triage_verdict,
                   confidence, rationale, author, created_at
              from review_decisions
             where finding_id = ?1
             order by created_at asc, id asc
            "#,
        )?;
        let rows = stmt.query_map(params![finding_id], review_decision_record_from_row)?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .context("Could not list review decisions")
    }

    pub fn list_review_decisions_for_identity(
        &self,
        identity_id: &str,
    ) -> Result<Vec<ReviewDecisionRecord>> {
        let mut stmt = self.conn.prepare(
            r#"
            select id, finding_id, identity_id, decision_verdict, triage_verdict,
                   confidence, rationale, author, created_at
              from review_decisions
             where identity_id = ?1
             order by created_at asc, id asc
            "#,
        )?;
        let rows = stmt.query_map(params![identity_id], review_decision_record_from_row)?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .context("Could not list review decisions for identity")
    }

    pub fn list_review_decisions_for_finding_identity(
        &self,
        finding_id: i64,
    ) -> Result<Vec<ReviewDecisionRecord>> {
        let Some(identity_id) = self.identity_id_for_finding(finding_id)? else {
            return self.list_review_decisions(finding_id);
        };
        self.list_review_decisions_for_identity(&identity_id)
    }

    pub fn latest_review_decision(&self, finding_id: i64) -> Result<Option<ReviewDecisionRecord>> {
        let mut stmt = self.conn.prepare(
            r#"
            select id, finding_id, identity_id, decision_verdict, triage_verdict,
                   confidence, rationale, author, created_at
              from review_decisions
             where finding_id = ?1
             order by created_at desc, id desc
             limit 1
            "#,
        )?;
        stmt.query_row(params![finding_id], review_decision_record_from_row)
            .optional()
            .context("Could not load latest review decision")
    }

    pub fn latest_review_decision_for_identity(
        &self,
        identity_id: &str,
    ) -> Result<Option<ReviewDecisionRecord>> {
        let mut stmt = self.conn.prepare(
            r#"
            select id, finding_id, identity_id, decision_verdict, triage_verdict,
                   confidence, rationale, author, created_at
              from review_decisions
             where identity_id = ?1
             order by created_at desc, id desc
             limit 1
            "#,
        )?;
        stmt.query_row(params![identity_id], review_decision_record_from_row)
            .optional()
            .context("Could not load latest review decision for identity")
    }

    pub fn latest_review_decision_for_finding_identity(
        &self,
        finding_id: i64,
    ) -> Result<Option<ReviewDecisionRecord>> {
        let Some(identity_id) = self.identity_id_for_finding(finding_id)? else {
            return self.latest_review_decision(finding_id);
        };
        self.latest_review_decision_for_identity(&identity_id)
    }

    pub fn append_user_review_decision(
        &self,
        finding_id: i64,
        decision: &ReviewDecision,
    ) -> Result<i64> {
        if decision.author == TriageAuthor::Auto {
            anyhow::bail!(
                "append_user_review_decision requires a human or imported author; automated triage must use save_triage"
            );
        }
        if decision.rationale.trim().is_empty() {
            anyhow::bail!("review decision reason cannot be empty");
        }
        self.append_review_decision(
            finding_id,
            decision,
            decision.verdict.to_triage_verdict(),
            &now_isoish(),
        )
    }

    pub(in crate::findings::persistence::open) fn append_review_decision_from_triage(
        &self,
        finding_id: i64,
        triage: &TriageOutcome,
        author: TriageAuthor,
        created_at: &str,
    ) -> Result<i64> {
        let decision = ReviewDecision::from_triage(triage, Some(author));
        self.append_review_decision(finding_id, &decision, Some(triage.verdict), created_at)
    }

    fn append_review_decision(
        &self,
        finding_id: i64,
        decision: &ReviewDecision,
        triage_verdict: Option<TriageVerdict>,
        created_at: &str,
    ) -> Result<i64> {
        let triage_verdict = triage_verdict.map(TriageVerdict::as_str);
        self.conn.execute(
            r#"
            insert into review_decisions(
              finding_id, identity_id, decision_verdict, triage_verdict, confidence,
              rationale, author, created_at
            )
            values (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
            "#,
            params![
                finding_id,
                self.identity_id_for_finding(finding_id)?,
                decision.verdict.as_str(),
                triage_verdict,
                decision.confidence,
                decision.rationale.as_str(),
                decision.author.as_str(),
                created_at,
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    fn identity_id_for_finding(&self, finding_id: i64) -> Result<Option<String>> {
        Ok(self
            .v3_finding_by_projected_id(finding_id)?
            .and_then(|finding| finding.identity_id))
    }
}

fn review_decision_record_from_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<ReviewDecisionRecord> {
    let decision_verdict: String = row.get(3)?;
    let triage_verdict: Option<String> = row.get(4)?;
    let author: String = row.get(7)?;
    Ok(ReviewDecisionRecord {
        id: row.get(0)?,
        finding_id: row.get(1)?,
        identity_id: row.get(2)?,
        decision: ReviewDecision {
            verdict: ReviewDecisionVerdict::from_str(&decision_verdict).ok_or_else(|| {
                to_sql_error(anyhow::anyhow!(
                    "unknown review decision verdict {decision_verdict:?}"
                ))
            })?,
            author: TriageAuthor::from_str(&author).ok_or_else(|| {
                to_sql_error(anyhow::anyhow!("unknown review decision author {author:?}"))
            })?,
            confidence: row.get(5)?,
            rationale: row.get(6)?,
        },
        triage_verdict: triage_verdict
            .as_deref()
            .map(TriageVerdict::try_from)
            .transpose()
            .map_err(to_sql_error)?,
        created_at: row.get(8)?,
    })
}
