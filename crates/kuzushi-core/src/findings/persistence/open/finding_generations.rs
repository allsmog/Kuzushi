use super::*;

#[cfg(test)]
mod tests;

const EMITTED_FINDING_GENERATIONS_SQL: &str = r#"
with ranked as (
    select finding_json, created_seq,
           row_number() over (
               partition by cast(json_extract(finding_json, '$.id') as integer)
               order by created_seq desc
           ) as observation_rank
      from finding_observations
     where finding_json is not null
       and json_extract(finding_json, '$.id') is not null
)
select finding_json
  from ranked
 where observation_rank = 1
 order by created_seq asc
"#;

impl FindingStore {
    /// One latest observation for every emitted finding generation.
    ///
    /// Unlike `list_all_findings`, this never projects multiple generations
    /// through a durable identity. Safety audits need the unfurled rows so a
    /// broad identity cannot erase conflicting locations, rules, or symbols.
    pub fn list_emitted_finding_generations(&self) -> Result<Vec<Finding>> {
        let mut findings = self.finding_generations_in_observation_order()?;
        findings.sort_by(super::v3_finding_reads::finding_list_order);
        Ok(findings)
    }

    pub(super) fn finding_generations_in_observation_order(&self) -> Result<Vec<Finding>> {
        let mut statement = self.conn.prepare(EMITTED_FINDING_GENERATIONS_SQL)?;
        let rows = statement.query_map([], |row| row.get::<_, String>(0))?;
        let findings = rows
            .collect::<rusqlite::Result<Vec<_>>>()?
            .into_iter()
            .map(parse_finding_generation)
            .collect::<Result<Vec<_>>>()?;
        self.hydrate_v3_findings(findings)
    }
}

fn parse_finding_generation(raw: String) -> Result<Finding> {
    serde_json::from_str(&raw).context("Could not parse emitted finding generation")
}
