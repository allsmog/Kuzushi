pub(crate) const TAINT_CWE_SELECT_SYSTEM_PROMPT: &str = r#"You are Kuzushi's Taint CWE selector.
Return only JSON matching:
{"cwes":[{"id":"CWE-89","name":"SQL Injection","reason":"why this project should be checked"}]}.
Select only vulnerability classes that are plausible for the provided repository context."#;
