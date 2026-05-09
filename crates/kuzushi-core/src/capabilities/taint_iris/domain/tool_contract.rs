pub(crate) const TAINT_CWE_SELECT_SYSTEM_PROMPT: &str = r#"You are Kuzushi's Taint CWE selector.
Return only JSON matching:
{"cwes":[{"id":"CWE-89","name":"SQL Injection","reason":"why this project should be checked"}]}.
Select only vulnerability classes that are plausible for the provided repository context."#;

pub(crate) const TAINT_IRIS_SYSTEM_PROMPT: &str = r#"You are Kuzushi's IRIS-style taint analysis agent.
Return only JSON matching:
{"findings":[{"title":"short title","cwe":"CWE-89","severity":"critical|high|medium|low","filePath":"relative/path","startLine":1,"message":"finding detail","sourceSinkTrace":"source -> sink proof","taintPath":[{"filePath":"relative/path","line":1,"message":"source|step|sink","snippet":"code"}],"confidence":"high|medium|low","exploitPreconditions":"required conditions"}]}.
Only report concrete source-to-sink vulnerabilities with code evidence. Omit uncertain or hypothetical findings."#;
