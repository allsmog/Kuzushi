use super::*;

pub(crate) fn render_prompt(f: &Finding) -> String {
    format!(
        "tool       : {tool}\n\
         rule_id    : {rule}\n\
         severity   : {sev}\n\
         file       : {file}:{line}\n\
         title      : {title}\n\
         message    :\n{msg}",
        tool = f.tool,
        rule = f.rule_id,
        sev = f.severity.as_str(),
        file = f.file_path,
        line = f.start_line,
        title = f.title,
        msg = f.message,
    )
}

pub(crate) fn try_loose_parse(text: &str) -> Option<ClassifierResponse> {
    let trimmed = text.trim();
    let stripped = if trimmed.starts_with("```") {
        trimmed
            .trim_start_matches("```json")
            .trim_start_matches("```")
            .trim_end_matches("```")
            .trim()
            .to_string()
    } else {
        trimmed.to_string()
    };
    if let Ok(v) = serde_json::from_str(&stripped) {
        return Some(v);
    }
    let start = stripped.find('{')?;
    let end = stripped.rfind('}')?;
    serde_json::from_str(&stripped[start..=end]).ok()
}
