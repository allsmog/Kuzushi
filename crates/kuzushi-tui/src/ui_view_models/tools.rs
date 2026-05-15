use crate::ShellApp;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ToolsModel {
    pub(crate) rows: Vec<ToolRow>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ToolRow {
    pub(crate) name: String,
    pub(crate) headless: String,
    pub(crate) description: String,
}

pub(crate) fn tools_model(app: &ShellApp) -> ToolsModel {
    ToolsModel {
        rows: app
            .registry
            .tools()
            .map(|tool| ToolRow {
                name: tool.name.clone(),
                headless: tool.headless.to_string(),
                description: tool.description.clone(),
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests;
