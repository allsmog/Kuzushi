use crate::ShellApp;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ToolsModel {
    pub(crate) rows: Vec<ToolRow>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ToolRow {
    pub(crate) cells: [String; 3],
}

pub(crate) fn tools_model(app: &ShellApp) -> ToolsModel {
    ToolsModel {
        rows: app
            .registry
            .tools()
            .map(|tool| ToolRow {
                cells: [
                    tool.name.clone(),
                    tool.headless.to_string(),
                    tool.description.clone(),
                ],
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests;
