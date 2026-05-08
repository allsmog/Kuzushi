use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShellCommandSpec {
    pub command: &'static str,
    pub aliases: &'static [&'static str],
    pub category: ShellCommandCategory,
    pub description: &'static str,
}
