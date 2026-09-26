//! Line-level Terraform block tracking for structural finding locators.
//!
//! A line detector sees `cidr_blocks = ["0.0.0.0/0"]` many times in one file.
//! Naming the enclosing block (`aws_security_group.alb.ingress[1]`) keeps
//! those occurrences distinct without making line numbers part of identity.
//! The tracker is deliberately conservative: it names only `key = value`
//! statements directly inside labeled blocks and yields no locator inside
//! heredocs or unlabeled nesting such as `jsonencode({ ... })`.

use std::collections::BTreeMap;

const BLOCK_OPEN: char = '{';

#[derive(Debug, Default)]
pub(crate) struct TerraformBlockPath {
    frames: Vec<Option<String>>,
    sibling_counts: BTreeMap<String, usize>,
    heredoc_terminator: Option<String>,
}

impl TerraformBlockPath {
    /// Structural locator for a comment-stripped, trimmed statement, read
    /// before [`Self::advance`] consumes that statement.
    pub(crate) fn locator_for(&self, statement: &str) -> Option<String> {
        if self.heredoc_terminator.is_some() || !self.innermost_is_labeled() {
            return None;
        }
        let key = attribute_key(statement)?;
        Some(format!("{}.{key}", self.labeled_path()))
    }

    fn innermost_is_labeled(&self) -> bool {
        matches!(self.frames.last(), Some(Some(_)))
    }

    fn labeled_path(&self) -> String {
        let labels = self.frames.iter().flatten().cloned().collect::<Vec<_>>();
        labels.join(".")
    }

    /// Consume one statement, updating heredoc state and the block stack.
    pub(crate) fn advance(&mut self, statement: &str) {
        if let Some(terminator) = &self.heredoc_terminator {
            if statement == terminator {
                self.heredoc_terminator = None;
            }
            return;
        }
        self.heredoc_terminator = heredoc_terminator(statement);
        self.apply_braces(statement);
    }

    fn apply_braces(&mut self, statement: &str) {
        let (opens, closes) = unquoted_brace_counts(statement);
        for _ in 0..closes {
            self.frames.pop();
        }
        if opens == 0 {
            return;
        }
        let label = self.block_label(statement);
        self.frames.push(label);
        self.frames.extend((1..opens).map(|_| None));
    }

    /// Labeled blocks (`resource "type" "name"`) are unique by Terraform
    /// rules; repeated nested blocks (`ingress`) are numbered per parent.
    fn block_label(&mut self, statement: &str) -> Option<String> {
        let header = block_header(statement)?;
        if header.labeled {
            return Some(header.name);
        }
        let key = format!("{}|{}", self.labeled_path(), header.name);
        let ordinal = self.sibling_counts.entry(key).or_default();
        let label = format!("{}[{ordinal}]", header.name);
        *ordinal += 1;
        Some(label)
    }
}

struct BlockHeader {
    name: String,
    labeled: bool,
}

/// Parses `resource "aws_sg" "alb" {`, `module "vpc" {`, `ingress {`, and
/// `tags = {`. Anything else (for example `jsonencode({`) is unlabeled.
fn block_header(statement: &str) -> Option<BlockHeader> {
    let head = statement.strip_suffix(BLOCK_OPEN)?.trim_end();
    let head = head.strip_suffix('=').unwrap_or(head).trim_end();
    let tokens = head.split_whitespace().collect::<Vec<_>>();
    let (keyword, labels) = tokens.split_first()?;
    if !is_identifier(keyword) || !labels.iter().all(|label| is_quoted(label)) {
        return None;
    }
    Some(labeled_header(keyword, labels))
}

fn labeled_header(keyword: &str, labels: &[&str]) -> BlockHeader {
    let labels = labels
        .iter()
        .map(|label| label.trim_matches('"'))
        .collect::<Vec<_>>();
    let name = match (keyword, labels.as_slice()) {
        ("resource", [kind, name]) => format!("{kind}.{name}"),
        (_, []) => keyword.to_string(),
        _ => format!("{keyword}.{}", labels.join(".")),
    };
    BlockHeader {
        name,
        labeled: !labels.is_empty(),
    }
}

fn attribute_key(statement: &str) -> Option<&str> {
    let (key, _) = statement.split_once('=')?;
    let key = key.trim();
    is_identifier(key).then_some(key)
}

fn heredoc_terminator(statement: &str) -> Option<String> {
    let (_, marker) = statement.rsplit_once("<<")?;
    let marker = marker.trim_start_matches('-').trim();
    is_identifier(marker).then(|| marker.to_string())
}

fn unquoted_brace_counts(statement: &str) -> (usize, usize) {
    let mut in_string = false;
    let mut previous = '\0';
    let (mut opens, mut closes) = (0, 0);
    for ch in statement.chars() {
        in_string ^= ch == '"' && previous != '\\';
        opens += usize::from(!in_string && ch == '{');
        closes += usize::from(!in_string && ch == '}');
        previous = ch;
    }
    (opens, closes)
}

fn is_identifier(value: &str) -> bool {
    !value.is_empty()
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '_' || ch == '-')
}

fn is_quoted(value: &str) -> bool {
    value.len() >= 2 && value.starts_with('"') && value.ends_with('"')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn locators(source: &str) -> Vec<Option<String>> {
        let mut path = TerraformBlockPath::default();
        source
            .lines()
            .map(|line| {
                let statement = line.trim();
                let locator = path.locator_for(statement);
                path.advance(statement);
                locator
            })
            .collect()
    }

    #[test]
    fn repeated_nested_blocks_are_numbered_per_resource() {
        let source = r#"resource "aws_security_group" "alb" {
  ingress {
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    cidr_blocks = ["0.0.0.0/0"]
  }
}
resource "aws_security_group" "ecs" {
  egress {
    cidr_blocks = ["0.0.0.0/0"]
  }
}"#;
        let found = locators(source).into_iter().flatten().collect::<Vec<_>>();

        assert_eq!(
            found,
            [
                "aws_security_group.alb.ingress[0].cidr_blocks",
                "aws_security_group.alb.ingress[1].cidr_blocks",
                "aws_security_group.ecs.egress[0].cidr_blocks",
            ]
        );
    }

    #[test]
    fn interpolation_braces_inside_strings_do_not_open_blocks() {
        let source = r#"resource "aws_route_table" "public" {
  name = "${var.project}-rt"
  route {
    cidr_block = "0.0.0.0/0"
  }
}"#;

        assert_eq!(
            locators(source)[3].as_deref(),
            Some("aws_route_table.public.route[0].cidr_block")
        );
    }

    #[test]
    fn heredoc_and_unlabeled_nesting_yield_no_locator() {
        let source = r#"resource "aws_iam_policy" "p" {
  policy = <<EOF
cidr = "0.0.0.0/0"
EOF
  document = jsonencode({
    cidr = "0.0.0.0/0"
  })
  after = "0.0.0.0/0"
}"#;
        let found = locators(source);

        assert_eq!(found[2], None);
        assert_eq!(found[5], None);
        assert_eq!(found[7].as_deref(), Some("aws_iam_policy.p.after"));
    }

    #[test]
    fn statements_outside_any_block_have_no_locator() {
        assert_eq!(locators(r#"cidr = "0.0.0.0/0""#), [None]);
    }

    #[test]
    fn non_resource_blocks_keep_their_keyword() {
        let source = "module \"vpc\" {\n  cidr = \"0.0.0.0/0\"\n}";

        assert_eq!(locators(source)[1].as_deref(), Some("module.vpc.cidr"));
    }
}
