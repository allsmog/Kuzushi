//! Helpers that assemble system prompts from spine blocks so each capability
//! concatenates shared text instead of inlining its own variant.

/// Join a header with any number of spine blocks, separated by blank lines.
/// Empty blocks are skipped so callers can conditionally include sections.
pub fn assemble_system_prompt(header: &str, blocks: &[&str]) -> String {
    let mut sections: Vec<&str> = Vec::with_capacity(blocks.len() + 1);
    if !header.is_empty() {
        sections.push(header);
    }
    for block in blocks {
        if !block.is_empty() {
            sections.push(block);
        }
    }
    sections.join("\n\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assembles_header_and_blocks_with_blank_line_separators() {
        let out = assemble_system_prompt("HEADER", &["one", "", "two"]);
        assert_eq!(out, "HEADER\n\none\n\ntwo");
    }

    #[test]
    fn empty_header_is_omitted() {
        let out = assemble_system_prompt("", &["only"]);
        assert_eq!(out, "only");
    }
}
