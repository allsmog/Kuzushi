pub(super) const ITEM_HEADER_LINE_LIMIT: usize = 12;
const ITEM_HEADER_BYTE_LIMIT: usize = 2_048;

#[derive(Debug, PartialEq, Eq)]
pub(super) struct FunctionHeader<'a> {
    pub(super) function_offset: usize,
    pub(super) name: &'a str,
}

pub(super) fn function_header(code: &str, start: usize) -> Option<FunctionHeader<'_>> {
    let bounded = bounded_item_header(code.get(start..)?)?;
    let mut cursor = HeaderCursor::new(bounded);
    cursor.skip_whitespace();
    cursor.consume_visibility()?;
    cursor.consume_qualifiers();
    let function_offset = start + cursor.offset;
    cursor.consume_keyword("fn")?;
    cursor.skip_whitespace();
    let name = cursor.consume_identifier()?;
    Some(FunctionHeader {
        function_offset,
        name,
    })
}

fn bounded_item_header(tail: &str) -> Option<&str> {
    let byte_end = utf8_boundary_before(tail, ITEM_HEADER_BYTE_LIMIT);
    let line_end = tail[..byte_end]
        .match_indices('\n')
        .nth(ITEM_HEADER_LINE_LIMIT - 1)
        .map_or(byte_end, |(offset, _)| offset);
    tail.get(..line_end)
}

fn utf8_boundary_before(text: &str, limit: usize) -> usize {
    let mut end = text.len().min(limit);
    while !text.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    end
}

struct HeaderCursor<'a> {
    text: &'a str,
    offset: usize,
}

impl<'a> HeaderCursor<'a> {
    fn new(text: &'a str) -> Self {
        Self { text, offset: 0 }
    }

    fn skip_whitespace(&mut self) {
        self.offset += self.text[self.offset..]
            .find(|character: char| !character.is_whitespace())
            .unwrap_or(self.text.len() - self.offset);
    }

    fn consume_visibility(&mut self) -> Option<()> {
        if self.consume_keyword("pub").is_none() {
            return Some(());
        }
        self.skip_whitespace();
        if self.text.as_bytes().get(self.offset) == Some(&b'(') {
            self.consume_balanced_parentheses()?;
            self.skip_whitespace();
        }
        Some(())
    }

    fn consume_qualifiers(&mut self) {
        loop {
            self.skip_whitespace();
            if self.consume_qualifier() {
                continue;
            }
            break;
        }
    }

    fn consume_qualifier(&mut self) -> bool {
        ["async", "const", "unsafe", "extern"]
            .iter()
            .any(|keyword| self.consume_keyword(keyword).is_some())
    }

    fn consume_keyword(&mut self, keyword: &str) -> Option<()> {
        let suffix = self.text.get(self.offset..)?.strip_prefix(keyword)?;
        if suffix.chars().next().is_some_and(identifier_character) {
            return None;
        }
        self.offset += keyword.len();
        Some(())
    }

    fn consume_identifier(&mut self) -> Option<&'a str> {
        let start = self.offset;
        let raw_prefix = self.text.get(start..)?.starts_with("r#");
        if raw_prefix {
            self.offset += 2;
        }
        self.offset += self.text[self.offset..]
            .find(|character: char| !identifier_character(character))
            .unwrap_or(self.text.len() - self.offset);
        (self.offset > start + usize::from(raw_prefix) * 2).then(|| &self.text[start..self.offset])
    }

    fn consume_balanced_parentheses(&mut self) -> Option<()> {
        let mut depth = 0isize;
        for (offset, character) in self.text[self.offset..].char_indices() {
            depth += isize::from(character == '(');
            depth -= isize::from(character == ')');
            if depth == 0 {
                self.offset += offset + 1;
                return Some(());
            }
        }
        None
    }
}

fn identifier_character(character: char) -> bool {
    character == '_' || character.is_alphanumeric()
}
