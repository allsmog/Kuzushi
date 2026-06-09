//! Sanitisation helpers for strings that may carry LLM- or repo-controlled
//! content into the operator's terminal or a CI log line. A malicious
//! scanned repository, or an agent tricked by prompt injection, can plant
//! ANSI escape sequences that move the cursor / clear the screen / spoof
//! a fake prompt, or embed newlines that inject extra CI log lines under
//! a forged prefix. Always run untrusted strings through one of these
//! before `println!`-ing them.

/// Drop ANSI escape sequences (CSI, OSC, plain `ESC <byte>`) and other
/// C0 control bytes, but keep `\n`, `\r`, `\t` so legitimate multi-line
/// tool output (markdown, JSON, etc.) still renders.
pub(crate) fn sanitize_for_terminal(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{001b}' {
            consume_escape_sequence(&mut chars);
            continue;
        }
        let code = c as u32;
        if code < 0x20 && c != '\n' && c != '\r' && c != '\t' {
            continue;
        }
        if code == 0x7F {
            continue;
        }
        out.push(c);
    }
    out
}

/// Drop ALL control characters including `\n`, `\r`, `\t`, ESC, and DEL.
/// Use for content that goes into a single CI log line — embedded
/// newlines would otherwise let an attacker inject a fake `[+N.Ns] exit: 0`
/// line under our prefix.
pub(crate) fn sanitize_for_log_line(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for c in input.chars() {
        let code = c as u32;
        if code < 0x20 || code == 0x7F {
            continue;
        }
        out.push(c);
    }
    out
}

fn consume_escape_sequence(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) {
    match chars.peek() {
        Some(&'[') => {
            chars.next();
            for c in chars.by_ref() {
                if c.is_ascii_alphabetic() || c == '~' {
                    break;
                }
            }
        }
        Some(&']') => {
            chars.next();
            while let Some(c) = chars.next() {
                if c == '\u{0007}' {
                    break;
                }
                if c == '\u{001b}' && matches!(chars.peek(), Some(&'\\')) {
                    chars.next();
                    break;
                }
            }
        }
        Some(_) => {
            chars.next();
        }
        None => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_csi_color_codes_from_terminal_output() {
        let input = "\u{001b}[31mred\u{001b}[0m plain";
        assert_eq!(sanitize_for_terminal(input), "red plain");
    }

    #[test]
    fn strips_cursor_movement_csi() {
        let input = "before\u{001b}[2Jafter";
        assert_eq!(sanitize_for_terminal(input), "beforeafter");
    }

    #[test]
    fn strips_osc_title_set() {
        let input = "x\u{001b}]0;malicious\u{0007}y";
        assert_eq!(sanitize_for_terminal(input), "xy");
    }

    #[test]
    fn strips_st_terminated_osc() {
        let input = "x\u{001b}]8;;https://evil\u{001b}\\link\u{001b}]8;;\u{001b}\\y";
        // Both hyperlink OSC sequences are stripped; the literal letters
        // between them survive.
        assert_eq!(sanitize_for_terminal(input), "xlinky");
    }

    #[test]
    fn preserves_newlines_and_tabs_for_terminal() {
        let input = "line1\nline2\tindented\r\n";
        assert_eq!(sanitize_for_terminal(input), "line1\nline2\tindented\r\n");
    }

    #[test]
    fn drops_other_c0_control_bytes() {
        let input = "x\u{0000}\u{0001}\u{0008}y";
        assert_eq!(sanitize_for_terminal(input), "xy");
    }

    #[test]
    fn log_line_drops_newlines_and_cr() {
        let input = "[+0.0s] error: boom\n[+0.0s] exit: 0";
        let cleaned = sanitize_for_log_line(input);
        assert!(!cleaned.contains('\n'), "got: {cleaned}");
        assert_eq!(cleaned, "[+0.0s] error: boom[+0.0s] exit: 0");
    }

    #[test]
    fn log_line_drops_carriage_return() {
        let input = "ok\rEVIL: gotcha";
        assert!(!sanitize_for_log_line(input).contains('\r'));
    }

    #[test]
    fn log_line_drops_esc_and_del() {
        let input = "a\u{001b}b\u{007F}c";
        assert_eq!(sanitize_for_log_line(input), "abc");
    }
}
