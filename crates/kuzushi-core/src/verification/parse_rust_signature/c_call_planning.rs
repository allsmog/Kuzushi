use super::*;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CCallPlan {
    pub fn_name: String,
    /// One or more lines of C source forwarding into the suspect function.
    /// Always ends with a newline so callers can concatenate verbatim.
    pub call_expression: String,
    /// Short label describing which call pattern was selected.
    pub call_kind: &'static str,
}

/// Pick a C call expression appropriate for the signature's argument
/// types. Mirrors the Rust analogue's table.
pub(crate) fn plan_c_call_expression(sig: &CSignature) -> Option<CCallPlan> {
    match sig.args.as_slice() {
        [] => Some(c_call_plan(
            sig,
            "zero-argument call",
            &format!("{}()", sig.fn_name),
        )),
        [arg] => c_single_arg_payload_expr(arg).map(|expr| {
            c_call_plan(
                sig,
                "single-arg payload call",
                &format!("{}({expr})", sig.fn_name),
            )
        }),
        [buf, len] => c_buf_len_call_args(buf, len).map(|(buf_expr, len_expr)| {
            c_call_plan(
                sig,
                "(buf, len) C-FFI-style call",
                &format!("{}({buf_expr}, {len_expr})", sig.fn_name),
            )
        }),
        _ => None,
    }
    .map(|mut plan| {
        let bind = c_call_bind(sig);
        plan.call_expression = format!("    {bind}{};\n", plan.call_expression);
        plan
    })
}

pub(in crate::verification) fn c_call_bind(sig: &CSignature) -> &'static str {
    if c_returns_value(sig) {
        "(void)"
    } else {
        ""
    }
}

pub(in crate::verification) fn c_returns_value(sig: &CSignature) -> bool {
    sig.return_type
        .as_deref()
        .map(str::trim)
        .is_some_and(|rt| !rt.is_empty() && rt != "void")
}

pub(in crate::verification) fn c_call_plan(
    sig: &CSignature,
    call_kind: &'static str,
    call_expression: &str,
) -> CCallPlan {
    CCallPlan {
        fn_name: sig.fn_name.clone(),
        call_expression: call_expression.to_string(),
        call_kind,
    }
}

pub(in crate::verification) fn c_single_arg_payload_expr(raw_type: &str) -> Option<&'static str> {
    let ty = normalize_c_type(raw_type);
    lookup_type_expression(&ty, C_SINGLE_ARG_PAYLOADS)
}

pub(in crate::verification) fn c_buf_len_call_args(
    raw_buf_type: &str,
    raw_len_type: &str,
) -> Option<(&'static str, &'static str)> {
    let buf = normalize_c_type(raw_buf_type);
    let len = normalize_c_type(raw_len_type);
    Some((c_buffer_expr(&buf)?, c_len_expr(&len)?))
}

pub(in crate::verification) fn c_buffer_expr(ty: &str) -> Option<&'static str> {
    lookup_type_expression(ty, C_BUFFER_EXPRESSIONS)
}

pub(in crate::verification) fn c_len_expr(ty: &str) -> Option<&'static str> {
    lookup_type_expression(ty, C_LENGTH_EXPRESSIONS)
}

/// Normalise a C type for matching: collapse whitespace, attach `*` /
/// `&` adjacent to the previous token, and lowercase the qualifier
/// keywords (`const`, `volatile`).
pub(in crate::verification) fn normalize_c_type(ty: &str) -> String {
    let collapsed: String = ty.split_whitespace().collect::<Vec<_>>().join(" ");
    // Re-attach pointer markers — `const char *` and `const char*` both
    // map to `const char *` after trimming and normalising spacing.
    let mut out = String::with_capacity(collapsed.len());
    let mut chars = collapsed.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == ' ' {
            // Drop spaces immediately before `*` / `&`.
            match chars.peek() {
                Some('*') | Some('&') => continue,
                _ => out.push(' '),
            }
        } else {
            out.push(ch);
        }
    }
    out
}
