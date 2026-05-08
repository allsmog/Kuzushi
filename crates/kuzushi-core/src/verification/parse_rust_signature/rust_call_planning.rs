use super::*;

/// A planned synthetic call into the suspect function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CallPlan {
    pub fn_name: String,
    /// Single line of Rust source that invokes the function. Always ends
    /// with `;` so it can be slotted into a function body verbatim.
    pub call_expression: String,
    /// One-line description of the synthesis pattern (for the harness
    /// header comment).
    pub call_kind: &'static str,
}

/// Pick a call expression appropriate for the signature's argument
/// types. Returns `None` when no supported pattern matches — the
/// harness will then fall back to the payload-only mode.
pub(crate) fn plan_call_expression(sig: &RustSignature) -> Option<CallPlan> {
    let fn_path = format!("suspect::{}", sig.fn_name);
    let bind = rust_call_bind(sig);

    match sig.args.as_slice() {
        [] => Some(rust_call_plan(
            sig,
            "zero-argument call",
            &format!("{fn_path}()"),
        )),
        [arg] => rust_single_arg_payload_expr(arg).map(|expr| {
            rust_call_plan(
                sig,
                "single-arg payload call",
                &format!("{fn_path}({expr})"),
            )
        }),
        [buf, len] => rust_buf_len_call_args(buf, len).map(|(buf_expr, len_expr)| {
            rust_call_plan(
                sig,
                "(buf, len) C-FFI-style call",
                &format!("{fn_path}({buf_expr}, {len_expr})"),
            )
        }),
        _ => None,
    }
    .map(|mut plan| {
        plan.call_expression = format!("            {bind}{};\n", plan.call_expression.trim());
        plan
    })
}

pub(in crate::verification) fn rust_call_bind(sig: &RustSignature) -> &'static str {
    if sig.return_type.is_some() {
        "let _ = "
    } else {
        ""
    }
}

pub(in crate::verification) fn rust_call_plan(
    sig: &RustSignature,
    call_kind: &'static str,
    call_expression: &str,
) -> CallPlan {
    CallPlan {
        fn_name: sig.fn_name.clone(),
        call_expression: call_expression.to_string(),
        call_kind,
    }
}

pub(in crate::verification) fn rust_single_arg_payload_expr(
    raw_type: &str,
) -> Option<&'static str> {
    let ty = normalize_type(raw_type);
    lookup_type_expression(&ty, RUST_SINGLE_ARG_PAYLOADS)
}

pub(in crate::verification) fn rust_buf_len_call_args(
    raw_buf_type: &str,
    raw_len_type: &str,
) -> Option<(&'static str, &'static str)> {
    let buf = normalize_type(raw_buf_type);
    let len = normalize_type(raw_len_type);
    Some((rust_buffer_expr(&buf)?, rust_len_expr(&len)?))
}

pub(in crate::verification) fn rust_buffer_expr(ty: &str) -> Option<&'static str> {
    lookup_type_expression(ty, RUST_BUFFER_EXPRESSIONS)
}

pub(in crate::verification) fn rust_len_expr(ty: &str) -> Option<&'static str> {
    lookup_type_expression(ty, RUST_LENGTH_EXPRESSIONS)
}

pub(in crate::verification) fn lookup_type_expression(
    ty: &str,
    table: &[(&[&str], &'static str)],
) -> Option<&'static str> {
    table
        .iter()
        .find_map(|(types, expr)| types.contains(&ty).then_some(*expr))
}

pub(in crate::verification) fn normalize_type(ty: &str) -> String {
    // Collapse whitespace; strip path prefixes from the standard
    // collections so `std::vec::Vec<u8>` and `Vec<u8>` are treated the
    // same.
    let mut out = ty.split_whitespace().collect::<Vec<_>>().join(" ");
    out = out.replace("std::vec::Vec", "Vec");
    out = out.replace("alloc::vec::Vec", "Vec");
    out = out.replace("std::string::String", "String");
    out = out.replace("alloc::string::String", "String");
    out
}
