pub(in crate::verify) const RUST_SINGLE_ARG_PAYLOADS: &[(&[&str], &str)] = &[
    (&["&[u8]", "&Vec<u8>"], "&payload"),
    (&["Vec<u8>"], "payload.clone()"),
    (&["&str"], "std::str::from_utf8(&payload).unwrap_or(\"\")"),
    (
        &["String"],
        "String::from_utf8_lossy(&payload).into_owned()",
    ),
    (&["usize"], "payload.len()"),
    (&["u32"], "payload.len() as u32"),
    (&["u64"], "payload.len() as u64"),
    (&["i32"], "payload.len() as i32"),
    (&["i64"], "payload.len() as i64"),
];

pub(in crate::verify) const RUST_BUFFER_EXPRESSIONS: &[(&[&str], &str)] = &[
    (&["&[u8]"], "&payload"),
    (&["*const u8"], "payload.as_ptr()"),
];

pub(in crate::verify) const RUST_LENGTH_EXPRESSIONS: &[(&[&str], &str)] = &[
    (&["usize"], "payload.len()"),
    (&["u32"], "payload.len() as u32"),
    (&["u64"], "payload.len() as u64"),
];
