//! Shared `key:value` filter grammar primitives used by both the findings
//! filter and the tool catalog query. One tokenizer, so the two grammars can
//! never drift on quoting, CSV, or negation rules.

mod filter_expression;

pub use filter_expression::{tokenize_filter_expression, FilterToken};
