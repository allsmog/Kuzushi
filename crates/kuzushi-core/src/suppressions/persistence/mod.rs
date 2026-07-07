mod suppressions_file;

#[cfg(test)]
mod tests;

pub use suppressions_file::{
    derive_rule_id, load_suppression_rules, remove_suppression_rule, save_suppression_rules,
    upsert_suppression_rule,
};
