pub(in crate::renderer) use super::*;

pub(crate) fn option_table_widths(width: u16) -> Vec<usize> {
    let total = width as usize;
    let option = if total <= 80 { 13 } else { 16 };
    let value = if total <= 80 { 8 } else { 10 };
    let default = if total <= 80 { 7 } else { 9 };
    let required = if total <= 80 { 3 } else { 5 };
    let kind = 5;
    let aliases = if total <= 80 { 10 } else { 16 };
    let gaps = 12;
    let description = total
        .saturating_sub(option + value + default + required + kind + aliases + gaps)
        .max(12);
    vec![option, value, default, required, kind, aliases, description]
}

pub(crate) fn sast_task_table_widths(width: u16) -> Vec<usize> {
    let total = width as usize;
    let state = 5;
    let id = if total < 88 { 20 } else { 24 };
    let cost = 5;
    let scan = if total < 88 { 14 } else { 18 };
    let gaps = 8;
    let notes = total
        .saturating_sub(state + id + cost + scan + gaps)
        .max(16);
    vec![state, id, cost, scan, notes]
}
