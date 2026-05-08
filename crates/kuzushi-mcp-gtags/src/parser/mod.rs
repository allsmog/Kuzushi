mod records;

#[cfg(test)]
mod tests;

pub(crate) use records::{parse_global_x, records_to_symbols};

#[cfg(test)]
pub(crate) use records::parse_global_x_line;
