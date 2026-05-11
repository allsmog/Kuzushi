mod auto_spawn;
mod cpg_parse;
mod http_query;

#[cfg(test)]
mod tests;

pub(crate) use cpg_parse::parse_repo;
pub(crate) use http_query::run_query;

#[cfg(test)]
pub(crate) use cpg_parse::read_head_commit;
