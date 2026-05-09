use super::*;

mod auth_network_native;
mod data_formats;
mod filesystem_commands;
mod web_injection;

pub(crate) const TAINT_IRIS_NEXT_CATALOG: &[TaintIrisNextCatalogEntry] = &[
    filesystem_commands::PATH_TRAVERSAL,
    filesystem_commands::COMMAND_INJECTION,
    web_injection::CROSS_SITE_SCRIPTING,
    web_injection::SQL_INJECTION,
    web_injection::CODE_INJECTION,
    data_formats::LOG_INJECTION,
    auth_network_native::INTEGER_OVERFLOW,
    data_formats::DESERIALIZATION,
    data_formats::XML_EXTERNAL_ENTITY,
    auth_network_native::MISSING_AUTHORIZATION,
    auth_network_native::SERVER_SIDE_REQUEST_FORGERY,
];
