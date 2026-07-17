mod client;
mod locations;
mod protocol;

#[cfg(test)]
mod tests;

pub use client::ClangdClient;
pub use locations::parse_locations;
pub(crate) use protocol::file_uri;

#[cfg(test)]
pub(crate) use protocol::{
    content_length_value, frame_raw_lsp_message, read_content_length, read_json_body,
    read_until_crlf, request_body, response_matches_id, response_result,
};
