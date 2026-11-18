//! The filesystem path an upstream tool reported a location as a URI for.
//!
//! An MCP server's answer is the path the agent opens next: it reads the file
//! to judge a candidate, and the tools it chains to (`tree_sitter:node_at`,
//! `cpg.method_at`) take a path. A URI is not one. RFC 3986 lets no byte
//! outside the unreserved set stand in a reference, so every producer we read
//! escapes an ordinary file name: clangd answers `textDocument/definition`
//! with `file:///tmp/a%20b.c`, and `codeql database analyze` writes
//! `src/caf%C3%A9.rs` in `artifactLocation.uri`. Handing either string on as a
//! path names no file — nothing can open it, and the agent has no way to see
//! that the name it was given is not the name of the file the engine found.
//!
//! This is the one reading both servers use. `kuzushi-mcp-clang` already
//! encodes its own outgoing URIs with `url::Url::from_file_path`, so a `file:`
//! URI reads back through that crate's inverse rather than through a second
//! hand-written parser.

use percent_encoding::percent_decode_str;
use url::Url;

/// The path a tool-reported URI names, or `None` when it names none.
///
/// `None` means the caller skips the location rather than reporting a name
/// that names nothing: both call sites already collect with `filter_map`, and
/// a dropped step is honest where a fabricated path is not.
///
/// - A `file:` URI reads back through [`Url::to_file_path`], the inverse of
///   the `Url::from_file_path` encoder `kuzushi-mcp-clang` uses for the URIs
///   it sends, and its reading is the platform's own: a URI naming a non-local
///   host (`file://build01/share.c`) is a UNC path on Windows and `None`
///   elsewhere, and a URI with no Windows drive letter is `None` on Windows.
/// - Any other scheme is returned verbatim. It names an identifier rather than
///   a path, and decoding it would rewrite it: `%2F` inside a query string is
///   not a separator.
/// - A relative reference — what CodeQL writes for every result inside the
///   analyzed source tree — is percent-decoded. It stays relative, because the
///   root it resolves against is the caller's to name.
/// - A reference that decodes to bytes that are not UTF-8 is `None`. A path
///   holding U+FFFD names a different file than the one the tool found, and
///   these answers travel as JSON strings, so there is no honest third option.
/// A single-letter scheme is read as a Windows drive letter rather than a
/// scheme: `C:/src/a.c` is a path a non-conformant producer wrote, and reading
/// it as a scheme would skip the decoding its escapes need.
pub fn reported_path(uri: &str) -> Option<String> {
    match Url::parse(uri) {
        Ok(url) if url.scheme() == "file" => local_file_path(&url),
        Ok(url) if url.scheme().len() > 1 => Some(uri.to_string()),
        _ => non_empty(percent_decode_str(uri).decode_utf8().ok()?.into_owned()),
    }
}

fn local_file_path(url: &Url) -> Option<String> {
    let path = url.to_file_path().ok()?;
    // `Url` normalizes an empty path to the root, so `file://` would otherwise
    // read back as `/`. A URI naming no file name names no location.
    path.file_name()?;
    non_empty(path.to_str()?.to_string())
}

fn non_empty(path: String) -> Option<String> {
    (!path.is_empty()).then_some(path)
}

#[cfg(test)]
mod tests;
