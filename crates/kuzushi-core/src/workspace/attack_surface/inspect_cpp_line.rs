use super::*;

pub(crate) fn inspect_cpp_line(
    source_file: &InventorySourceFile,
    framework: Option<&str>,
    line_number: u32,
    line: &str,
    builder: &mut AttackSurfaceBuilder,
) {
    let detail = trim_detail(line);
    if is_cpp_preprocessor_or_comment_line(&detail) {
        return;
    }
    let lower = detail.to_ascii_lowercase();
    for detector in CPP_LINE_DETECTORS {
        if detector.matches(&lower) {
            builder.add(detector.surface(source_file, framework, line_number, &detail));
        }
    }
}

fn is_cpp_preprocessor_or_comment_line(line: &str) -> bool {
    let trimmed = line.trim_start();
    trimmed.starts_with('#') || trimmed.starts_with("//") || trimmed.starts_with('*')
}

struct CppLineDetector {
    kind: AttackSurfaceKind,
    title: &'static str,
    boundary: &'static str,
    detector: &'static str,
    needles: &'static [&'static str],
}

impl CppLineDetector {
    fn matches(&self, line: &str) -> bool {
        line_contains_any(line, self.needles)
    }

    fn surface(
        &self,
        source_file: &InventorySourceFile,
        framework: Option<&str>,
        line_number: u32,
        detail: &str,
    ) -> AttackSurfaceDraft {
        surface(
            self.kind,
            source_file,
            framework,
            line_number,
            self.title,
            detail,
            None,
            None,
            Some(self.boundary),
            json!({ "source": "source_line", "detector": self.detector }),
        )
    }
}

const CPP_LINE_DETECTORS: &[CppLineDetector] = &[
    CppLineDetector {
        kind: AttackSurfaceKind::RpcHandler,
        title: "RPC service host",
        boundary: "rpc_handler",
        detector: "cpp.rpc-handler",
        needles: &[
            "tsimpleserver",
            "tthreadedserver",
            "tthreadpoolserver",
            "tnonblockingserver",
            "tprocessor",
            "tmultiplexedprocessor",
            "tserversocket",
            "grpc::serverbuilder",
            "addlisteningport",
            "registerservice(",
        ],
    },
    CppLineDetector {
        kind: AttackSurfaceKind::RequestTrustBoundary,
        title: "Network listener",
        boundary: "request_trust",
        detector: "cpp.network-listener",
        needles: &[
            "listen(",
            "accept4(",
            "::accept(",
            "recvfrom(",
            "evhttp_bind_socket",
            "tcp::acceptor",
        ],
    },
    CppLineDetector {
        kind: AttackSurfaceKind::CommandExecutionBoundary,
        title: "Process execution boundary",
        boundary: "command_execution",
        detector: "cpp.command-execution",
        needles: &[
            "::system(",
            " system(",
            "popen(",
            "execl(",
            "execlp(",
            "execle(",
            "execv(",
            "execvp(",
            "execve(",
            "posix_spawn",
        ],
    },
    CppLineDetector {
        kind: AttackSurfaceKind::DeserializationPoint,
        title: "Deserialization or parser boundary",
        boundary: "parser_boundary",
        detector: "cpp.deserialization",
        needles: &[
            "parsefromarray",
            "parsefromstring",
            "parsefromistream",
            "json::parse",
            "rapidjson",
            "deserialize(",
            "tbinaryprotocol",
            "tcompactprotocol",
        ],
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    fn cpp_source_file() -> InventorySourceFile {
        InventorySourceFile {
            path: "src/cpp/agent/server_main.cpp".to_string(),
            language: "C++".to_string(),
        }
    }

    fn detect(line: &str) -> Vec<AttackSurfaceKind> {
        let mut builder = AttackSurfaceBuilder::default();
        inspect_cpp_line(&cpp_source_file(), None, 7, line, &mut builder);
        builder.surfaces.values().map(|s| s.kind).collect()
    }

    #[test]
    fn thrift_server_and_exec_lines_become_surfaces() {
        assert_eq!(
            detect("TThreadedServer server(processor, transport, tf, pf);"),
            vec![AttackSurfaceKind::RpcHandler]
        );
        assert_eq!(
            detect("int rc = ::system(cmd.c_str());"),
            vec![AttackSurfaceKind::CommandExecutionBoundary]
        );
        assert_eq!(
            detect("if (listen(fd, SOMAXCONN) < 0) {"),
            vec![AttackSurfaceKind::RequestTrustBoundary]
        );
        assert_eq!(
            detect("request.ParseFromArray(buf.data(), buf.size());"),
            vec![AttackSurfaceKind::DeserializationPoint]
        );
    }

    #[test]
    fn filesystem_calls_and_preprocessor_lines_stay_quiet() {
        assert!(detect("auto fs = getFilesystem(path);").is_empty());
        assert!(detect("#include <cstdlib> // system(3)").is_empty());
        assert!(detect("// call system( only when sandboxed").is_empty());
    }
}
