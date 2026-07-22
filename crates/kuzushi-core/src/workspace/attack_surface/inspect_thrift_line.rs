use super::*;

/// Thrift IDL files declare the RPC surface a service exposes before any
/// handler code exists, so each `service` declaration is itself a
/// ground-truth entry-point row.
pub(crate) fn inspect_thrift_line(
    source_file: &InventorySourceFile,
    framework: Option<&str>,
    line_number: u32,
    line: &str,
    builder: &mut AttackSurfaceBuilder,
) {
    let Some(service_name) = thrift_service_name(line) else {
        return;
    };
    builder.add(surface(
        AttackSurfaceKind::RpcHandler,
        source_file,
        framework,
        line_number,
        &format!("Thrift service {service_name}"),
        &trim_detail(line),
        None,
        None,
        Some("rpc_handler"),
        json!({ "source": "source_line", "detector": "thrift.service" }),
    ));
}

fn thrift_service_name(line: &str) -> Option<String> {
    let rest = line.trim_start().strip_prefix("service ")?;
    let name: String = rest
        .trim_start()
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect();
    (!name.is_empty()).then_some(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn thrift_source_file() -> InventorySourceFile {
        InventorySourceFile {
            path: "src/thrift/agent.thrift".to_string(),
            language: "Thrift".to_string(),
        }
    }

    #[test]
    fn service_declarations_become_rpc_handler_rows() {
        let mut builder = AttackSurfaceBuilder::default();
        inspect_thrift_line(
            &thrift_source_file(),
            None,
            3,
            "service AgentService extends BaseService {",
            &mut builder,
        );
        let surface = builder.surfaces.values().next().expect("one surface");
        assert_eq!(surface.kind, AttackSurfaceKind::RpcHandler);
        assert!(surface.title.contains("AgentService"));
    }

    #[test]
    fn structs_and_comments_stay_quiet() {
        let mut builder = AttackSurfaceBuilder::default();
        for line in [
            "struct SnapshotSpec {",
            "// service disabled",
            "  1: required string serviceName,",
        ] {
            inspect_thrift_line(&thrift_source_file(), None, 1, line, &mut builder);
        }
        assert!(builder.surfaces.is_empty());
    }
}
