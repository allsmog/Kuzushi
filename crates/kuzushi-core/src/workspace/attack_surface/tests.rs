#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::fs;

    use super::super::*;

    #[test]
    fn attack_surface_detects_node_express_boundaries_from_source() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src")).unwrap();
        fs::create_dir_all(temp.path().join("node_modules/express")).unwrap();
        fs::write(
            temp.path().join("package.json"),
            r#"{
              "scripts": {
                "start": "node src/server.ts && touch SHOULD_NOT_EXIST"
              },
              "dependencies": {
                "express": "^4.18.0",
                "multer": "^1.4.5",
                "graphql": "^16.0.0"
              }
            }"#,
        )
        .unwrap();
        fs::write(
            temp.path().join("src/server.ts"),
            r#"
              import express from 'express';
              import multer from 'multer';
              import { exec } from 'child_process';
              const app = express();
              const upload = multer();
              app.use('/admin', requireAuth);
              app.post('/upload', requireAuth, upload.single('file'), (req, res) => {
                const parsed = JSON.parse(req.body.metadata);
                db.query(`select * from users where name = ${req.query.name}`);
                exec(req.query.cmd);
                res.json(parsed);
              });
              app.post('/graphql', graphqlHTTP({ schema }));
              app.post('/proxy', async (req, res) => fetch(req.body.url));
              app.post('/session', (req, res) => { req.session.user = req.body.user; res.cookie('sid', req.session.id); });
              app.use(csurf());
              const tenantId = req.user.tenantId;
              cron.schedule('* * * * *', runJob);
              const args = process.argv.slice(2);
            "#,
        )
        .unwrap();
        fs::write(
            temp.path().join("node_modules/express/index.js"),
            "module.exports = {}\n",
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();
        assert!(!temp.path().join("SHOULD_NOT_EXIST").exists());

        assert_has_kind(&map, AttackSurfaceKind::HttpRoute);
        assert_has_kind(&map, AttackSurfaceKind::RpcHandler);
        assert_has_kind(&map, AttackSurfaceKind::CliEntrypoint);
        assert_has_kind(&map, AttackSurfaceKind::BackgroundJob);
        assert_has_kind(&map, AttackSurfaceKind::DeserializationPoint);
        assert_has_kind(&map, AttackSurfaceKind::FileUploadParsePath);
        assert_has_kind(&map, AttackSurfaceKind::ExternalServiceClient);
        assert_has_kind(&map, AttackSurfaceKind::AuthBoundary);
        assert_has_kind(&map, AttackSurfaceKind::SessionStateBoundary);
        assert_has_kind(&map, AttackSurfaceKind::RequestTrustBoundary);
        assert_has_kind(&map, AttackSurfaceKind::TenantIsolationBoundary);
        assert_has_kind(&map, AttackSurfaceKind::DbQueryBoundary);
        assert_has_kind(&map, AttackSurfaceKind::CommandExecutionBoundary);

        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.method.as_deref() == Some("POST")
                && surface.route.as_deref() == Some("/upload")
                && surface.framework.as_deref() == Some("Express")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::RpcHandler
                && surface.route.as_deref() == Some("/graphql")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::SessionStateBoundary
                && surface
                    .metadata
                    .pointer("/detector")
                    .and_then(Value::as_str)
                    == Some("node.session-state")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::RequestTrustBoundary
                && surface
                    .metadata
                    .pointer("/detector")
                    .and_then(Value::as_str)
                    == Some("node.request-trust")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::TenantIsolationBoundary
                && surface
                    .metadata
                    .pointer("/detector")
                    .and_then(Value::as_str)
                    == Some("node.tenant-isolation")
        }));
        assert!(map
            .surfaces
            .iter()
            .all(|surface| !surface.path.starts_with("node_modules/")));
        assert!(map.summary.high_risk > 0);
        assert_eq!(map.summary.max_risk_score, 100);
        assert_eq!(
            map.summary
                .by_risk_tier
                .values()
                .copied()
                .sum::<usize>(),
            map.summary.total
        );
        assert_ranked_by_risk(&map);
    }

    #[test]
    fn attack_surface_detects_python_and_go_security_boundaries() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("svc")).unwrap();
        fs::write(
            temp.path().join("svc/app.py"),
            r#"
              @login_required
              @csrf_protect
              def handler(request):
                  request.session["user"] = request.user
                  Project.objects.filter(tenant_id=request.user.tenant_id)
                  yaml.load(request.body)
                  cursor.execute("select * from users")
                  requests.post(request.GET["url"], json={})
                  subprocess.call(request.GET["cmd"], shell=True)
            "#,
        )
        .unwrap();
        fs::write(
            temp.path().join("svc/main.go"),
            r#"
              package main
              func handler() {
                  authorize(user)
                  session.Get("user")
                  csrf.Protect(authKey)
                  db.Where("tenant_id = ?", user.TenantID)
                  json.NewDecoder(r.Body).Decode(&payload)
                  db.Query("select * from users")
                  http.Get(input)
                  exec.Command("sh", "-c", input)
              }
            "#,
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();

        assert!(map.surfaces.iter().any(|surface| {
            surface.path.ends_with("app.py")
                && surface
                    .metadata
                    .pointer("/detector")
                    .and_then(Value::as_str)
                    == Some("python.command-exec")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.path.ends_with("main.go")
                && surface
                    .metadata
                    .pointer("/detector")
                    .and_then(Value::as_str)
                    == Some("go.deserialization")
        }));
        assert_has_kind(&map, AttackSurfaceKind::AuthBoundary);
        assert_has_kind(&map, AttackSurfaceKind::SessionStateBoundary);
        assert_has_kind(&map, AttackSurfaceKind::RequestTrustBoundary);
        assert_has_kind(&map, AttackSurfaceKind::TenantIsolationBoundary);
        assert_has_kind(&map, AttackSurfaceKind::DbQueryBoundary);
        assert_has_kind(&map, AttackSurfaceKind::ExternalServiceClient);
        assert_has_kind(&map, AttackSurfaceKind::CommandExecutionBoundary);
    }

    #[test]
    fn node_sink_boundaries_keep_inline_route_context() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src")).unwrap();
        fs::write(
            temp.path().join("package.json"),
            r#"{"dependencies":{"express":"^4.18.0"}}"#,
        )
        .unwrap();
        fs::write(
            temp.path().join("src/routes.ts"),
            r#"
              import express from 'express';
              import { exec } from 'child_process';
              const app = express();
              app.post('/admin/query', (req, res) => db.query(req.body.sql));
              app.post('/admin/import', (req, res) => JSON.parse(req.body.payload));
              app.post('/admin/run', (req, res) => exec(req.body.cmd));
            "#,
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();

        assert_surface_route(&map, AttackSurfaceKind::DbQueryBoundary, "/admin/query");
        assert_surface_route(
            &map,
            AttackSurfaceKind::DeserializationPoint,
            "/admin/import",
        );
        assert_surface_route(
            &map,
            AttackSurfaceKind::CommandExecutionBoundary,
            "/admin/run",
        );
    }

    #[test]
    fn attack_surface_detects_rust_external_clients() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src")).unwrap();
        fs::write(
            temp.path().join("src/lib.rs"),
            r#"
              async fn call(url: &str) {
                  let _ = reqwest::get(url).await;
                  let _ = session.get::<String>("user");
                  let _ = CorsLayer::new();
                  let _ = query.filter(tenant_id.eq(user.tenant_id));
              }
            "#,
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();

        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::ExternalServiceClient
                && surface
                    .metadata
                    .pointer("/detector")
                    .and_then(Value::as_str)
                    == Some("rust.external-client")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::SessionStateBoundary
                && surface
                    .metadata
                    .pointer("/detector")
                    .and_then(Value::as_str)
                    == Some("rust.session-state")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::RequestTrustBoundary
                && surface
                    .metadata
                    .pointer("/detector")
                    .and_then(Value::as_str)
                    == Some("rust.request-trust")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::TenantIsolationBoundary
                && surface
                    .metadata
                    .pointer("/detector")
                    .and_then(Value::as_str)
                    == Some("rust.tenant-isolation")
        }));
    }

    #[test]
    fn attack_surface_map_is_deterministic_and_summarized() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src")).unwrap();
        fs::write(
            temp.path().join("package.json"),
            r#"{"dependencies":{"express":"^4.18.0"}}"#,
        )
        .unwrap();
        fs::write(
            temp.path().join("src/api.ts"),
            "import express from 'express';\nconst app = express();\napp.get('/a', requireAuth, handler);\nJSON.parse(req.body.payload);\n",
        )
        .unwrap();

        let first = build_attack_surface_map(temp.path()).unwrap();
        let second = build_attack_surface_map(temp.path()).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.summary.total, first.surfaces.len());
        assert_eq!(
            first.summary.high_risk,
            first
                .surfaces
                .iter()
                .filter(|surface| matches!(surface.risk.tier.as_str(), "critical" | "high"))
                .count()
        );
        assert_eq!(
            first.summary.by_risk_tier.get("medium"),
            Some(
                &first
                    .surfaces
                    .iter()
                    .filter(|surface| surface.risk.tier == "medium")
                    .count()
            )
        );
        assert_eq!(first.surfaces.first().map(|surface| surface.risk.rank), Some(1));
        assert_ranked_by_risk(&first);
        assert_eq!(
            first.summary.by_kind.get("http_route"),
            Some(&1),
            "{:?}",
            first.summary
        );

        let ids = first
            .surfaces
            .iter()
            .map(|surface| surface.id.as_str())
            .collect::<BTreeSet<_>>();
        assert_eq!(ids.len(), first.surfaces.len());
    }

    fn assert_has_kind(map: &AttackSurfaceMap, kind: AttackSurfaceKind) {
        assert!(
            map.surfaces.iter().any(|surface| surface.kind == kind),
            "missing {kind:?} in {:#?}",
            map.surfaces
        );
        assert!(
            map.summary.by_kind.contains_key(kind.as_str()),
            "summary missing {kind:?}: {:?}",
            map.summary
        );
    }

    fn assert_ranked_by_risk(map: &AttackSurfaceMap) {
        for (index, surface) in map.surfaces.iter().enumerate() {
            assert_eq!(surface.risk.rank, index + 1);
        }
        for pair in map.surfaces.windows(2) {
            assert!(
                pair[0].risk.score >= pair[1].risk.score,
                "attack surfaces are not risk sorted: {:#?}",
                map.surfaces
            );
        }
    }

    fn assert_surface_route(map: &AttackSurfaceMap, kind: AttackSurfaceKind, route: &str) {
        let surface = map
            .surfaces
            .iter()
            .find(|surface| surface.kind == kind && surface.route.as_deref() == Some(route))
            .unwrap_or_else(|| panic!("missing {kind:?} for {route} in {:#?}", map.surfaces));
        assert_eq!(surface.method.as_deref(), Some("POST"));
        assert!(surface
            .risk
            .reasons
            .contains(&"route touches auth or admin workflow".to_string()));
    }
}
