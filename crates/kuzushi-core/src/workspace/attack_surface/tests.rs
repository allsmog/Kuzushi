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
        assert_has_kind(&map, AttackSurfaceKind::AuthBoundary);
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
        assert!(map
            .surfaces
            .iter()
            .all(|surface| !surface.path.starts_with("node_modules/")));
    }

    #[test]
    fn attack_surface_detects_python_and_go_security_boundaries() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("svc")).unwrap();
        fs::write(
            temp.path().join("svc/app.py"),
            r#"
              @login_required
              def handler(request):
                  yaml.load(request.body)
                  cursor.execute("select * from users")
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
                  json.NewDecoder(r.Body).Decode(&payload)
                  db.Query("select * from users")
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
        assert_has_kind(&map, AttackSurfaceKind::DbQueryBoundary);
        assert_has_kind(&map, AttackSurfaceKind::CommandExecutionBoundary);
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
}
