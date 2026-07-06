#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::fs;

    use super::super::*;

    #[test]
    fn attack_surface_splits_aspnet_inventory_multi_method_routes() {
        let mut builder = AttackSurfaceBuilder::default();
        add_route_surface(
            &mut builder,
            &InventoryRouteController {
                kind: "route".to_string(),
                path: "Program.cs".to_string(),
                line: Some(1),
                method: Some("TRACE,CONNECT".to_string()),
                route: Some("/imports/tunnel".to_string()),
                framework: Some("ASP.NET Core".to_string()),
                detail: "app.MapMethods".to_string(),
            },
        );

        let map = builder.finish("demo".to_string());

        assert!(map.surfaces.iter().any(|surface| {
            surface.method.as_deref() == Some("TRACE")
                && surface.route.as_deref() == Some("/imports/tunnel")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.method.as_deref() == Some("CONNECT")
                && surface.route.as_deref() == Some("/imports/tunnel")
        }));
        assert!(map
            .surfaces
            .iter()
            .all(|surface| surface.method.as_deref() != Some("TRACE,CONNECT")));
    }

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
              app.get('/realtime/socket', websocketHandler);
              app.post('/proxy', async (req, res) => fetch(req.body.url));
              app.post('/session', (req, res) => { req.session.user = req.body.user; res.cookie('sid', req.session.id); });
              app.use(csurf());
              const tenantId = req.user.tenantId;
              const teamScope = db.projects.where({ teamId: req.user.currentTeam.id });
              cron.schedule('* * * * *', runJob);
              kafka.consumer({ groupId: 'billing' }).run({ eachMessage });
              pubsub.subscription('tenant-events').on('message', handleTenantEvent);
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
            surface.kind == AttackSurfaceKind::RpcHandler
                && surface.route.as_deref() == Some("/realtime/socket")
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
                && surface.evidence.contains("currentTeam")
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
            map.summary.by_risk_tier.values().copied().sum::<usize>(),
            map.summary.total
        );
        assert_ranked_by_risk(&map);
    }

    #[test]
    fn attack_surface_promotes_nextjs_route_files() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/app/api/admin/[userId]")).unwrap();
        fs::create_dir_all(temp.path().join("src/app/api/health")).unwrap();
        fs::create_dir_all(temp.path().join("src/app/api/teams/projects")).unwrap();
        fs::create_dir_all(temp.path().join("pages/api/webhooks")).unwrap();
        fs::write(
            temp.path().join("package.json"),
            r#"{"dependencies":{"next":"14.0.0"}}"#,
        )
        .unwrap();
        fs::write(
            temp.path().join("src/app/api/admin/[userId]/route.ts"),
            "import { NextRequest, NextResponse } from 'next/server';\nexport async function POST(request: NextRequest) { const sid = request.cookies.get('sid'); return NextResponse.json({ sid }); }\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("src/app/api/health/route.ts"),
            "export function HEAD() { return new Response(null); }\nexport const OPTIONS = () => Response.json({ ok: true });\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("src/app/api/teams/projects/route.ts"),
            "import { NextRequest } from 'next/server';\nexport async function POST(request: NextRequest) { const teamScope = db.projects.where({ teamId: request.user.currentTeam.id }); return Response.json({ ok: true, teamScope }); }\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("pages/api/webhooks/[...slug].ts"),
            "export default function handler(req, res) { res.json({ ok: true }); }\n",
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();

        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.method.as_deref() == Some("POST")
                && surface.route.as_deref() == Some("/api/admin/:userId")
                && surface.framework.as_deref() == Some("Next.js")
                && surface
                    .risk
                    .reasons
                    .contains(&"mutating request method".to_string())
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.method.as_deref() == Some("HEAD")
                && surface.route.as_deref() == Some("/api/health")
                && surface.framework.as_deref() == Some("Next.js")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.method.as_deref() == Some("OPTIONS")
                && surface.route.as_deref() == Some("/api/health")
                && surface.framework.as_deref() == Some("Next.js")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.method.as_deref() == Some("ANY")
                && surface.route.as_deref() == Some("/api/webhooks/:slug")
                && surface.framework.as_deref() == Some("Next.js")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::SessionStateBoundary
                && surface.framework.as_deref() == Some("Next.js")
                && surface.evidence.contains("request.cookies.get")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::TenantIsolationBoundary
                && surface.framework.as_deref() == Some("Next.js")
                && surface.evidence.contains("currentTeam")
                && surface
                    .metadata
                    .pointer("/detector")
                    .and_then(Value::as_str)
                    == Some("node.tenant-isolation")
        }));
    }

    #[test]
    fn attack_surface_promotes_nestjs_decorator_routes_and_tenant_boundaries() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src")).unwrap();
        fs::write(
            temp.path().join("package.json"),
            r#"{"dependencies":{"@nestjs/common":"^10.0.0"}}"#,
        )
        .unwrap();
        fs::write(
            temp.path().join("src/projects.controller.ts"),
            "import { AuthGuard, Controller, Post, UseGuards } from '@nestjs/common';\n@Controller('teams')\nexport class ProjectsController {\n  @UseGuards(AuthGuard('jwt'))\n  @Post('/teams/projects')\n  createProject(req) { const teamScope = this.projects.where({ teamId: req.user.currentTeam.id }); return teamScope; }\n}\n",
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();

        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.method.as_deref() == Some("POST")
                && surface.route.as_deref() == Some("/teams/projects")
                && surface.framework.as_deref() == Some("NestJS")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::AuthBoundary
                && surface.framework.as_deref() == Some("NestJS")
                && surface.evidence.contains("UseGuards")
                && surface
                    .metadata
                    .pointer("/detector")
                    .and_then(Value::as_str)
                    == Some("node.auth-guard")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::TenantIsolationBoundary
                && surface.framework.as_deref() == Some("NestJS")
                && surface.evidence.contains("currentTeam")
                && surface
                    .metadata
                    .pointer("/detector")
                    .and_then(Value::as_str)
                    == Some("node.tenant-isolation")
        }));
    }

    #[test]
    fn attack_surface_promotes_koa_router_routes_and_tenant_boundaries() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src")).unwrap();
        fs::write(
            temp.path().join("package.json"),
            r#"{"dependencies":{"koa":"^2.15.0","@koa/router":"^12.0.0"}}"#,
        )
        .unwrap();
        fs::write(
            temp.path().join("src/server.ts"),
            "import Koa from 'koa';\nimport Router from '@koa/router';\nconst router = new Router();\nrouter.post('/teams/projects', createProject);\nasync function createProject(ctx) { const teamScope = db.projects.where({ teamId: ctx.state.user.currentTeam.id }); ctx.body = teamScope; }\n",
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();

        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.method.as_deref() == Some("POST")
                && surface.route.as_deref() == Some("/teams/projects")
                && surface.framework.as_deref() == Some("Koa")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::TenantIsolationBoundary
                && surface.framework.as_deref() == Some("Koa")
                && surface.evidence.contains("currentTeam")
                && surface
                    .metadata
                    .pointer("/detector")
                    .and_then(Value::as_str)
                    == Some("node.tenant-isolation")
        }));
    }

    #[test]
    fn attack_surface_promotes_fastify_routes_and_tenant_boundaries() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src")).unwrap();
        fs::write(
            temp.path().join("package.json"),
            r#"{"dependencies":{"fastify":"^4.26.0"}}"#,
        )
        .unwrap();
        fs::write(
            temp.path().join("src/server.ts"),
            "import fastify from 'fastify';\nconst app = fastify();\napp.post('/teams/projects', createProject);\nasync function createProject(request, reply) { const teamScope = db.projects.where({ teamId: request.user.currentTeam.id }); return reply.send(teamScope); }\n",
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();

        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.method.as_deref() == Some("POST")
                && surface.route.as_deref() == Some("/teams/projects")
                && surface.framework.as_deref() == Some("Fastify")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::TenantIsolationBoundary
                && surface.framework.as_deref() == Some("Fastify")
                && surface.evidence.contains("currentTeam")
                && surface
                    .metadata
                    .pointer("/detector")
                    .and_then(Value::as_str)
                    == Some("node.tenant-isolation")
        }));
    }

    #[test]
    fn attack_surface_promotes_hono_routes_and_tenant_boundaries() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src")).unwrap();
        fs::write(
            temp.path().join("package.json"),
            r#"{"dependencies":{"hono":"^4.3.0"}}"#,
        )
        .unwrap();
        fs::write(
            temp.path().join("src/server.ts"),
            "import { Hono } from 'hono';\nconst app = new Hono();\napp.post('/teams/projects', createProject);\nasync function createProject(c) { const teamScope = db.projects.where({ teamId: c.get('user').currentTeam.id }); return c.json(teamScope); }\n",
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();

        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.method.as_deref() == Some("POST")
                && surface.route.as_deref() == Some("/teams/projects")
                && surface.framework.as_deref() == Some("Hono")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::TenantIsolationBoundary
                && surface.framework.as_deref() == Some("Hono")
                && surface.evidence.contains("currentTeam")
                && surface
                    .metadata
                    .pointer("/detector")
                    .and_then(Value::as_str)
                    == Some("node.tenant-isolation")
        }));
    }

    #[test]
    fn attack_surface_promotes_elysia_routes_and_tenant_boundaries() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src")).unwrap();
        fs::write(
            temp.path().join("package.json"),
            r#"{"dependencies":{"elysia":"^1.1.0"}}"#,
        )
        .unwrap();
        fs::write(
            temp.path().join("src/server.ts"),
            "import { Elysia } from 'elysia';\nconst app = new Elysia();\napp.post('/teams/projects', createProject);\nasync function createProject({ user }) { const teamScope = db.projects.where({ teamId: user.currentTeam.id }); return teamScope; }\n",
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();

        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.method.as_deref() == Some("POST")
                && surface.route.as_deref() == Some("/teams/projects")
                && surface.framework.as_deref() == Some("Elysia")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::TenantIsolationBoundary
                && surface.framework.as_deref() == Some("Elysia")
                && surface.evidence.contains("currentTeam")
                && surface
                    .metadata
                    .pointer("/detector")
                    .and_then(Value::as_str)
                    == Some("node.tenant-isolation")
        }));
    }

    #[test]
    fn attack_surface_detects_python_and_go_security_boundaries() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("svc")).unwrap();
        fs::write(
            temp.path().join("svc/app.py"),
            r#"
              api_key_header = APIKeyHeader(name="X-API-Key")
              @login_required
              @jwt_required()
              @permission_classes([IsAuthenticated])
              @csrf_protect
              def handler(request, user=Depends(get_current_user)):
                  parser_classes = [MultiPartParser]
                  request.session["user"] = request.user
                  Project.objects.filter(tenant_id=request.user.tenant_id)
                  Project.objects.filter(organization=request.user.organization)
                  yaml.load(request.body)
                  file: UploadFile = File(...)
                  cursor.execute("select * from users")
                  requests.post(request.GET["url"], json={})
                  subprocess.call(request.GET["cmd"], shell=True)
                  kafka.consumer.KafkaConsumer("tenant-events")
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
                  db.Where("team_id = ?", claims.TeamID)
                  json.NewDecoder(r.Body).Decode(&payload)
                  r.ParseMultipartForm(32 << 20)
                  r.FormFile("import")
                  db.Query("select * from users")
                  http.Get(input)
                  exec.Command("sh", "-c", input)
                  reader.ReadMessage(ctx)
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
            surface.path.ends_with("app.py")
                && surface.evidence.contains("permission_classes")
                && surface
                    .metadata
                    .pointer("/detector")
                    .and_then(Value::as_str)
                    == Some("python.auth-guard")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.path.ends_with("app.py")
                && surface.evidence.contains("Depends(get_current_user)")
                && surface
                    .metadata
                    .pointer("/detector")
                    .and_then(Value::as_str)
                    == Some("python.auth-guard")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.path.ends_with("app.py")
                && surface.evidence.contains("APIKeyHeader")
                && surface
                    .metadata
                    .pointer("/detector")
                    .and_then(Value::as_str)
                    == Some("python.auth-guard")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.path.ends_with("app.py")
                && surface.evidence.contains("jwt_required")
                && surface
                    .metadata
                    .pointer("/detector")
                    .and_then(Value::as_str)
                    == Some("python.auth-guard")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.path.ends_with("app.py")
                && surface.evidence.contains("UploadFile")
                && surface.kind == AttackSurfaceKind::FileUploadParsePath
                && surface
                    .metadata
                    .pointer("/detector")
                    .and_then(Value::as_str)
                    == Some("python.file-upload")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.path.ends_with("app.py")
                && surface.evidence.contains("MultiPartParser")
                && surface.kind == AttackSurfaceKind::FileUploadParsePath
                && surface
                    .metadata
                    .pointer("/detector")
                    .and_then(Value::as_str)
                    == Some("python.file-upload")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.path.ends_with("main.go")
                && surface
                    .metadata
                    .pointer("/detector")
                    .and_then(Value::as_str)
                    == Some("go.deserialization")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.path.ends_with("main.go")
                && surface.kind == AttackSurfaceKind::FileUploadParsePath
                && surface
                    .metadata
                    .pointer("/detector")
                    .and_then(Value::as_str)
                    == Some("go.file-upload")
        }));
        assert_has_kind(&map, AttackSurfaceKind::AuthBoundary);
        assert_has_kind(&map, AttackSurfaceKind::SessionStateBoundary);
        assert_has_kind(&map, AttackSurfaceKind::RequestTrustBoundary);
        assert_has_kind(&map, AttackSurfaceKind::TenantIsolationBoundary);
        assert!(map.surfaces.iter().any(|surface| {
            surface.path.ends_with("app.py")
                && surface.kind == AttackSurfaceKind::TenantIsolationBoundary
                && surface.evidence.contains("request.user.organization")
                && surface
                    .metadata
                    .pointer("/detector")
                    .and_then(Value::as_str)
                    == Some("python.tenant-isolation")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.path.ends_with("main.go")
                && surface.kind == AttackSurfaceKind::TenantIsolationBoundary
                && surface.evidence.contains("claims.TeamID")
                && surface
                    .metadata
                    .pointer("/detector")
                    .and_then(Value::as_str)
                    == Some("go.tenant-isolation")
        }));
        assert_has_kind(&map, AttackSurfaceKind::DbQueryBoundary);
        assert_has_kind(&map, AttackSurfaceKind::ExternalServiceClient);
        assert_has_kind(&map, AttackSurfaceKind::CommandExecutionBoundary);
        assert_has_kind(&map, AttackSurfaceKind::BackgroundJob);
        assert!(map.surfaces.iter().any(|surface| {
            surface.path.ends_with("app.py")
                && surface
                    .metadata
                    .pointer("/detector")
                    .and_then(Value::as_str)
                    == Some("python.background-job")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.path.ends_with("main.go")
                && surface
                    .metadata
                    .pointer("/detector")
                    .and_then(Value::as_str)
                    == Some("go.background-job")
        }));
    }

    #[test]
    fn attack_surface_ignores_python_import_only_lines() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("svc")).unwrap();
        fs::write(
            temp.path().join("svc/app.py"),
            "from fastapi import Depends, File, UploadFile\nfrom rest_framework.permissions import IsAuthenticated\nimport requests\n",
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();

        assert!(map.surfaces.iter().all(|surface| {
            surface.metadata.pointer("/source").and_then(Value::as_str) != Some("source_line")
        }));
    }

    #[test]
    fn attack_surface_ignores_import_only_lines_for_backend_languages() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::create_dir_all(temp.path().join("app/controllers")).unwrap();
        fs::create_dir_all(temp.path().join("app/Http/Controllers")).unwrap();
        fs::write(
            temp.path().join("src/main/java/app/Imports.java"),
            "package app;\nimport org.springframework.web.multipart.MultipartFile;\nimport org.springframework.security.core.context.SecurityContextHolder;\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("app/controllers/imports_controller.rb"),
            "require 'active_storage/engine'\nrequire_relative 'application_controller'\n",
        )
        .unwrap();
        fs::write(
            temp.path()
                .join("app/Http/Controllers/ImportController.php"),
            "<?php\nuse Illuminate\\Http\\UploadedFile;\nuse Illuminate\\Support\\Facades\\Http;\n",
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();

        assert!(map.surfaces.iter().all(|surface| {
            surface.metadata.pointer("/source").and_then(Value::as_str) != Some("source_line")
        }));
    }

    #[test]
    fn attack_surface_ignores_go_and_rust_import_only_lines() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("svc")).unwrap();
        fs::write(
            temp.path().join("svc/main.go"),
            "package main\nimport \"mime/multipart\"\nimport \"google.golang.org/grpc\"\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("svc/lib.rs"),
            "use axum::extract::Multipart;\nuse tonic::transport::Server;\nmod uploads;\n",
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();

        assert!(map.surfaces.iter().all(|surface| {
            surface.metadata.pointer("/source").and_then(Value::as_str) != Some("source_line")
        }));
    }

    #[test]
    fn attack_surface_ignores_node_import_only_lines() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src")).unwrap();
        fs::write(
            temp.path().join("package.json"),
            r#"{"dependencies":{"express":"^4.18.0","multer":"^1.4.5","graphql":"^16.0.0"}}"#,
        )
        .unwrap();
        fs::write(
            temp.path().join("src/imports.ts"),
            r#"
              import multer from 'multer';
              import { graphqlHTTP } from 'express-graphql';
              const express = require('express');
              const upload = require('multer');
              let fetch = require('node-fetch');
              var WebSocketServer = require('ws').WebSocketServer;
              export { graphqlHTTP };
            "#,
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();

        assert!(map.surfaces.iter().all(|surface| {
            surface.metadata.pointer("/source").and_then(Value::as_str) != Some("source_line")
        }));
    }

    #[test]
    fn attack_surface_detects_go_worker_registrations() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("svc")).unwrap();
        fs::write(
            temp.path().join("go.mod"),
            "module svc\nrequire github.com/hibiken/asynq v0.25.0\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("svc/workers.go"),
            "package svc\nfunc register(handleMux *asynq.ServeMux, router *message.Router) {\nhandleMux.HandleFunc(\"email:send\", sendEmail)\nrouter.AddHandler(\"events\", \"tenant.events\", subscriber, \"processed\", publisher, handleEvent)\n}\n",
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();
        let go_jobs = map
            .surfaces
            .iter()
            .filter(|surface| {
                surface.kind == AttackSurfaceKind::BackgroundJob
                    && surface
                        .metadata
                        .pointer("/detector")
                        .and_then(Value::as_str)
                        == Some("go.background-job")
            })
            .collect::<Vec<_>>();

        assert_eq!(go_jobs.len(), 2, "{:#?}", map.surfaces);
        assert!(go_jobs
            .iter()
            .any(|surface| surface.evidence.contains("HandleFunc")));
        assert!(go_jobs
            .iter()
            .any(|surface| surface.evidence.contains("AddHandler")));
    }

    #[test]
    fn attack_surface_detects_go_and_rust_grpc_handlers() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("svc")).unwrap();
        fs::write(
            temp.path().join("svc/main.go"),
            r#"
              package main
              func main() {
                  server := grpc.NewServer()
                  pb.RegisterGreeterGrpcServer(server, handler)
              }
            "#,
        )
        .unwrap();
        fs::write(
            temp.path().join("svc/server.rs"),
            r#"
              async fn serve() {
                  tonic::transport::Server::builder()
                      .add_service(GreeterServer::new(handler));
              }
            "#,
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();

        assert_detector(&map, "go.grpc-handler");
        assert_detector(&map, "rust.grpc-handler");
        assert_has_kind(&map, AttackSurfaceKind::RpcHandler);
    }

    #[test]
    fn attack_surface_promotes_go_fiber_routes_and_tenant_boundaries() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("svc")).unwrap();
        fs::write(
            temp.path().join("go.mod"),
            "module svc\nrequire github.com/gofiber/fiber/v2 v2.52.0\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("svc/main.go"),
            "package main\nimport \"github.com/gofiber/fiber/v2\"\nfunc main() { app := fiber.New(); app.Post(\"/teams/projects\", createProject) }\nfunc createProject(c *fiber.Ctx) { teamID := claims.TeamID; db.Where(\"team_id = ?\", teamID).Create(&project) }\n",
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();

        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/teams/projects")
                && surface.method.as_deref() == Some("POST")
                && surface.framework.as_deref() == Some("Fiber")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::TenantIsolationBoundary
                && surface.framework.as_deref() == Some("Fiber")
                && surface.evidence.contains("TeamID")
                && surface
                    .metadata
                    .pointer("/detector")
                    .and_then(Value::as_str)
                    == Some("go.tenant-isolation")
        }));
    }

    #[test]
    fn attack_surface_promotes_go_chi_routes_and_tenant_boundaries() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("svc")).unwrap();
        fs::write(
            temp.path().join("go.mod"),
            "module svc\nrequire github.com/go-chi/chi/v5 v5.0.12\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("svc/main.go"),
            "package main\nimport \"github.com/go-chi/chi/v5\"\nfunc main() { r := chi.NewRouter(); r.Post(\"/teams/projects\", createProject) }\nfunc createProject(w http.ResponseWriter, r *http.Request) { teamID := claims.TeamID; db.Where(\"team_id = ?\", teamID).Create(&project) }\n",
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();

        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/teams/projects")
                && surface.method.as_deref() == Some("POST")
                && surface.framework.as_deref() == Some("Chi")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::TenantIsolationBoundary
                && surface.framework.as_deref() == Some("Chi")
                && surface.evidence.contains("TeamID")
                && surface
                    .metadata
                    .pointer("/detector")
                    .and_then(Value::as_str)
                    == Some("go.tenant-isolation")
        }));
    }

    #[test]
    fn attack_surface_promotes_go_echo_routes_and_tenant_boundaries() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("svc")).unwrap();
        fs::write(
            temp.path().join("go.mod"),
            "module svc\nrequire github.com/labstack/echo/v4 v4.12.0\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("svc/main.go"),
            "package main\nimport \"github.com/labstack/echo/v4\"\nfunc main() { e := echo.New(); e.POST(\"/teams/projects\", createProject) }\nfunc createProject(c echo.Context) error { teamID := claims.TeamID; db.Where(\"team_id = ?\", teamID).Create(&project); return nil }\n",
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();

        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/teams/projects")
                && surface.method.as_deref() == Some("POST")
                && surface.framework.as_deref() == Some("Echo")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::TenantIsolationBoundary
                && surface.framework.as_deref() == Some("Echo")
                && surface.evidence.contains("TeamID")
                && surface
                    .metadata
                    .pointer("/detector")
                    .and_then(Value::as_str)
                    == Some("go.tenant-isolation")
        }));
    }

    #[test]
    fn attack_surface_detects_node_trpc_procedure_handlers() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src")).unwrap();
        fs::write(
            temp.path().join("package.json"),
            r#"{"dependencies":{"@trpc/server":"^10.45.0"}}"#,
        )
        .unwrap();
        fs::write(
            temp.path().join("src/projects.router.ts"),
            "export const projectRouter = createTRPCRouter({\n  create: protectedProcedure.mutation(({ ctx }) => db.projects.where({ teamId: ctx.user.currentTeam.id }))\n});\n",
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();

        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::RpcHandler
                && surface.evidence.contains("protectedProcedure")
                && surface
                    .metadata
                    .pointer("/detector")
                    .and_then(Value::as_str)
                    == Some("node.rpc-handler")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::TenantIsolationBoundary
                && surface.evidence.contains("currentTeam")
                && surface
                    .metadata
                    .pointer("/detector")
                    .and_then(Value::as_str)
                    == Some("node.tenant-isolation")
        }));
    }

    #[test]
    fn attack_surface_detects_socket_io_event_handlers() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src")).unwrap();
        fs::write(
            temp.path().join("package.json"),
            r#"{"dependencies":{"socket.io":"^4.7.0"}}"#,
        )
        .unwrap();
        fs::write(
            temp.path().join("src/realtime.ts"),
            "io.on('connection', (socket) => {\n  socket.on('project:create', (payload) => db.projects.where({ teamId: socket.user.currentTeam.id }).create(payload));\n});\n",
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();

        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::RpcHandler
                && surface.evidence.contains("socket.on")
                && surface
                    .metadata
                    .pointer("/detector")
                    .and_then(Value::as_str)
                    == Some("node.rpc-handler")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::TenantIsolationBoundary
                && surface.evidence.contains("currentTeam")
                && surface
                    .metadata
                    .pointer("/detector")
                    .and_then(Value::as_str)
                    == Some("node.tenant-isolation")
        }));
    }

    #[test]
    fn attack_surface_detects_apollo_graphql_server_handlers() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src")).unwrap();
        fs::write(
            temp.path().join("package.json"),
            r#"{"dependencies":{"@apollo/server":"^4.10.0","graphql":"^16.0.0"}}"#,
        )
        .unwrap();
        fs::write(
            temp.path().join("src/graphql.ts"),
            "const resolvers = { Mutation: { createProject: (_parent, args, ctx) => db.projects.where({ teamId: ctx.user.currentTeam.id }).create(args.input) } };\nconst server = new ApolloServer({ typeDefs, resolvers });\n",
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();

        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::RpcHandler
                && surface.evidence.contains("ApolloServer")
                && surface
                    .metadata
                    .pointer("/detector")
                    .and_then(Value::as_str)
                    == Some("node.rpc-handler")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::TenantIsolationBoundary
                && surface.evidence.contains("currentTeam")
                && surface
                    .metadata
                    .pointer("/detector")
                    .and_then(Value::as_str)
                    == Some("node.tenant-isolation")
        }));
    }

    #[test]
    fn attack_surface_detects_graphql_yoga_handlers() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src")).unwrap();
        fs::write(
            temp.path().join("package.json"),
            r#"{"dependencies":{"graphql-yoga":"^5.0.0","graphql":"^16.0.0"}}"#,
        )
        .unwrap();
        fs::write(
            temp.path().join("src/graphql.ts"),
            "const yoga = createYoga({ schema, context: ({ request }) => ({ teamId: request.user.currentTeam.id }) });\n",
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();

        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::RpcHandler
                && surface.evidence.contains("createYoga")
                && surface
                    .metadata
                    .pointer("/detector")
                    .and_then(Value::as_str)
                    == Some("node.rpc-handler")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::TenantIsolationBoundary
                && surface.evidence.contains("currentTeam")
                && surface
                    .metadata
                    .pointer("/detector")
                    .and_then(Value::as_str)
                    == Some("node.tenant-isolation")
        }));
    }

    #[test]
    fn attack_surface_detects_mercurius_graphql_handlers() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src")).unwrap();
        fs::write(
            temp.path().join("package.json"),
            r#"{"dependencies":{"fastify":"^4.0.0","mercurius":"^13.0.0","graphql":"^16.0.0"}}"#,
        )
        .unwrap();
        fs::write(
            temp.path().join("src/server.ts"),
            "fastify.register(mercurius, { schema, resolvers, context: (request) => ({ teamId: request.user.currentTeam.id }) });\n",
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();

        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::RpcHandler
                && surface.evidence.contains("register(mercurius")
                && surface
                    .metadata
                    .pointer("/detector")
                    .and_then(Value::as_str)
                    == Some("node.rpc-handler")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::TenantIsolationBoundary
                && surface.evidence.contains("currentTeam")
                && surface
                    .metadata
                    .pointer("/detector")
                    .and_then(Value::as_str)
                    == Some("node.tenant-isolation")
        }));
    }

    #[test]
    fn attack_surface_detects_nestjs_graphql_resolvers() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src")).unwrap();
        fs::write(
            temp.path().join("package.json"),
            r#"{"dependencies":{"@nestjs/graphql":"^12.0.0","graphql":"^16.0.0"}}"#,
        )
        .unwrap();
        fs::write(
            temp.path().join("src/projects.resolver.ts"),
            "@Resolver(() => Project)\nexport class ProjectResolver {\n  @Mutation(() => Project)\n  createProject(@Context() ctx) { return db.projects.where({ teamId: ctx.user.currentTeam.id }).create(); }\n}\n",
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();

        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::RpcHandler
                && surface.evidence.contains("@Mutation")
                && surface
                    .metadata
                    .pointer("/detector")
                    .and_then(Value::as_str)
                    == Some("node.rpc-handler")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::TenantIsolationBoundary
                && surface.evidence.contains("currentTeam")
                && surface
                    .metadata
                    .pointer("/detector")
                    .and_then(Value::as_str)
                    == Some("node.tenant-isolation")
        }));
    }

    #[test]
    fn attack_surface_detects_bullmq_worker_consumers() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src")).unwrap();
        fs::write(
            temp.path().join("package.json"),
            r#"{"dependencies":{"bullmq":"^5.0.0"}}"#,
        )
        .unwrap();
        fs::write(
            temp.path().join("src/workers.ts"),
            "const worker = new Worker('tenant-events', async job => processTenantEvent(job.data));\n",
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();

        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::BackgroundJob
                && surface.evidence.contains("new Worker")
                && surface
                    .metadata
                    .pointer("/detector")
                    .and_then(Value::as_str)
                    == Some("node.background-job")
        }));
    }

    #[test]
    fn attack_surface_detects_nestjs_queue_processors() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src")).unwrap();
        fs::write(
            temp.path().join("package.json"),
            r#"{"dependencies":{"@nestjs/bullmq":"^10.0.0","bullmq":"^5.0.0"}}"#,
        )
        .unwrap();
        fs::write(
            temp.path().join("src/email.processor.ts"),
            "@Processor('email')\nexport class EmailProcessor {\n  @Process('send')\n  async send(job) { return sendEmail(job.data); }\n}\n",
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();

        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::BackgroundJob
                && surface.evidence.contains("@Processor")
                && surface
                    .metadata
                    .pointer("/detector")
                    .and_then(Value::as_str)
                    == Some("node.background-job")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::BackgroundJob
                && surface.evidence.contains("@Process")
                && surface
                    .metadata
                    .pointer("/detector")
                    .and_then(Value::as_str)
                    == Some("node.background-job")
        }));
    }

    #[test]
    fn attack_surface_detects_node_request_files_uploads() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src")).unwrap();
        fs::write(
            temp.path().join("package.json"),
            r#"{"dependencies":{"express":"^4.18.0","express-fileupload":"^1.4.0"}}"#,
        )
        .unwrap();
        fs::write(
            temp.path().join("src/uploads.ts"),
            "app.post('/imports/file', (req, res) => {\n  const upload = req.files.import;\n  return res.json({ name: upload.name });\n});\napp.post('/avatars/file', (request, response) => response.json(request.files.avatar));\n",
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();
        let upload_surfaces = map
            .surfaces
            .iter()
            .filter(|surface| {
                surface.kind == AttackSurfaceKind::FileUploadParsePath
                    && surface
                        .metadata
                        .pointer("/detector")
                        .and_then(Value::as_str)
                        == Some("node.file-upload")
            })
            .collect::<Vec<_>>();

        assert_eq!(upload_surfaces.len(), 2, "{:#?}", map.surfaces);
        assert!(upload_surfaces
            .iter()
            .any(|surface| surface.evidence.contains("req.files")));
        assert!(upload_surfaces
            .iter()
            .any(|surface| surface.evidence.contains("request.files")));
    }

    #[test]
    fn attack_surface_detects_python_worker_decorators() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("svc")).unwrap();
        fs::write(
            temp.path().join("requirements.txt"),
            "dramatiq\nhuey\ncelery\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("svc/tasks.py"),
            "@dramatiq.actor\ndef sync_account(message): pass\n\n@app.task\ndef send_email(message): pass\n\n@huey.task\ndef compact_logs(): pass\n",
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();
        let python_jobs = map
            .surfaces
            .iter()
            .filter(|surface| {
                surface.kind == AttackSurfaceKind::BackgroundJob
                    && surface
                        .metadata
                        .pointer("/detector")
                        .and_then(Value::as_str)
                        == Some("python.background-job")
            })
            .collect::<Vec<_>>();

        assert_eq!(python_jobs.len(), 3, "{:#?}", map.surfaces);
        assert!(python_jobs
            .iter()
            .any(|surface| surface.evidence.contains("@dramatiq.actor")));
        assert!(python_jobs
            .iter()
            .any(|surface| surface.evidence.contains("@app.task")));
        assert!(python_jobs
            .iter()
            .any(|surface| surface.evidence.contains("@huey.task")));
    }

    #[test]
    fn attack_surface_detects_python_filestorage_uploads() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("svc")).unwrap();
        fs::write(temp.path().join("requirements.txt"), "flask\nwerkzeug\n").unwrap();
        fs::write(
            temp.path().join("svc/uploads.py"),
            "def import_files(request):\n    uploads = request.files.getlist('imports')\n    avatar: FileStorage = uploads[0]\n    return avatar.filename\n",
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();
        let upload_surfaces = map
            .surfaces
            .iter()
            .filter(|surface| {
                surface.kind == AttackSurfaceKind::FileUploadParsePath
                    && surface
                        .metadata
                        .pointer("/detector")
                        .and_then(Value::as_str)
                        == Some("python.file-upload")
            })
            .collect::<Vec<_>>();

        assert_eq!(upload_surfaces.len(), 2, "{:#?}", map.surfaces);
        assert!(upload_surfaces
            .iter()
            .any(|surface| surface.evidence.contains("files.getlist")));
        assert!(upload_surfaces
            .iter()
            .any(|surface| surface.evidence.contains("FileStorage")));
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
              const signature = req.headers.get('x-signature');
              db.query(req.headers.get('x-query'));
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
        assert_no_surface_route(&map, AttackSurfaceKind::DbQueryBoundary, "x-query");
    }

    #[test]
    fn node_auth_boundary_ignores_non_route_get_helpers() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src")).unwrap();
        fs::write(
            temp.path().join("package.json"),
            r#"{"dependencies":{"express":"^4.18.0"}}"#,
        )
        .unwrap();
        fs::write(
            temp.path().join("src/auth.ts"),
            r#"
              import express from 'express';
              const app = express();
              app.get('/admin', requireAuth, handler);
              const authorized = authorize(headers.get('x-user'));
            "#,
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();

        assert_detector(&map, "node.express.auth-route");
        assert_detector(&map, "node.auth-guard");
        assert_no_surface_route(&map, AttackSurfaceKind::AuthBoundary, "x-user");
    }

    #[test]
    fn route_risk_calibration_covers_account_recovery_and_import_paths() {
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
              const app = express();
              app.post('/password/reset-token', (req, res) => res.json({ ok: true }));
              app.post('/auth/2fa/verify', (req, res) => res.json({ ok: true }));
              app.post('/auth/totp/enroll', (req, res) => res.json({ ok: true }));
              app.post('/auth/otp/verify', (req, res) => res.json({ ok: true }));
              app.post('/recovery-codes/rotate', (req, res) => res.json({ ok: true }));
              app.post('/backup-codes/regenerate', (req, res) => res.json({ ok: true }));
              app.post('/profile/email-change', (req, res) => res.json({ ok: true }));
              app.post('/settings/change-email', (req, res) => res.json({ ok: true }));
              app.post('/identity/verify-email', (req, res) => res.json({ ok: true }));
              app.post('/auth/passkey/register', (req, res) => res.json({ ok: true }));
              app.post('/webauthn/challenge', (req, res) => res.json({ ok: true }));
              app.post('/credentials/rotate', (req, res) => res.json({ ok: true }));
              app.post('/customers/import-file', (req, res) => res.json({ ok: true }));
              app.post('/customers/export', (req, res) => res.json({ ok: true }));
              app.get('/reports/download', (req, res) => res.json({ ok: true }));
              app.post('/billing/api-key', (req, res) => res.json({ ok: true }));
              app.post('/projects/restore-archive', (req, res) => res.json({ ok: true }));
              app.post('/oauth/callback', (req, res) => res.json({ ok: true }));
              app.post('/webhooks/proxy', (req, res) => res.json({ ok: true }));
              app.post('/auth/redirect', (req, res) => res.json({ ok: true }));
              app.post('/login/return-to', (req, res) => res.json({ ok: true }));
              app.post('/fetch/proxy', (req, res) => res.json({ ok: true }));
              app.post('/admin/users', (req, res) => res.json({ ok: true }));
              app.post('/tenants/:tenantId/members', (req, res) => res.json({ ok: true }));
              app.post('/payments/refund', (req, res) => res.json({ ok: true }));
              app.post('/billing/subscription', (req, res) => res.json({ ok: true }));
              app.post('/teams/invite', (req, res) => res.json({ ok: true }));
              app.post('/roles/permission', (req, res) => res.json({ ok: true }));
              app.post('/saml/acs', (req, res) => res.json({ ok: true }));
              app.post('/oidc/connect', (req, res) => res.json({ ok: true }));
              app.post('/sso/magic-link', (req, res) => res.json({ ok: true }));
              app.post('/scim/users', (req, res) => res.json({ ok: true }));
              app.post('/support/impersonate', (req, res) => res.json({ ok: true }));
              app.post('/federation/return-url', (req, res) => res.json({ ok: true }));
              app.get('/realtime/socket', (req, res) => res.json({ ok: true }));
            "#,
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();

        assert_route_risk_reason(
            &map,
            "/password/reset-token",
            "route touches auth or admin workflow",
        );
        assert_route_risk_reason(
            &map,
            "/auth/2fa/verify",
            "route touches auth or admin workflow",
        );
        assert_route_risk_reason(
            &map,
            "/auth/totp/enroll",
            "route touches auth or admin workflow",
        );
        assert_route_risk_reason(
            &map,
            "/auth/otp/verify",
            "route touches auth or admin workflow",
        );
        assert_route_risk_reason(
            &map,
            "/recovery-codes/rotate",
            "route touches auth or admin workflow",
        );
        assert_route_risk_reason(
            &map,
            "/backup-codes/regenerate",
            "route touches auth or admin workflow",
        );
        assert_route_risk_reason(
            &map,
            "/profile/email-change",
            "route touches auth or admin workflow",
        );
        assert_route_risk_reason(
            &map,
            "/settings/change-email",
            "route touches auth or admin workflow",
        );
        assert_route_risk_reason(
            &map,
            "/identity/verify-email",
            "route touches auth or admin workflow",
        );
        assert_route_risk_reason(
            &map,
            "/auth/passkey/register",
            "route touches auth or admin workflow",
        );
        assert_route_risk_reason(
            &map,
            "/webauthn/challenge",
            "route touches auth or admin workflow",
        );
        assert_route_risk_reason(
            &map,
            "/webauthn/challenge",
            "route accepts rich external input",
        );
        assert_route_risk_reason(
            &map,
            "/credentials/rotate",
            "route touches auth or admin workflow",
        );
        assert_route_risk_reason(
            &map,
            "/customers/import-file",
            "route accepts rich external input",
        );
        assert_route_risk_reason(
            &map,
            "/customers/export",
            "route accepts rich external input",
        );
        assert_route_risk_reason(
            &map,
            "/reports/download",
            "route accepts rich external input",
        );
        assert_route_risk_reason(
            &map,
            "/billing/api-key",
            "route touches auth or admin workflow",
        );
        assert_route_risk_reason(
            &map,
            "/projects/restore-archive",
            "route accepts rich external input",
        );
        assert_route_risk_reason(
            &map,
            "/oauth/callback",
            "route touches auth or admin workflow",
        );
        assert_route_risk_reason(&map, "/oauth/callback", "route accepts rich external input");
        assert_route_risk_reason(&map, "/webhooks/proxy", "route accepts rich external input");
        assert_route_risk_reason(&map, "/auth/redirect", "route accepts rich external input");
        assert_route_risk_reason(
            &map,
            "/login/return-to",
            "route accepts rich external input",
        );
        assert_route_risk_reason(&map, "/fetch/proxy", "route accepts rich external input");
        assert_route_risk_reason(&map, "/admin/users", "route touches auth or admin workflow");
        assert_route_risk_reason(
            &map,
            "/tenants/:tenantId/members",
            "route touches auth or admin workflow",
        );
        assert_route_risk_reason(
            &map,
            "/payments/refund",
            "route touches auth or admin workflow",
        );
        assert_route_risk_reason(
            &map,
            "/billing/subscription",
            "route touches auth or admin workflow",
        );
        assert_route_risk_reason(
            &map,
            "/teams/invite",
            "route touches auth or admin workflow",
        );
        assert_route_risk_reason(
            &map,
            "/roles/permission",
            "route touches auth or admin workflow",
        );
        assert_route_risk_reason(&map, "/saml/acs", "route touches auth or admin workflow");
        assert_route_risk_reason(
            &map,
            "/oidc/connect",
            "route touches auth or admin workflow",
        );
        assert_route_risk_reason(&map, "/oidc/connect", "route accepts rich external input");
        assert_route_risk_reason(
            &map,
            "/sso/magic-link",
            "route touches auth or admin workflow",
        );
        assert_route_risk_reason(&map, "/scim/users", "route touches auth or admin workflow");
        assert_route_risk_reason(
            &map,
            "/support/impersonate",
            "route touches auth or admin workflow",
        );
        assert_route_risk_reason(
            &map,
            "/federation/return-url",
            "route accepts rich external input",
        );
        assert_route_risk_reason(
            &map,
            "/realtime/socket",
            "route accepts rich external input",
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
                  let _ = projects.filter(team_id.eq(claims.team_id));
                  while let Some(field) = multipart.next_field().await.unwrap() {
                      let _ = field.name();
                  }
                  tokio::spawn(async move { consumer.recv().await });
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
                && surface.evidence.contains("claims.team_id")
                && surface
                    .metadata
                    .pointer("/detector")
                    .and_then(Value::as_str)
                    == Some("rust.tenant-isolation")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::BackgroundJob
                && surface
                    .metadata
                    .pointer("/detector")
                    .and_then(Value::as_str)
                    == Some("rust.background-job")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::FileUploadParsePath
                && surface
                    .metadata
                    .pointer("/detector")
                    .and_then(Value::as_str)
                    == Some("rust.file-upload")
        }));
    }

    #[test]
    fn attack_surface_promotes_actix_routes_and_tenant_boundaries() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src")).unwrap();
        fs::write(
            temp.path().join("Cargo.toml"),
            "[package]\nname = \"svc\"\nversion = \"0.1.0\"\n[dependencies]\nactix-web = \"4\"\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("src/main.rs"),
            "use actix_web::{post, HttpResponse};\n#[post(\"/teams/projects\")]\nasync fn create_project(claims: Claims) -> HttpResponse { let _ = projects.filter(team_id.eq(claims.team_id)); HttpResponse::Ok().finish() }\n",
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();

        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/teams/projects")
                && surface.method.as_deref() == Some("POST")
                && surface.framework.as_deref() == Some("Actix Web")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::TenantIsolationBoundary
                && surface.framework.as_deref() == Some("Actix Web")
                && surface.evidence.contains("claims.team_id")
                && surface
                    .metadata
                    .pointer("/detector")
                    .and_then(Value::as_str)
                    == Some("rust.tenant-isolation")
        }));
    }

    #[test]
    fn attack_surface_promotes_rocket_routes_and_tenant_boundaries() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src")).unwrap();
        fs::write(
            temp.path().join("Cargo.toml"),
            "[package]\nname = \"svc\"\nversion = \"0.1.0\"\n[dependencies]\nrocket = \"0.5\"\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("src/main.rs"),
            "use rocket::{post, routes};\n#[post(\"/teams/projects\")]\nfn create_project(claims: Claims) -> &'static str { let _ = projects.filter(team_id.eq(claims.team_id)); \"ok\" }\n",
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();

        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/teams/projects")
                && surface.method.as_deref() == Some("POST")
                && surface.framework.as_deref() == Some("Rocket")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::TenantIsolationBoundary
                && surface.framework.as_deref() == Some("Rocket")
                && surface.evidence.contains("claims.team_id")
                && surface
                    .metadata
                    .pointer("/detector")
                    .and_then(Value::as_str)
                    == Some("rust.tenant-isolation")
        }));
    }

    #[test]
    fn attack_surface_promotes_warp_routes_and_tenant_boundaries() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src")).unwrap();
        fs::write(
            temp.path().join("Cargo.toml"),
            "[package]\nname = \"svc\"\nversion = \"0.1.0\"\n[dependencies]\nwarp = \"0.3\"\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("src/main.rs"),
            "fn routes() { let create = warp::path!(\"teams\" / \"projects\").and(warp::post()).and_then(create_project); }\nasync fn create_project(claims: Claims) { let _ = projects.filter(team_id.eq(claims.team_id)); }\n",
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();

        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/teams/projects")
                && surface.method.as_deref() == Some("POST")
                && surface.framework.as_deref() == Some("Warp")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::TenantIsolationBoundary
                && surface.framework.as_deref() == Some("Warp")
                && surface.evidence.contains("claims.team_id")
                && surface
                    .metadata
                    .pointer("/detector")
                    .and_then(Value::as_str)
                    == Some("rust.tenant-isolation")
        }));
    }

    #[test]
    fn attack_surface_preserves_rails_match_via_methods() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("config")).unwrap();
        fs::create_dir_all(temp.path().join("app/controllers")).unwrap();
        fs::write(temp.path().join("Gemfile"), "gem 'rails'\n").unwrap();
        fs::write(
            temp.path().join("config/routes.rb"),
            "Rails.application.routes.draw do\nmatch '/imports/file', to: 'imports#create', via: :post\nend\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("app/controllers/imports_controller.rb"),
            "class ImportsController < ApplicationController\ndef create\nuploaded_file = params[:file]\nend\nend\n",
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();

        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/imports/file")
                && surface.method.as_deref() == Some("POST")
                && surface.framework.as_deref() == Some("Rails")
        }));
        assert_detector(&map, "ruby.file-upload");
    }

    #[test]
    fn attack_surface_detects_rust_async_nats_subscriptions() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src")).unwrap();
        fs::write(
            temp.path().join("Cargo.toml"),
            "[package]\nname = \"svc\"\nversion = \"0.1.0\"\n[dependencies]\nasync-nats = \"0.35\"\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("src/workers.rs"),
            "async fn workers(client: async_nats::Client, jetstream: JetStream) {\nlet _events = client.subscribe(\"tenant.events\".into()).await.unwrap();\nlet _jobs = jetstream.subscribe(\"jobs.email\").await.unwrap();\n}\n",
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();
        let rust_jobs = map
            .surfaces
            .iter()
            .filter(|surface| {
                surface.kind == AttackSurfaceKind::BackgroundJob
                    && surface
                        .metadata
                        .pointer("/detector")
                        .and_then(Value::as_str)
                        == Some("rust.background-job")
            })
            .collect::<Vec<_>>();

        assert_eq!(rust_jobs.len(), 2, "{:#?}", map.surfaces);
        assert!(rust_jobs
            .iter()
            .any(|surface| surface.evidence.contains("client.subscribe")));
        assert!(rust_jobs
            .iter()
            .any(|surface| surface.evidence.contains("jetstream.subscribe")));
    }

    #[test]
    fn attack_surface_detects_jvm_spring_security_boundaries() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(
            temp.path().join("build.gradle"),
            "plugins { id 'java' }\ndependencies { implementation 'org.springframework.boot:spring-boot-starter-cache' }\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("src/main/java/app/UserController.java"),
            r#"
              @RestController
              class UserController {
                @PostMapping("/admin/invite")
                @PreAuthorize("hasRole('ADMIN')")
                void invite(HttpSession session, @RequestPart MultipartFile importFile) {
                  objectMapper.readValue(body, Payload.class);
                  jdbcTemplate.query(sql);
                  webClient.post().uri(url);
                  Runtime.getRuntime().exec(cmd);
                  tenantId = user.tenantId;
                  organizationId = principal.getOrganizationId();
                }
                @PostMapping("/webhooks/signed")
                void signed(@RequestHeader("X-Signature") String signature) {}
                @GetMapping
                void missingRoute() {}
                @KafkaListener(topics = "tenant-events")
                void consume(String event) {}
              }
            "#,
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();

        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/admin/invite")
                && surface.framework.as_deref() == Some("Spring")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/webhooks/signed")
                && surface.framework.as_deref() == Some("Spring")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::RequestTrustBoundary
                && surface.evidence.contains("@RequestHeader")
                && surface
                    .metadata
                    .pointer("/detector")
                    .and_then(Value::as_str)
                    == Some("jvm.request-trust")
        }));
        assert_has_kind(&map, AttackSurfaceKind::AuthBoundary);
        assert_has_kind(&map, AttackSurfaceKind::SessionStateBoundary);
        assert_has_kind(&map, AttackSurfaceKind::TenantIsolationBoundary);
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::TenantIsolationBoundary
                && surface.evidence.contains("principal.getOrganizationId")
                && surface
                    .metadata
                    .pointer("/detector")
                    .and_then(Value::as_str)
                    == Some("jvm.tenant-isolation")
        }));
        assert_has_kind(&map, AttackSurfaceKind::DeserializationPoint);
        assert_has_kind(&map, AttackSurfaceKind::FileUploadParsePath);
        assert_detector(&map, "jvm.file-upload");
        assert_has_kind(&map, AttackSurfaceKind::DbQueryBoundary);
        assert_has_kind(&map, AttackSurfaceKind::ExternalServiceClient);
        assert_has_kind(&map, AttackSurfaceKind::CommandExecutionBoundary);
        assert_has_kind(&map, AttackSurfaceKind::BackgroundJob);
        assert_no_surface_route(&map, AttackSurfaceKind::HttpRoute, "unknown");
    }

    #[test]
    fn attack_surface_detects_jvm_security_configuration_as_auth_boundaries() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/SecurityConfig.java"),
            r#"
              import org.springframework.security.config.annotation.web.builders.HttpSecurity;
              class SecurityConfig {
                SecurityFilterChain api(HttpSecurity http) {
                  http.authorizeHttpRequests(auth -> auth.anyRequest().authenticated());
                  http.oauth2ResourceServer(oauth -> oauth.jwt());
                  http.oauth2Login();
                  return http.build();
                }
                void reactive(ServerHttpSecurity http) {
                  http.authorizeExchange(exchange -> exchange.anyExchange().authenticated());
                }
                JwtDecoder jwtDecoder() { return decoder; }
                PasswordEncoder passwordEncoder() { return encoder; }
                AuthenticationProvider authenticationProvider() { return provider; }
                AuthenticationManager authenticationManager() { return manager; }
                UserDetailsService userDetailsService() { return users; }
              }
              class TenantFilter extends OncePerRequestFilter {}
              class PasskeyConfig { void enable() { WebAuthn4J webauthn = new WebAuthn4J(); } }
            "#,
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();
        let auth = map
            .surfaces
            .iter()
            .filter(|surface| {
                surface.kind == AttackSurfaceKind::AuthBoundary
                    && surface
                        .metadata
                        .pointer("/detector")
                        .and_then(Value::as_str)
                        == Some("jvm.auth-guard")
            })
            .collect::<Vec<_>>();

        assert_eq!(auth.len(), 13, "{:#?}", map.surfaces);
        assert!(auth
            .iter()
            .all(|surface| surface.framework.as_deref() == Some("Spring")));
        assert!(auth
            .iter()
            .all(|surface| surface.boundary.as_deref() == Some("auth_guard")));
    }

    #[test]
    fn attack_surface_detects_jvm_oauth_client_and_token_auth_boundaries() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/OAuthSecurity.java"),
            r#"
              import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
              import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
              class OAuthSecurity {
                ClientRegistrationRepository clientRegistrationRepository;
                ReactiveClientRegistrationRepository reactiveClientRegistrationRepository;
                OAuth2AuthorizedClientService authorizedClientService;
                OAuth2AuthorizedClientRepository authorizedClientRepository;
                OAuth2AuthorizedClientManager authorizedClientManager;
                ReactiveOAuth2AuthorizedClientManager reactiveAuthorizedClientManager;
                BearerTokenResolver bearerTokenResolver;
                BearerTokenAuthenticationFilter bearerTokenAuthenticationFilter;
                ReactiveJwtDecoder reactiveJwtDecoder;
                void opaque(HttpSecurity http) {
                  http.oauth2ResourceServer(oauth -> oauth.opaqueToken());
                }
              }
            "#,
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();
        let auth = map
            .surfaces
            .iter()
            .filter(|surface| {
                surface.kind == AttackSurfaceKind::AuthBoundary
                    && surface
                        .metadata
                        .pointer("/detector")
                        .and_then(Value::as_str)
                        == Some("jvm.auth-guard")
            })
            .collect::<Vec<_>>();

        assert_eq!(auth.len(), 11, "{:#?}", map.surfaces);
        assert!(auth
            .iter()
            .all(|surface| surface.framework.as_deref() == Some("Spring")));
        assert!(auth
            .iter()
            .all(|surface| surface.boundary.as_deref() == Some("auth_guard")));
    }

    #[test]
    fn attack_surface_detects_jvm_saml_x509_preauth_and_api_key_auth_boundaries() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/FederatedSecurity.java"),
            r#"
              import org.springframework.security.config.annotation.web.builders.HttpSecurity;
              class FederatedSecurity {
                void federated(HttpSecurity http) {
                  http.saml2Login();
                  http.saml2Logout();
                  http.saml2Metadata();
                  http.x509();
                }
                RelyingPartyRegistrationRepository relyingPartyRegistrationRepository;
                X509AuthenticationFilter x509AuthenticationFilter;
                RequestHeaderAuthenticationFilter requestHeaderAuthenticationFilter;
                AbstractPreAuthenticatedProcessingFilter preAuthFilter;
                PreAuthenticatedAuthenticationProvider preAuthProvider;
                ApiKeyAuthenticationFilter apiKeyAuthenticationFilter;
                String apiKeyHeader = "X-API-Key";
              }
            "#,
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();
        let auth = map
            .surfaces
            .iter()
            .filter(|surface| {
                surface.kind == AttackSurfaceKind::AuthBoundary
                    && surface
                        .metadata
                        .pointer("/detector")
                        .and_then(Value::as_str)
                        == Some("jvm.auth-guard")
            })
            .collect::<Vec<_>>();

        assert_eq!(auth.len(), 12, "{:#?}", map.surfaces);
        assert!(auth
            .iter()
            .all(|surface| surface.framework.as_deref() == Some("Spring")));
        assert!(auth
            .iter()
            .all(|surface| surface.boundary.as_deref() == Some("auth_guard")));
    }

    #[test]
    fn attack_surface_detects_jvm_method_security_as_auth_boundaries() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/MethodSecurity.java"),
            r#"
              import org.springframework.security.access.prepost.PostAuthorize;
              class MethodSecurity {
                @RolesAllowed("ADMIN")
                void adminOnly() {}
                @DenyAll
                void disabled() {}
                @PermitAll
                void publicEndpoint() {}
                @PostAuthorize("returnObject.owner == authentication.name")
                Account ownedAccount() {}
                void expressionChecks(AccessExpression access) {
                  access.hasRole("ADMIN");
                  access.hasAuthority("SCOPE_billing");
                }
                void principal(@AuthenticationPrincipal User user) {}
              }
            "#,
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();
        let auth = map
            .surfaces
            .iter()
            .filter(|surface| {
                surface.kind == AttackSurfaceKind::AuthBoundary
                    && surface
                        .metadata
                        .pointer("/detector")
                        .and_then(Value::as_str)
                        == Some("jvm.auth-guard")
            })
            .collect::<Vec<_>>();

        assert_eq!(auth.len(), 7, "{:#?}", map.surfaces);
        assert!(auth
            .iter()
            .all(|surface| surface.framework.as_deref() == Some("Spring")));
        assert!(auth
            .iter()
            .all(|surface| surface.boundary.as_deref() == Some("auth_guard")));
    }

    #[test]
    fn attack_surface_detects_jvm_method_security_extension_auth_boundaries() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/AdvancedMethodSecurity.java"),
            r#"
              import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
              @EnableWebSecurity
              @EnableMethodSecurity
              @EnableReactiveMethodSecurity
              class AdvancedMethodSecurity {
                AuthorizationManager<RequestAuthorizationContext> authorizationManager;
                AuthorizationDecision authorizationDecision;
                PermissionEvaluator permissionEvaluator;
                @PreFilter("filterObject.owner == authentication.name")
                void filterBefore(List<Account> accounts) {}
                @PostFilter("filterObject.owner == authentication.name")
                List<Account> filterAfter() { return accounts; }
              }
            "#,
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();
        let auth = map
            .surfaces
            .iter()
            .filter(|surface| {
                surface.kind == AttackSurfaceKind::AuthBoundary
                    && surface
                        .metadata
                        .pointer("/detector")
                        .and_then(Value::as_str)
                        == Some("jvm.auth-guard")
            })
            .collect::<Vec<_>>();

        assert_eq!(auth.len(), 8, "{:#?}", map.surfaces);
        assert!(auth
            .iter()
            .all(|surface| surface.framework.as_deref() == Some("Spring")));
        assert!(auth
            .iter()
            .all(|surface| surface.boundary.as_deref() == Some("auth_guard")));
    }

    #[test]
    fn attack_surface_detects_jvm_session_configuration_as_session_state() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/SessionConfig.java"),
            r#"
              import org.springframework.session.data.redis.config.annotation.web.http.EnableRedisHttpSession;
              @EnableRedisHttpSession
              class SessionConfig {
                void configure(HttpSecurity http) {
                  http.sessionManagement(session -> session
                    .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                    .sessionFixation().migrateSession()
                    .maximumSessions(1));
                }
                DefaultCookieSerializer cookieSerializer() { return serializer; }
                CookieWebSessionIdResolver webSessionIdResolver() { return resolver; }
                FindByIndexNameSessionRepository<?> repository() { return repository; }
                void filter(SpringSessionRepositoryFilter<?> filter) {}
                void servlet(SessionCookieConfig config) {}
              }
            "#,
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();
        let sessions = map
            .surfaces
            .iter()
            .filter(|surface| {
                surface.kind == AttackSurfaceKind::SessionStateBoundary
                    && surface
                        .metadata
                        .pointer("/detector")
                        .and_then(Value::as_str)
                        == Some("jvm.session-state")
            })
            .collect::<Vec<_>>();

        assert_eq!(sessions.len(), 10, "{:#?}", map.surfaces);
        assert!(sessions
            .iter()
            .all(|surface| surface.framework.as_deref() == Some("Spring")));
        assert!(sessions
            .iter()
            .all(|surface| surface.boundary.as_deref() == Some("session_state")));
    }

    #[test]
    fn attack_surface_detects_jvm_cookie_and_session_access_as_session_state() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/SessionAccess.java"),
            r#"
              import org.springframework.web.bind.annotation.GetMapping;
              class SessionAccess {
                @GetMapping("/session")
                String show(@CookieValue("sid") String sid, HttpServletRequest request) {
                  request.getSession(false);
                  request.getCookies();
                  ResponseCookie.from("sid", sid).httpOnly(true).build();
                  serverWebExchange.getSession();
                }
              }
            "#,
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();
        let sessions = map
            .surfaces
            .iter()
            .filter(|surface| {
                surface.kind == AttackSurfaceKind::SessionStateBoundary
                    && surface
                        .metadata
                        .pointer("/detector")
                        .and_then(Value::as_str)
                        == Some("jvm.session-state")
            })
            .collect::<Vec<_>>();

        assert_eq!(sessions.len(), 5, "{:#?}", map.surfaces);
        assert!(sessions
            .iter()
            .all(|surface| surface.framework.as_deref() == Some("Spring")));
        assert!(sessions
            .iter()
            .all(|surface| surface.boundary.as_deref() == Some("session_state")));
    }

    #[test]
    fn attack_surface_detects_jvm_remember_me_and_security_context_sessions() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path()
                .join("src/main/java/app/RememberMeSessions.java"),
            r#"
              import org.springframework.security.web.authentication.RememberMeServices;
              class RememberMeSessions {
                void configure(HttpSecurity http) {
                  http.rememberMe(remember -> remember.key("tenant-key"));
                  SecurityContextRepository securityContextRepository;
                  securityContextRepository.saveContext(context, request, response);
                  SessionAuthenticationStrategy sessionAuthenticationStrategy;
                  LogoutSuccessHandler logoutSuccessHandler;
                  RememberMeServices rememberMeServices;
                }
              }
            "#,
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();
        let sessions = map
            .surfaces
            .iter()
            .filter(|surface| {
                surface.kind == AttackSurfaceKind::SessionStateBoundary
                    && surface
                        .metadata
                        .pointer("/detector")
                        .and_then(Value::as_str)
                        == Some("jvm.session-state")
            })
            .collect::<Vec<_>>();

        assert_eq!(sessions.len(), 6, "{:#?}", map.surfaces);
        assert!(sessions
            .iter()
            .all(|surface| surface.framework.as_deref() == Some("Spring")));
        assert!(sessions
            .iter()
            .all(|surface| surface.boundary.as_deref() == Some("session_state")));
    }

    #[test]
    fn attack_surface_detects_jvm_tenant_context_markers_as_tenant_isolation() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/TenantAccess.java"),
            r#"
              import org.springframework.web.bind.annotation.GetMapping;
              class TenantAccess {
                @GetMapping("/tenants/current")
                void show(TenantContext tenantContext) {
                  TenantResolver tenantResolver;
                  TenantProvider tenantProvider;
                  String currentWorkspace;
                  String organization_id;
                  String account_id;
                  String team_id;
                  principal.getTenantId();
                  jwt.getClaim("tenant_id");
                  authentication.getPrincipal();
                }
              }
            "#,
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();
        let tenants = map
            .surfaces
            .iter()
            .filter(|surface| {
                surface.kind == AttackSurfaceKind::TenantIsolationBoundary
                    && surface
                        .metadata
                        .pointer("/detector")
                        .and_then(Value::as_str)
                        == Some("jvm.tenant-isolation")
            })
            .collect::<Vec<_>>();

        assert_eq!(tenants.len(), 10, "{:#?}", map.surfaces);
        assert!(tenants
            .iter()
            .all(|surface| surface.framework.as_deref() == Some("Spring")));
        assert!(tenants
            .iter()
            .all(|surface| surface.boundary.as_deref() == Some("tenant_isolation")));
    }

    #[test]
    fn attack_surface_detects_jvm_persistence_tenant_isolation_boundaries() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/TenantPersistence.java"),
            r#"
              import org.springframework.data.domain.AuditorAware;
              class TenantPersistence {
                AuditorAware<String> auditorAware;
                void audit() { auditorAware.getCurrentAuditor(); }
                CurrentTenantIdentifierResolver tenantIdentifierResolver;
                MultiTenantConnectionProvider connectionProvider;
                void filter(Session session) { session.enableFilter("tenant"); }
                @FilterDef(name = "tenantFilter")
                @Filter(name = "tenantFilter")
                TenantLineHandler tenantLineHandler;
                TenantLineInnerInterceptor tenantInterceptor;
              }
            "#,
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();
        let tenants = map
            .surfaces
            .iter()
            .filter(|surface| {
                surface.kind == AttackSurfaceKind::TenantIsolationBoundary
                    && surface
                        .metadata
                        .pointer("/detector")
                        .and_then(Value::as_str)
                        == Some("jvm.tenant-isolation")
            })
            .collect::<Vec<_>>();

        assert_eq!(tenants.len(), 9, "{:#?}", map.surfaces);
        assert!(tenants
            .iter()
            .all(|surface| surface.framework.as_deref() == Some("Spring")));
        assert!(tenants
            .iter()
            .all(|surface| surface.boundary.as_deref() == Some("tenant_isolation")));
    }

    #[test]
    fn attack_surface_detects_jvm_gateway_configuration_boundaries() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/GatewayConfig.java"),
            r#"
              import org.springframework.cloud.gateway.filter.GatewayFilter;
              import org.springframework.cloud.gateway.filter.GlobalFilter;
              import org.springframework.cloud.gateway.handler.RoutePredicateHandlerMapping;
              import org.springframework.cloud.gateway.route.RouteLocator;
              import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
              class GatewayConfig {
                RouteLocator gatewayRoutes(RouteLocatorBuilder routes) {
                  return routes.routes()
                    .route("orders", r -> r.path("/orders/**").filters(f -> f.stripPrefix(1)
                      .rewritePath("/orders/(?<segment>.*)", "/${segment}")
                      .addRequestHeader("X-Gateway", "kuzushi"))
                      .uri("http://orders.internal"))
                    .build();
                }
                GatewayFilter auditGatewayFilter() { return filter; }
                GlobalFilter globalFilter() { return filter; }
                RoutePredicateHandlerMapping handlerMapping;
              }
            "#,
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();
        let gateway_clients = map
            .surfaces
            .iter()
            .filter(|surface| {
                surface.kind == AttackSurfaceKind::ExternalServiceClient
                    && surface
                        .metadata
                        .pointer("/detector")
                        .and_then(Value::as_str)
                        == Some("jvm.external-client")
            })
            .collect::<Vec<_>>();
        let gateway_trust = map
            .surfaces
            .iter()
            .filter(|surface| {
                surface.kind == AttackSurfaceKind::RequestTrustBoundary
                    && surface
                        .metadata
                        .pointer("/detector")
                        .and_then(Value::as_str)
                        == Some("jvm.request-trust")
            })
            .collect::<Vec<_>>();

        assert_eq!(gateway_clients.len(), 3, "{:#?}", map.surfaces);
        assert_eq!(gateway_trust.len(), 5, "{:#?}", map.surfaces);
        assert!(gateway_clients
            .iter()
            .all(|surface| surface.framework.as_deref() == Some("Spring")));
        assert!(gateway_trust
            .iter()
            .all(|surface| surface.boundary.as_deref() == Some("request_trust")));
    }

    #[test]
    fn attack_surface_detects_jvm_filter_and_rate_limit_request_trust() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path()
                .join("src/main/java/app/RequestTrustConfig.java"),
            r#"
              import org.springframework.web.filter.ForwardedHeaderFilter;
              import org.springframework.web.reactive.function.client.ExchangeFilterFunction;
              class RequestTrustConfig {
                WebFilter auditWebFilter;
                HandlerInterceptor tenantInterceptor;
                ForwardedHeaderFilter forwardedHeaderFilter;
                CorsWebFilter corsWebFilter;
                ExchangeFilterFunction outboundHeaderFilter;
                RateLimiter rateLimiter;
                Bucket4j bucket4j;
                io.github.resilience4j.ratelimiter.RateLimiter resilience4jLimiter;
              }
            "#,
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();
        let trust = map
            .surfaces
            .iter()
            .filter(|surface| {
                surface.kind == AttackSurfaceKind::RequestTrustBoundary
                    && surface
                        .metadata
                        .pointer("/detector")
                        .and_then(Value::as_str)
                        == Some("jvm.request-trust")
            })
            .collect::<Vec<_>>();

        assert_eq!(trust.len(), 8, "{:#?}", map.surfaces);
        assert!(trust
            .iter()
            .all(|surface| surface.framework.as_deref() == Some("Spring")));
        assert!(trust
            .iter()
            .all(|surface| surface.boundary.as_deref() == Some("request_trust")));
    }

    #[test]
    fn attack_surface_detects_jvm_cors_csrf_and_forwarded_header_request_trust() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/TrustConfig.java"),
            r#"
              import org.springframework.web.servlet.config.annotation.CorsRegistry;
              class TrustConfig {
                void addCorsMappings(CorsRegistry registry) {
                  registry.addMapping("/api/**").allowedOrigins("https://app.example");
                  registry.allowedOriginPatterns("https://*.example");
                  registry.allowedMethods("GET", "POST");
                }
                void csrf(HttpSecurity http) {
                  http.csrf(csrf -> csrf.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()));
                  ServerCsrfTokenRepository serverRepository;
                }
                ForwardedHeaderTransformer forwardedHeaderTransformer;
                XForwardedHeadersFilter xForwardedHeadersFilter;
                void cookie(DefaultCookieSerializer serializer) { serializer.setCookieDomain("example.com"); }
              }
            "#,
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();
        let trust = map
            .surfaces
            .iter()
            .filter(|surface| {
                surface.kind == AttackSurfaceKind::RequestTrustBoundary
                    && surface
                        .metadata
                        .pointer("/detector")
                        .and_then(Value::as_str)
                        == Some("jvm.request-trust")
            })
            .collect::<Vec<_>>();

        assert_eq!(trust.len(), 10, "{:#?}", map.surfaces);
        assert!(trust
            .iter()
            .all(|surface| surface.framework.as_deref() == Some("Spring")));
        assert!(trust
            .iter()
            .all(|surface| surface.boundary.as_deref() == Some("request_trust")));
    }

    #[test]
    fn attack_surface_detects_jvm_binding_and_content_negotiation_request_trust() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/BindingTrustConfig.java"),
            r#"
              class BindingTrustConfig {
                @InitBinder
                void initBinder(WebDataBinder binder) {}
                ConfigurableWebBindingInitializer bindingInitializer;
                RequestMappingHandlerAdapter requestMappingHandlerAdapter;
                ContentNegotiationConfigurer contentNegotiationConfigurer;
                void configureContentNegotiation(ContentNegotiationConfigurer configurer) {}
                void favor(ContentNegotiationConfigurer configurer) { configurer.favorParameter(true); }
                void allowedHeaders(CorsRegistration registration) {}
                void exposedHeaders(CorsRegistration registration) {}
                void allowCredentials(CorsRegistration registration) {}
                void setAllowedOrigins(CorsConfiguration config) {}
                void setAllowCredentials(CorsConfiguration config) {}
              }
            "#,
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();
        let trust = map
            .surfaces
            .iter()
            .filter(|surface| {
                surface.kind == AttackSurfaceKind::RequestTrustBoundary
                    && surface
                        .metadata
                        .pointer("/detector")
                        .and_then(Value::as_str)
                        == Some("jvm.request-trust")
            })
            .collect::<Vec<_>>();

        assert_eq!(trust.len(), 12, "{:#?}", map.surfaces);
        assert!(trust
            .iter()
            .all(|surface| surface.framework.as_deref() == Some("Spring")));
        assert!(trust
            .iter()
            .all(|surface| surface.boundary.as_deref() == Some("request_trust")));
    }

    #[test]
    fn attack_surface_detects_jvm_validation_request_trust() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/ValidationConfig.java"),
            r#"
              import org.springframework.validation.annotation.Validated;
              @Validated
              class ValidationConfig {
                void create(@Valid SignupRequest request, BindingResult bindingResult) {}
                ConstraintValidator<TenantId, String> tenantValidator;
                MethodValidationPostProcessor methodValidationPostProcessor;
                void reactive(WebExchangeBindException bindException) {}
              }
            "#,
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();
        let trust = map
            .surfaces
            .iter()
            .filter(|surface| {
                surface.kind == AttackSurfaceKind::RequestTrustBoundary
                    && surface
                        .metadata
                        .pointer("/detector")
                        .and_then(Value::as_str)
                        == Some("jvm.request-trust")
            })
            .collect::<Vec<_>>();

        assert_eq!(trust.len(), 5, "{:#?}", map.surfaces);
        assert!(trust
            .iter()
            .all(|surface| surface.framework.as_deref() == Some("Spring")));
        assert!(trust
            .iter()
            .all(|surface| surface.boundary.as_deref() == Some("request_trust")));
    }

    #[test]
    fn attack_surface_detects_jvm_request_input_boundaries() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path()
                .join("src/main/java/app/RequestInputController.java"),
            r#"
              import org.springframework.web.bind.annotation.PostMapping;
              class RequestInputController {
                @PostMapping("/imports/body")
                void body(@RequestBody ImportRequest body) {}
                void query(@RequestParam String tenant) {}
                void path(@PathVariable String accountId) {}
                void servlet(HttpServletRequest request) {}
                void exchange(ServerWebExchange exchange) {}
                void nativeRequest(NativeWebRequest request) {}
              }
            "#,
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();
        let trust = map
            .surfaces
            .iter()
            .filter(|surface| {
                surface.kind == AttackSurfaceKind::RequestTrustBoundary
                    && surface
                        .metadata
                        .pointer("/detector")
                        .and_then(Value::as_str)
                        == Some("jvm.request-trust")
            })
            .collect::<Vec<_>>();

        assert_eq!(trust.len(), 6, "{:#?}", map.surfaces);
        assert!(trust
            .iter()
            .all(|surface| surface.framework.as_deref() == Some("Spring")));
        assert!(trust
            .iter()
            .all(|surface| surface.boundary.as_deref() == Some("request_trust")));
    }

    #[test]
    fn attack_surface_preserves_spring_request_mapping_methods() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/ImportController.java"),
            "import org.springframework.web.bind.annotation.RequestMapping;\nclass ImportController {\n@RequestMapping(value = \"/imports/file\", method = RequestMethod.POST)\nvoid importFile(@RequestPart MultipartFile importFile) {}\n}\n",
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();

        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/imports/file")
                && surface.method.as_deref() == Some("POST")
                && surface.framework.as_deref() == Some("Spring")
        }));
        assert_detector(&map, "jvm.file-upload");
    }

    #[test]
    fn attack_surface_preserves_kotlin_spring_request_mapping_methods() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/kotlin/app")).unwrap();
        fs::write(
            temp.path().join("build.gradle.kts"),
            "plugins { kotlin(\"jvm\") }\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("src/main/kotlin/app/ImportController.kt"),
            "import org.springframework.web.bind.annotation.RequestMapping\nclass ImportController {\n@RequestMapping(value = [\"/imports/file\"], method = [RequestMethod.POST])\nfun importFile(importFile: MultipartFile) {}\n}\n",
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();

        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/imports/file")
                && surface.method.as_deref() == Some("POST")
                && surface.framework.as_deref() == Some("Spring")
                && surface.language == "Kotlin"
        }));
        assert_detector(&map, "jvm.file-upload");
    }

    #[test]
    fn attack_surface_detects_jvm_spring_functional_routes() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/FunctionalRoutes.java"),
            r#"
              import static org.springframework.web.reactive.function.server.RequestPredicates.GET;
              import org.springframework.web.reactive.function.server.RouterFunctions;
              import org.springframework.web.reactive.function.server.RequestPredicates;
              class FunctionalRoutes {
                void routes(AccountHandler handler) {
                  RouterFunctions.route(GET("/imports/file"), handler::importFile);
                  RouterFunctions.route(RequestPredicates.POST("/exports/report"), handler::exportReport);
                  RouterFunctions.route().PUT("/teams/{teamId}", handler::updateTeam).build();
                }
              }
            "#,
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();
        let routes = map
            .surfaces
            .iter()
            .filter(|surface| {
                surface.kind == AttackSurfaceKind::HttpRoute
                    && surface
                        .metadata
                        .pointer("/detector")
                        .and_then(Value::as_str)
                        == Some("jvm.spring-functional-route")
            })
            .collect::<Vec<_>>();

        assert_eq!(routes.len(), 3, "{:#?}", map.surfaces);
        assert!(routes
            .iter()
            .all(|surface| surface.framework.as_deref() == Some("Spring")));
        assert!(routes.iter().any(|surface| {
            surface.method.as_deref() == Some("GET")
                && surface.route.as_deref() == Some("/imports/file")
        }));
        assert!(routes.iter().any(|surface| {
            surface.method.as_deref() == Some("POST")
                && surface.route.as_deref() == Some("/exports/report")
        }));
        assert!(routes.iter().any(|surface| {
            surface.method.as_deref() == Some("PUT")
                && surface.route.as_deref() == Some("/teams/{teamId}")
        }));
    }

    #[test]
    fn attack_surface_detects_jvm_jaxrs_resource_routes() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("pom.xml"), "<project></project>\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/AccountResource.java"),
            r#"
              import jakarta.ws.rs.GET;
              import jakarta.ws.rs.POST;
              import jakarta.ws.rs.Path;
              @Path("/accounts")
              class AccountResource {
                @GET
                public Account list() { return account; }
                @POST
                @Path("recovery")
                public Account recover(AccountRecovery recovery) { return account; }
              }
            "#,
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();
        let routes = map
            .surfaces
            .iter()
            .filter(|surface| {
                surface.kind == AttackSurfaceKind::HttpRoute
                    && surface
                        .metadata
                        .pointer("/detector")
                        .and_then(Value::as_str)
                        == Some("jvm.jaxrs-route")
            })
            .collect::<Vec<_>>();

        assert_eq!(routes.len(), 2, "{:#?}", map.surfaces);
        assert!(routes
            .iter()
            .all(|surface| surface.framework.as_deref() == Some("JAX-RS")));
        assert!(routes.iter().any(|surface| {
            surface.method.as_deref() == Some("GET")
                && surface.route.as_deref() == Some("/accounts")
        }));
        assert!(routes.iter().any(|surface| {
            surface.method.as_deref() == Some("POST")
                && surface.route.as_deref() == Some("/accounts/recovery")
        }));
    }

    #[test]
    fn attack_surface_detects_jvm_webservlet_routes() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/AccountServlets.java"),
            r#"
              import jakarta.servlet.annotation.WebServlet;
              @WebServlet("/accounts/*")
              class AccountServlet {}
              @WebServlet(urlPatterns = "/accounts/recovery")
              class RecoveryServlet {}
              @WebServlet(urlPatterns = {"/accounts/admin", "/accounts/settings"})
              class AdminServlet {}
              @WebServlet(name = "IgnoredName", value = {"/accounts/audit"})
              class AuditServlet {}
            "#,
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();
        let routes = map
            .surfaces
            .iter()
            .filter(|surface| {
                surface.kind == AttackSurfaceKind::HttpRoute
                    && surface
                        .metadata
                        .pointer("/detector")
                        .and_then(Value::as_str)
                        == Some("jvm.servlet-route")
            })
            .collect::<Vec<_>>();

        assert_eq!(routes.len(), 5, "{:#?}", map.surfaces);
        assert!(routes
            .iter()
            .all(|surface| surface.framework.as_deref() == Some("Servlet")));
        assert!(routes
            .iter()
            .all(|surface| surface.method.as_deref() == Some("ANY")));
        assert!(routes
            .iter()
            .any(|surface| surface.route.as_deref() == Some("/accounts/*")));
        assert!(routes
            .iter()
            .any(|surface| surface.route.as_deref() == Some("/accounts/recovery")));
        assert!(routes
            .iter()
            .any(|surface| surface.route.as_deref() == Some("/accounts/admin")));
        assert!(routes
            .iter()
            .any(|surface| surface.route.as_deref() == Some("/accounts/settings")));
        assert!(routes
            .iter()
            .any(|surface| surface.route.as_deref() == Some("/accounts/audit")));
        assert!(routes
            .iter()
            .all(|surface| surface.route.as_deref() != Some("/IgnoredName")));
    }

    #[test]
    fn attack_surface_detects_jvm_serverendpoint_routes() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/AccountSocket.java"),
            r#"
              import jakarta.websocket.OnMessage;
              import jakarta.websocket.server.ServerEndpoint;
              @ServerEndpoint("/accounts/{id}/stream")
              class AccountSocket {
                @OnMessage
                void onMessage(String body) {}
              }
            "#,
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();
        let routes = map
            .surfaces
            .iter()
            .filter(|surface| {
                surface.kind == AttackSurfaceKind::HttpRoute
                    && surface
                        .metadata
                        .pointer("/detector")
                        .and_then(Value::as_str)
                        == Some("jvm.websocket-route")
            })
            .collect::<Vec<_>>();

        assert_eq!(routes.len(), 1, "{:#?}", map.surfaces);
        let route = routes[0];
        assert_eq!(route.framework.as_deref(), Some("WebSocket"));
        assert_eq!(route.method.as_deref(), Some("ANY"));
        assert_eq!(route.route.as_deref(), Some("/accounts/{id}/stream"));
    }

    #[test]
    fn attack_surface_detects_jvm_micronaut_controller_routes() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/AccountController.java"),
            r#"
              import io.micronaut.http.annotation.Controller;
              import io.micronaut.http.annotation.Get;
              import io.micronaut.http.annotation.Post;
              @Controller("/accounts")
              class AccountController {
                @Get
                Account list() { return account; }
                @Get("/{id}")
                Account show(String id) { return account; }
                @Post("/recovery")
                Account recover(AccountRecovery recovery) { return account; }
              }
            "#,
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();
        let routes = map
            .surfaces
            .iter()
            .filter(|surface| {
                surface.kind == AttackSurfaceKind::HttpRoute
                    && surface
                        .metadata
                        .pointer("/detector")
                        .and_then(Value::as_str)
                        == Some("jvm.micronaut-route")
            })
            .collect::<Vec<_>>();

        assert_eq!(routes.len(), 3, "{:#?}", map.surfaces);
        assert!(routes
            .iter()
            .all(|surface| surface.framework.as_deref() == Some("Micronaut")));
        assert!(routes.iter().any(|surface| {
            surface.method.as_deref() == Some("GET")
                && surface.route.as_deref() == Some("/accounts")
        }));
        assert!(routes.iter().any(|surface| {
            surface.method.as_deref() == Some("GET")
                && surface.route.as_deref() == Some("/accounts/{id}")
        }));
        assert!(routes.iter().any(|surface| {
            surface.method.as_deref() == Some("POST")
                && surface.route.as_deref() == Some("/accounts/recovery")
        }));
    }

    #[test]
    fn attack_surface_detects_jvm_ktor_routes() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/kotlin/app")).unwrap();
        fs::write(
            temp.path().join("build.gradle.kts"),
            "plugins { kotlin(\"jvm\") }\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("src/main/kotlin/app/Routing.kt"),
            r#"
              import io.ktor.server.routing.routing
              import io.ktor.server.routing.route
              import io.ktor.server.routing.get
              import io.ktor.server.routing.post
              fun Application.routes() {
                routing {
                  route("/accounts") {
                    get { call.respond(accounts) }
                    get("/{id}") { call.respond(account) }
                    post("/recovery") { call.respond(recovered) }
                    head("/status") { call.respond(status) }
                    options("/preflight") { call.respond(options) }
                  }
                }
              }
            "#,
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();
        let routes = map
            .surfaces
            .iter()
            .filter(|surface| {
                surface.kind == AttackSurfaceKind::HttpRoute
                    && surface
                        .metadata
                        .pointer("/detector")
                        .and_then(Value::as_str)
                        == Some("jvm.ktor-route")
            })
            .collect::<Vec<_>>();

        assert_eq!(routes.len(), 5, "{:#?}", map.surfaces);
        assert!(routes
            .iter()
            .all(|surface| surface.framework.as_deref() == Some("Ktor")));
        assert!(routes.iter().any(|surface| {
            surface.method.as_deref() == Some("GET")
                && surface.route.as_deref() == Some("/accounts")
                && surface.language == "Kotlin"
        }));
        assert!(routes.iter().any(|surface| {
            surface.method.as_deref() == Some("GET")
                && surface.route.as_deref() == Some("/accounts/{id}")
                && surface.language == "Kotlin"
        }));
        assert!(routes.iter().any(|surface| {
            surface.method.as_deref() == Some("POST")
                && surface.route.as_deref() == Some("/accounts/recovery")
                && surface.language == "Kotlin"
        }));
        assert!(routes.iter().any(|surface| {
            surface.method.as_deref() == Some("HEAD")
                && surface.route.as_deref() == Some("/accounts/status")
                && surface.language == "Kotlin"
        }));
        assert!(routes.iter().any(|surface| {
            surface.method.as_deref() == Some("OPTIONS")
                && surface.route.as_deref() == Some("/accounts/preflight")
                && surface.language == "Kotlin"
        }));
    }

    #[test]
    fn attack_surface_detects_jvm_javalin_routes() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/JavalinRoutes.java"),
            r#"
              import io.javalin.Javalin;
              import static io.javalin.apibuilder.ApiBuilder.*;
              class JavalinRoutes {
                void routes() {
                  var app = Javalin.create();
                  app.get("/accounts/{id}", ctx -> ctx.result("ok"));
                  app.post("/accounts/recovery", ctx -> ctx.result("ok"));
                  app.head("/accounts/status", ctx -> ctx.result("ok"));
                  app.options("/accounts/preflight", ctx -> ctx.result("ok"));
                  app.routes(() -> path("teams", () -> {
                    get("/{id}", ctx -> ctx.result("ok"));
                    post("/invite", ctx -> ctx.result("ok"));
                  }));
                }
              }
            "#,
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();
        let routes = map
            .surfaces
            .iter()
            .filter(|surface| {
                surface.kind == AttackSurfaceKind::HttpRoute
                    && surface
                        .metadata
                        .pointer("/detector")
                        .and_then(Value::as_str)
                        == Some("jvm.javalin-route")
            })
            .collect::<Vec<_>>();

        assert_eq!(routes.len(), 6, "{:#?}", map.surfaces);
        assert!(routes
            .iter()
            .all(|surface| surface.framework.as_deref() == Some("Javalin")));
        assert!(routes.iter().any(|surface| {
            surface.method.as_deref() == Some("GET")
                && surface.route.as_deref() == Some("/accounts/{id}")
        }));
        assert!(routes.iter().any(|surface| {
            surface.method.as_deref() == Some("POST")
                && surface.route.as_deref() == Some("/accounts/recovery")
        }));
        assert!(routes.iter().any(|surface| {
            surface.method.as_deref() == Some("HEAD")
                && surface.route.as_deref() == Some("/accounts/status")
        }));
        assert!(routes.iter().any(|surface| {
            surface.method.as_deref() == Some("OPTIONS")
                && surface.route.as_deref() == Some("/accounts/preflight")
        }));
        assert!(routes.iter().any(|surface| {
            surface.method.as_deref() == Some("GET")
                && surface.route.as_deref() == Some("/teams/{id}")
        }));
        assert!(routes.iter().any(|surface| {
            surface.method.as_deref() == Some("POST")
                && surface.route.as_deref() == Some("/teams/invite")
        }));
    }

    #[test]
    fn attack_surface_detects_jvm_spark_java_routes() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/SparkRoutes.java"),
            r#"
              import spark.Spark;
              import static spark.Spark.*;
              class SparkRoutes {
                void routes() {
                  Spark.get("/accounts/:id", (request, response) -> "ok");
                  Spark.post("/accounts/recovery", (request, response) -> "ok");
                  Spark.head("/accounts/status", (request, response) -> "");
                  Spark.before("/admin/*", (request, response) -> {});
                  get("/teams/invite", (request, response) -> "ok");
                  head("/teams/status", (request, response) -> "");
                  after("/audit/*", (request, response) -> {});
                }
              }
            "#,
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();
        let routes = map
            .surfaces
            .iter()
            .filter(|surface| {
                surface.kind == AttackSurfaceKind::HttpRoute
                    && surface
                        .metadata
                        .pointer("/detector")
                        .and_then(Value::as_str)
                        == Some("jvm.spark-route")
            })
            .collect::<Vec<_>>();

        assert_eq!(routes.len(), 7, "{:#?}", map.surfaces);
        assert!(routes
            .iter()
            .all(|surface| surface.framework.as_deref() == Some("Spark Java")));
        assert!(routes.iter().any(|surface| {
            surface.method.as_deref() == Some("GET")
                && surface.route.as_deref() == Some("/accounts/:id")
        }));
        assert!(routes.iter().any(|surface| {
            surface.method.as_deref() == Some("POST")
                && surface.route.as_deref() == Some("/accounts/recovery")
        }));
        assert!(routes.iter().any(|surface| {
            surface.method.as_deref() == Some("HEAD")
                && surface.route.as_deref() == Some("/accounts/status")
        }));
        assert!(routes.iter().any(|surface| {
            surface.method.as_deref() == Some("GET")
                && surface.route.as_deref() == Some("/teams/invite")
        }));
        assert!(routes.iter().any(|surface| {
            surface.method.as_deref() == Some("HEAD")
                && surface.route.as_deref() == Some("/teams/status")
        }));
        assert!(routes.iter().any(|surface| {
            surface.method.as_deref() == Some("ANY") && surface.route.as_deref() == Some("/admin/*")
        }));
        assert!(routes.iter().any(|surface| {
            surface.method.as_deref() == Some("ANY") && surface.route.as_deref() == Some("/audit/*")
        }));
    }

    #[test]
    fn attack_surface_detects_jvm_jooby_routes() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/JoobyRoutes.java"),
            r#"
              import io.jooby.Jooby;
              class JoobyRoutes extends Jooby {
                {
                  path("/accounts", () -> {
                    get("/{id}", ctx -> "ok");
                    post("/recovery", ctx -> "ok");
                    head("/status", ctx -> "ok");
                    options("/preflight", ctx -> "ok");
                    all("/audit", ctx -> "ok");
                  });
                }
              }
            "#,
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();
        let routes = map
            .surfaces
            .iter()
            .filter(|surface| {
                surface.kind == AttackSurfaceKind::HttpRoute
                    && surface
                        .metadata
                        .pointer("/detector")
                        .and_then(Value::as_str)
                        == Some("jvm.jooby-route")
            })
            .collect::<Vec<_>>();

        assert_eq!(routes.len(), 5, "{:#?}", map.surfaces);
        assert!(routes
            .iter()
            .all(|surface| surface.framework.as_deref() == Some("Jooby")));
        assert!(routes.iter().any(|surface| {
            surface.method.as_deref() == Some("GET")
                && surface.route.as_deref() == Some("/accounts/{id}")
        }));
        assert!(routes.iter().any(|surface| {
            surface.method.as_deref() == Some("POST")
                && surface.route.as_deref() == Some("/accounts/recovery")
        }));
        assert!(routes.iter().any(|surface| {
            surface.method.as_deref() == Some("HEAD")
                && surface.route.as_deref() == Some("/accounts/status")
        }));
        assert!(routes.iter().any(|surface| {
            surface.method.as_deref() == Some("OPTIONS")
                && surface.route.as_deref() == Some("/accounts/preflight")
        }));
        assert!(routes.iter().any(|surface| {
            surface.method.as_deref() == Some("ANY")
                && surface.route.as_deref() == Some("/accounts/audit")
        }));
        assert!(routes
            .iter()
            .all(|surface| surface.framework.as_deref() != Some("Ktor")));
    }

    #[test]
    fn attack_surface_detects_jvm_vertx_web_routes() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/VertxRoutes.java"),
            r#"
              import io.vertx.ext.web.Router;
              class VertxRoutes {
                void routes(Vertx vertx) {
                  Router router = Router.router(vertx);
                  router.get("/accounts/:id").handler(ctx -> ctx.response().end("ok"));
                  router.post("/accounts/recovery").handler(ctx -> ctx.response().end("ok"));
                  router.head("/accounts/status").handler(ctx -> ctx.response().end("ok"));
                  router.route("/accounts").handler(ctx -> ctx.response().end("ok"));
                }
              }
            "#,
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();
        let routes = map
            .surfaces
            .iter()
            .filter(|surface| {
                surface.kind == AttackSurfaceKind::HttpRoute
                    && surface
                        .metadata
                        .pointer("/detector")
                        .and_then(Value::as_str)
                        == Some("jvm.vertx-route")
            })
            .collect::<Vec<_>>();

        assert_eq!(routes.len(), 4, "{:#?}", map.surfaces);
        assert!(routes
            .iter()
            .all(|surface| surface.framework.as_deref() == Some("Vert.x")));
        assert!(routes.iter().any(|surface| {
            surface.method.as_deref() == Some("GET")
                && surface.route.as_deref() == Some("/accounts/:id")
        }));
        assert!(routes.iter().any(|surface| {
            surface.method.as_deref() == Some("POST")
                && surface.route.as_deref() == Some("/accounts/recovery")
        }));
        assert!(routes.iter().any(|surface| {
            surface.method.as_deref() == Some("HEAD")
                && surface.route.as_deref() == Some("/accounts/status")
        }));
        assert!(routes.iter().any(|surface| {
            surface.method.as_deref() == Some("ANY")
                && surface.route.as_deref() == Some("/accounts")
        }));
    }

    #[test]
    fn attack_surface_detects_jvm_vertx_http_method_routes() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path()
                .join("src/main/java/app/VertxHttpMethodRoutes.java"),
            r#"
              import io.vertx.core.http.HttpMethod;
              import io.vertx.ext.web.Router;
              class VertxHttpMethodRoutes {
                void routes(Vertx vertx) {
                  Router router = Router.router(vertx);
                  router.route(HttpMethod.GET, "/accounts/:id").handler(this::show);
                  router.route(HttpMethod.POST, "/accounts/recovery").handler(this::recover);
                  router.route(HttpMethod.HEAD, "/accounts/status").handler(this::status);
                }
              }
            "#,
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();
        let routes = map
            .surfaces
            .iter()
            .filter(|surface| {
                surface.kind == AttackSurfaceKind::HttpRoute
                    && surface
                        .metadata
                        .pointer("/detector")
                        .and_then(Value::as_str)
                        == Some("jvm.vertx-route")
            })
            .collect::<Vec<_>>();

        assert_eq!(routes.len(), 3, "{:#?}", map.surfaces);
        assert!(routes.iter().any(|surface| {
            surface.method.as_deref() == Some("GET")
                && surface.route.as_deref() == Some("/accounts/:id")
        }));
        assert!(routes.iter().any(|surface| {
            surface.method.as_deref() == Some("POST")
                && surface.route.as_deref() == Some("/accounts/recovery")
        }));
        assert!(routes.iter().any(|surface| {
            surface.method.as_deref() == Some("HEAD")
                && surface.route.as_deref() == Some("/accounts/status")
        }));
    }

    #[test]
    fn attack_surface_detects_jvm_armeria_routes() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/ArmeriaRoutes.java"),
            r#"
              import com.linecorp.armeria.server.Server;
              class ArmeriaRoutes {
                void routes() {
                  var server = Server.builder();
                  server.service("/accounts/{id}", accountService);
                  server.serviceUnder("/accounts/recovery", recoveryService);
                  server.annotatedService("/admin", adminService);
                  server.route().get("/accounts", accountListService);
                  server.route().post("/accounts/import", accountImportService);
                  server.route().head("/accounts/status", accountStatusService);
                  server.route().path("/accounts/audit").build(accountAuditService);
                }
              }
            "#,
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();
        let routes = map
            .surfaces
            .iter()
            .filter(|surface| {
                surface.kind == AttackSurfaceKind::HttpRoute
                    && surface
                        .metadata
                        .pointer("/detector")
                        .and_then(Value::as_str)
                        == Some("jvm.armeria-route")
            })
            .collect::<Vec<_>>();

        assert_eq!(routes.len(), 7, "{:#?}", map.surfaces);
        assert!(routes
            .iter()
            .all(|surface| surface.framework.as_deref() == Some("Armeria")));
        assert!(routes.iter().any(|surface| {
            surface.method.as_deref() == Some("ANY")
                && surface.route.as_deref() == Some("/accounts/{id}")
        }));
        assert!(routes.iter().any(|surface| {
            surface.method.as_deref() == Some("ANY")
                && surface.route.as_deref() == Some("/accounts/recovery")
        }));
        assert!(routes.iter().any(|surface| {
            surface.method.as_deref() == Some("ANY") && surface.route.as_deref() == Some("/admin")
        }));
        assert!(routes.iter().any(|surface| {
            surface.method.as_deref() == Some("GET")
                && surface.route.as_deref() == Some("/accounts")
        }));
        assert!(routes.iter().any(|surface| {
            surface.method.as_deref() == Some("POST")
                && surface.route.as_deref() == Some("/accounts/import")
        }));
        assert!(routes.iter().any(|surface| {
            surface.method.as_deref() == Some("HEAD")
                && surface.route.as_deref() == Some("/accounts/status")
        }));
        assert!(routes.iter().any(|surface| {
            surface.method.as_deref() == Some("ANY")
                && surface.route.as_deref() == Some("/accounts/audit")
        }));
    }

    #[test]
    fn attack_surface_detects_jvm_helidon_routes() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/HelidonRoutes.java"),
            r#"
              import io.helidon.webserver.WebServer;
              import io.helidon.webserver.Routing;
              class HelidonRoutes {
                void routes() {
                  var routing = Routing.builder();
                  routing.register("/accounts", rules -> {
                    rules.get("/{id}", this::show);
                    rules.post("/recovery", this::recover);
                    rules.head("/status", this::status);
                    rules.any("/audit", this::audit);
                  });
                  WebServer.builder().routing(routing).build();
                }
              }
            "#,
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();
        let routes = map
            .surfaces
            .iter()
            .filter(|surface| {
                surface.kind == AttackSurfaceKind::HttpRoute
                    && surface
                        .metadata
                        .pointer("/detector")
                        .and_then(Value::as_str)
                        == Some("jvm.helidon-route")
            })
            .collect::<Vec<_>>();

        assert_eq!(routes.len(), 4, "{:#?}", map.surfaces);
        assert!(routes
            .iter()
            .all(|surface| surface.framework.as_deref() == Some("Helidon")));
        assert!(routes.iter().any(|surface| {
            surface.method.as_deref() == Some("GET")
                && surface.route.as_deref() == Some("/accounts/{id}")
        }));
        assert!(routes.iter().any(|surface| {
            surface.method.as_deref() == Some("POST")
                && surface.route.as_deref() == Some("/accounts/recovery")
        }));
        assert!(routes.iter().any(|surface| {
            surface.method.as_deref() == Some("HEAD")
                && surface.route.as_deref() == Some("/accounts/status")
        }));
        assert!(routes.iter().any(|surface| {
            surface.method.as_deref() == Some("ANY")
                && surface.route.as_deref() == Some("/accounts/audit")
        }));
    }

    #[test]
    fn attack_surface_detects_jvm_ratpack_routes() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/RatpackRoutes.java"),
            r#"
              import ratpack.server.RatpackServer;
              class RatpackRoutes {
                void routes() throws Exception {
                  RatpackServer.start(server -> server.handlers(chain -> {
                    chain.prefix("accounts", account -> {
                      account.get(":id", ctx -> ctx.render("ok"));
                      account.post("recovery", ctx -> ctx.render("ok"));
                      account.head("status", ctx -> ctx.render("ok"));
                      account.options("preflight", ctx -> ctx.render("ok"));
                      account.all("audit", ctx -> ctx.render("ok"));
                    });
                  }));
                }
              }
            "#,
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();
        let routes = map
            .surfaces
            .iter()
            .filter(|surface| {
                surface.kind == AttackSurfaceKind::HttpRoute
                    && surface
                        .metadata
                        .pointer("/detector")
                        .and_then(Value::as_str)
                        == Some("jvm.ratpack-route")
            })
            .collect::<Vec<_>>();

        assert_eq!(routes.len(), 5, "{:#?}", map.surfaces);
        assert!(routes
            .iter()
            .all(|surface| surface.framework.as_deref() == Some("Ratpack")));
        assert!(routes.iter().any(|surface| {
            surface.method.as_deref() == Some("GET")
                && surface.route.as_deref() == Some("/accounts/:id")
        }));
        assert!(routes.iter().any(|surface| {
            surface.method.as_deref() == Some("POST")
                && surface.route.as_deref() == Some("/accounts/recovery")
        }));
        assert!(routes.iter().any(|surface| {
            surface.method.as_deref() == Some("HEAD")
                && surface.route.as_deref() == Some("/accounts/status")
        }));
        assert!(routes.iter().any(|surface| {
            surface.method.as_deref() == Some("OPTIONS")
                && surface.route.as_deref() == Some("/accounts/preflight")
        }));
        assert!(routes.iter().any(|surface| {
            surface.method.as_deref() == Some("ANY")
                && surface.route.as_deref() == Some("/accounts/audit")
        }));
    }

    #[test]
    fn attack_surface_detects_jvm_undertow_routes() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/UndertowRoutes.java"),
            r#"
              import io.undertow.Handlers;
              import io.undertow.Undertow;
              class UndertowRoutes {
                void routes() {
                  var paths = Handlers.path();
                  paths.addExactPath("/accounts/{id}", accountHandler);
                  paths.addPrefixPath("/accounts/recovery", recoveryHandler);
                  var routes = Handlers.routing();
                  routes.get("/accounts", listHandler);
                  routes.post("/accounts/import", importHandler);
                  routes.head("/accounts/status", statusHandler);
                  routes.options("/accounts/preflight", optionsHandler);
                  Undertow.builder().setHandler(paths).build();
                }
              }
            "#,
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();
        let routes = map
            .surfaces
            .iter()
            .filter(|surface| {
                surface.kind == AttackSurfaceKind::HttpRoute
                    && surface
                        .metadata
                        .pointer("/detector")
                        .and_then(Value::as_str)
                        == Some("jvm.undertow-route")
            })
            .collect::<Vec<_>>();

        assert_eq!(routes.len(), 6, "{:#?}", map.surfaces);
        assert!(routes
            .iter()
            .all(|surface| surface.framework.as_deref() == Some("Undertow")));
        assert!(routes.iter().any(|surface| {
            surface.method.as_deref() == Some("ANY")
                && surface.route.as_deref() == Some("/accounts/{id}")
        }));
        assert!(routes.iter().any(|surface| {
            surface.method.as_deref() == Some("ANY")
                && surface.route.as_deref() == Some("/accounts/recovery")
        }));
        assert!(routes.iter().any(|surface| {
            surface.method.as_deref() == Some("GET")
                && surface.route.as_deref() == Some("/accounts")
        }));
        assert!(routes.iter().any(|surface| {
            surface.method.as_deref() == Some("POST")
                && surface.route.as_deref() == Some("/accounts/import")
        }));
        assert!(routes.iter().any(|surface| {
            surface.method.as_deref() == Some("HEAD")
                && surface.route.as_deref() == Some("/accounts/status")
        }));
        assert!(routes.iter().any(|surface| {
            surface.method.as_deref() == Some("OPTIONS")
                && surface.route.as_deref() == Some("/accounts/preflight")
        }));
    }

    #[test]
    fn attack_surface_detects_jvm_servlet_and_webflux_upload_parsers() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/UploadParsers.java"),
            r#"
              import org.springframework.web.bind.annotation.PostMapping;
              class UploadParsers {
                @PostMapping(path = "/imports/reactive", consumes = "multipart/form-data")
                void reactive(FilePart filePart, Flux<PartEvent> partEvents) {}
                void servlet(jakarta.servlet.http.Part servletPart) {}
                void legacy(javax.servlet.http.Part servletPart) {}
                void outbound(MultipartBodyBuilder multipartBodyBuilder) {}
              }
            "#,
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();
        let uploads = map
            .surfaces
            .iter()
            .filter(|surface| {
                surface.kind == AttackSurfaceKind::FileUploadParsePath
                    && surface
                        .metadata
                        .pointer("/detector")
                        .and_then(Value::as_str)
                        == Some("jvm.file-upload")
            })
            .collect::<Vec<_>>();

        assert_eq!(uploads.len(), 5, "{:#?}", map.surfaces);
        assert!(uploads
            .iter()
            .all(|surface| surface.framework.as_deref() == Some("Spring")));
        assert!(uploads
            .iter()
            .all(|surface| surface.boundary.as_deref() == Some("file_upload")));
    }

    #[test]
    fn attack_surface_detects_jvm_multipart_configuration_upload_boundaries() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/MultipartConfig.java"),
            r#"
              import org.springframework.web.multipart.support.StandardServletMultipartResolver;
              @MultipartConfig(fileSizeThreshold = 1024)
              class MultipartConfig {
                CommonsMultipartResolver commonsMultipartResolver;
                StandardServletMultipartResolver standardServletMultipartResolver;
                MultipartConfigElement multipartConfigElement;
                MultipartConfigFactory multipartConfigFactory;
                void limits(Object resolver, Object factory) {
                  resolver.setMaxUploadSize(1048576);
                  factory.setMaxFileSize(DataSize.ofMegabytes(10));
                  factory.setMaxRequestSize(DataSize.ofMegabytes(20));
                  factory.setFileSizeThreshold(DataSize.ofKilobytes(512));
                }
              }
            "#,
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();
        let uploads = map
            .surfaces
            .iter()
            .filter(|surface| {
                surface.kind == AttackSurfaceKind::FileUploadParsePath
                    && surface
                        .metadata
                        .pointer("/detector")
                        .and_then(Value::as_str)
                        == Some("jvm.file-upload")
            })
            .collect::<Vec<_>>();

        assert_eq!(uploads.len(), 9, "{:#?}", map.surfaces);
        assert!(uploads
            .iter()
            .all(|surface| surface.framework.as_deref() == Some("Spring")));
        assert!(uploads
            .iter()
            .all(|surface| surface.boundary.as_deref() == Some("file_upload")));
    }

    #[test]
    fn attack_surface_detects_jvm_serializer_frameworks_as_parser_boundaries() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/PayloadParsers.java"),
            r#"
              import org.springframework.web.bind.annotation.PostMapping;
              class PayloadParsers {
                @PostMapping("/imports/payload")
                void parse(String body, InputStream stream) {
                  objectMapper.readTree(body);
                  objectMapper.convertValue(node, Payload.class);
                  xmlMapper.readValue(body, Payload.class);
                  xstream.fromXML(body);
                  JAXBContext.newInstance(Payload.class).createUnmarshaller().unmarshal(stream);
                  new ObjectInputStream(stream).readObject();
                  kryo.readObject(input, Payload.class);
                  kryo.readClassAndObject(input);
                  Payload.parser().parseFrom(bytes);
                  new Jackson2JsonDecoder();
                  yaml.load(body);
                }
              }
            "#,
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();
        let parsers = map
            .surfaces
            .iter()
            .filter(|surface| {
                surface.kind == AttackSurfaceKind::DeserializationPoint
                    && surface
                        .metadata
                        .pointer("/detector")
                        .and_then(Value::as_str)
                        == Some("jvm.deserialization")
            })
            .collect::<Vec<_>>();

        assert_eq!(parsers.len(), 11, "{:#?}", map.surfaces);
        assert!(parsers
            .iter()
            .all(|surface| surface.framework.as_deref() == Some("Spring")));
        assert!(parsers
            .iter()
            .all(|surface| surface.boundary.as_deref() == Some("parser_boundary")));
    }

    #[test]
    fn attack_surface_detects_jvm_parser_factory_boundaries() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/ParserFactories.java"),
            r#"
              import org.springframework.stereotype.Service;
              @Service
              class ParserFactories {
                void parse(String body, InputStream stream) {
                  DocumentBuilderFactory.newInstance();
                  SAXParserFactory.newInstance();
                  XMLInputFactory.newFactory();
                  XMLInputFactory.newInstance();
                  JsonPath.parse(body);
                  gson.fromJson(body, Payload.class);
                  jsonb.fromJson(body, Payload.class);
                  objectReader.readValue(body);
                  properties.load(stream);
                  properties.loadFromXML(stream);
                  new YAMLMapper();
                }
              }
            "#,
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();
        let parsers = map
            .surfaces
            .iter()
            .filter(|surface| {
                surface.kind == AttackSurfaceKind::DeserializationPoint
                    && surface
                        .metadata
                        .pointer("/detector")
                        .and_then(Value::as_str)
                        == Some("jvm.deserialization")
            })
            .collect::<Vec<_>>();

        assert_eq!(parsers.len(), 11, "{:#?}", map.surfaces);
        assert!(parsers
            .iter()
            .all(|surface| surface.framework.as_deref() == Some("Spring")));
        assert!(parsers
            .iter()
            .all(|surface| surface.boundary.as_deref() == Some("parser_boundary")));
    }

    #[test]
    fn attack_surface_detects_jvm_archive_parsers_as_parser_boundaries() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/ArchiveParsers.java"),
            r#"
              import org.springframework.stereotype.Service;
              @Service
              class ArchiveParsers {
                void parse(InputStream stream, File file) {
                  new ZipInputStream(stream);
                  new ZipFile(file);
                  new GZIPInputStream(stream);
                  ArchiveInputStream archiveInputStream;
                  new ArchiveStreamFactory().createArchiveInputStream(stream);
                  org.apache.commons.compress.archivers.tar.TarArchiveInputStream tarStream;
                }
              }
            "#,
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();
        let parsers = map
            .surfaces
            .iter()
            .filter(|surface| {
                surface.kind == AttackSurfaceKind::DeserializationPoint
                    && surface
                        .metadata
                        .pointer("/detector")
                        .and_then(Value::as_str)
                        == Some("jvm.deserialization")
            })
            .collect::<Vec<_>>();

        assert_eq!(parsers.len(), 6, "{:#?}", map.surfaces);
        assert!(parsers
            .iter()
            .all(|surface| surface.framework.as_deref() == Some("Spring")));
        assert!(parsers
            .iter()
            .all(|surface| surface.boundary.as_deref() == Some("parser_boundary")));
    }

    #[test]
    fn attack_surface_detects_jvm_document_parsers_as_parser_boundaries() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/DocumentParsers.java"),
            r#"
              import org.springframework.stereotype.Service;
              @Service
              class DocumentParsers {
                void parse(InputStream stream, Reader reader, File file) {
                  CSVMapper csvMapper;
                  CSVParser.parse(reader, CSVFormat.DEFAULT);
                  CSVFormat.DEFAULT.parse(reader);
                  WorkbookFactory.create(stream);
                  new XSSFWorkbook(stream);
                  new HSSFWorkbook(stream);
                  AutoDetectParser autoDetectParser;
                  tika.parseToString(file);
                }
              }
            "#,
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();
        let parsers = map
            .surfaces
            .iter()
            .filter(|surface| {
                surface.kind == AttackSurfaceKind::DeserializationPoint
                    && surface
                        .metadata
                        .pointer("/detector")
                        .and_then(Value::as_str)
                        == Some("jvm.deserialization")
            })
            .collect::<Vec<_>>();

        assert_eq!(parsers.len(), 8, "{:#?}", map.surfaces);
        assert!(parsers
            .iter()
            .all(|surface| surface.framework.as_deref() == Some("Spring")));
        assert!(parsers
            .iter()
            .all(|surface| surface.boundary.as_deref() == Some("parser_boundary")));
    }

    #[test]
    fn attack_surface_detects_jvm_process_frameworks_as_command_execution() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/CommandRunners.java"),
            r#"
              import org.springframework.stereotype.Service;
              @Service
              class CommandRunners {
                void run(String command, List<String> commands) {
                  Runtime.getRuntime().exec(command);
                  Runtime.getRuntime().load(libraryPath);
                  Runtime.getRuntime().loadLibrary(libraryName);
                  new ProcessBuilder(command).start();
                  ProcessBuilder.startPipeline(commands);
                  CommandLine parsed = CommandLine.parse(command);
                  new DefaultExecutor().execute(parsed);
                  new ProcessExecutor().command(command).execute();
                  ProcessUtils.execute(command);
                  ProcessImpl.start(command, env, dir, redirects, false);
                }
              }
            "#,
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();
        let commands = map
            .surfaces
            .iter()
            .filter(|surface| {
                surface.kind == AttackSurfaceKind::CommandExecutionBoundary
                    && surface
                        .metadata
                        .pointer("/detector")
                        .and_then(Value::as_str)
                        == Some("jvm.command-exec")
            })
            .collect::<Vec<_>>();

        assert_eq!(commands.len(), 10, "{:#?}", map.surfaces);
        assert!(commands
            .iter()
            .all(|surface| surface.framework.as_deref() == Some("Spring")));
        assert!(commands
            .iter()
            .all(|surface| surface.boundary.as_deref() == Some("process_execution")));
    }

    #[test]
    fn attack_surface_detects_jvm_client_frameworks_as_external_services() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/BillingClients.java"),
            r#"
              import org.springframework.cloud.openfeign.FeignClient;
              @FeignClient(name = "billing", url = "${billing.url}")
              interface BillingFeign {}
              class BillingClients {
                void call(String url) {
                  Feign.builder().target(BillingFeign.class, url);
                  ClientBuilder.newClient();
                  WebTarget target = client.target(url);
                  new Retrofit.Builder().baseUrl(url).build();
                  retrofit.create(BillingApi.class);
                }
              }
            "#,
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();
        let clients = map
            .surfaces
            .iter()
            .filter(|surface| {
                surface.kind == AttackSurfaceKind::ExternalServiceClient
                    && surface
                        .metadata
                        .pointer("/detector")
                        .and_then(Value::as_str)
                        == Some("jvm.external-client")
            })
            .collect::<Vec<_>>();

        assert_eq!(clients.len(), 6, "{:#?}", map.surfaces);
        assert!(clients
            .iter()
            .all(|surface| surface.framework.as_deref() == Some("Spring")));
        assert!(clients
            .iter()
            .all(|surface| surface.boundary.as_deref() == Some("external_service")));
    }

    #[test]
    fn attack_surface_detects_jvm_core_http_clients_as_external_services() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/CoreHttpClients.java"),
            r#"
              import org.springframework.stereotype.Service;
              @Service
              class CoreHttpClients {
                void call() {
                  HttpClient.newHttpClient();
                  HttpClient.newBuilder().build();
                  URI.create("https://billing.example");
                  new URL("https://billing.example");
                  url.openConnection();
                  HttpURLConnection connection;
                  AsyncHttpClient asyncHttpClient;
                  vertx.createHttpClient();
                }
              }
            "#,
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();
        let clients = map
            .surfaces
            .iter()
            .filter(|surface| {
                surface.kind == AttackSurfaceKind::ExternalServiceClient
                    && surface
                        .metadata
                        .pointer("/detector")
                        .and_then(Value::as_str)
                        == Some("jvm.external-client")
            })
            .collect::<Vec<_>>();

        assert_eq!(clients.len(), 8, "{:#?}", map.surfaces);
        assert!(clients
            .iter()
            .all(|surface| surface.framework.as_deref() == Some("Spring")));
        assert!(clients
            .iter()
            .all(|surface| surface.boundary.as_deref() == Some("external_service")));
    }

    #[test]
    fn attack_surface_detects_jvm_apache_http_clients_as_external_services() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/ApacheHttpClients.java"),
            r#"
              import org.springframework.stereotype.Service;
              @Service
              class ApacheHttpClients {
                CloseableHttpClient closeableHttpClient;
                void call() {
                  HttpClients.createDefault();
                  HttpClients.custom().build();
                  HttpAsyncClients.createDefault();
                  new HttpGet("https://billing.example");
                  new HttpPost("https://billing.example/refund");
                  ClassicRequestBuilder.get("https://billing.example").build();
                }
              }
            "#,
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();
        let clients = map
            .surfaces
            .iter()
            .filter(|surface| {
                surface.kind == AttackSurfaceKind::ExternalServiceClient
                    && surface
                        .metadata
                        .pointer("/detector")
                        .and_then(Value::as_str)
                        == Some("jvm.external-client")
            })
            .collect::<Vec<_>>();

        assert_eq!(clients.len(), 7, "{:#?}", map.surfaces);
        assert!(clients
            .iter()
            .all(|surface| surface.framework.as_deref() == Some("Spring")));
        assert!(clients
            .iter()
            .all(|surface| surface.boundary.as_deref() == Some("external_service")));
    }

    #[test]
    fn attack_surface_detects_jvm_okhttp_clients_as_external_services() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/OkHttpClients.java"),
            r#"
              import org.springframework.stereotype.Service;
              @Service
              class OkHttpClients {
                OkHttpClient okHttpClient;
                Call.Factory callFactory;
                void call() {
                  new Request.Builder();
                  new Request.Builder().url("https://billing.example").build();
                  okHttpClient.newCall(request).execute();
                }
              }
            "#,
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();
        let clients = map
            .surfaces
            .iter()
            .filter(|surface| {
                surface.kind == AttackSurfaceKind::ExternalServiceClient
                    && surface
                        .metadata
                        .pointer("/detector")
                        .and_then(Value::as_str)
                        == Some("jvm.external-client")
            })
            .collect::<Vec<_>>();

        assert_eq!(clients.len(), 6, "{:#?}", map.surfaces);
        assert!(clients
            .iter()
            .all(|surface| surface.framework.as_deref() == Some("Spring")));
        assert!(clients
            .iter()
            .all(|surface| surface.boundary.as_deref() == Some("external_service")));
    }

    #[test]
    fn attack_surface_detects_jvm_grpc_clients_as_external_services() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/GrpcClients.java"),
            r#"
              import org.springframework.stereotype.Service;
              @Service
              class GrpcClients {
                void call() {
                  ManagedChannelBuilder.forAddress("billing", 443).useTransportSecurity();
                  ManagedChannel channel;
                  GrpcChannelBuilder grpcChannelBuilder;
                  BillingGrpc.newBlockingStub(channel);
                  BillingGrpc.newFutureStub(channel);
                  BillingGrpc.newStub(channel);
                  stub.useStub(callOptions);
                }
              }
            "#,
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();
        let clients = map
            .surfaces
            .iter()
            .filter(|surface| {
                surface.kind == AttackSurfaceKind::ExternalServiceClient
                    && surface
                        .metadata
                        .pointer("/detector")
                        .and_then(Value::as_str)
                        == Some("jvm.external-client")
            })
            .collect::<Vec<_>>();

        assert_eq!(clients.len(), 7, "{:#?}", map.surfaces);
        assert!(clients
            .iter()
            .all(|surface| surface.framework.as_deref() == Some("Spring")));
        assert!(clients
            .iter()
            .all(|surface| surface.boundary.as_deref() == Some("external_service")));
    }

    #[test]
    fn attack_surface_detects_jvm_graphql_clients_as_external_services() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/GraphQlClients.java"),
            r#"
              import org.springframework.graphql.client.HttpGraphQlClient;
              import org.springframework.stereotype.Service;
              @Service
              class GraphQlClients {
                void call() {
                  HttpGraphQlClient.builder(webClient).build();
                  WebSocketGraphQlClient.builder(url, client).build();
                  RSocketGraphQlClient.builder(requester).build();
                  GraphQlClient graphQlClient;
                  GraphQlClient.create(transport);
                  GraphQlClient.builder(transport).build();
                  DgsGraphQLClient dgsGraphQLClient;
                  DgsReactiveGraphQLClient dgsReactiveGraphQLClient;
                }
              }
            "#,
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();
        let clients = map
            .surfaces
            .iter()
            .filter(|surface| {
                surface.kind == AttackSurfaceKind::ExternalServiceClient
                    && surface
                        .metadata
                        .pointer("/detector")
                        .and_then(Value::as_str)
                        == Some("jvm.external-client")
            })
            .collect::<Vec<_>>();

        assert_eq!(clients.len(), 9, "{:#?}", map.surfaces);
        assert!(clients
            .iter()
            .all(|surface| surface.framework.as_deref() == Some("Spring")));
        assert!(clients
            .iter()
            .all(|surface| surface.boundary.as_deref() == Some("external_service")));
    }

    #[test]
    fn attack_surface_detects_jvm_soap_clients_as_external_services() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/SoapClients.java"),
            r#"
              import org.springframework.stereotype.Service;
              import org.springframework.ws.client.core.WebServiceTemplate;
              @Service
              class SoapClients {
                void call() {
                  WebServiceTemplate template;
                  template.marshalSendAndReceive(request);
                  JaxWsProxyFactoryBean factory;
                  Service.create(wsdlUrl, serviceName);
                  service.getPort(BillingPort.class);
                  SOAPConnectionFactory.newInstance();
                  SOAPConnection soapConnection;
                  soapConnection.call(message, endpoint);
                  Dispatch<SOAPMessage> dispatch;
                  org.apache.cxf.jaxrs.client.WebClient.create(endpoint);
                }
              }
            "#,
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();
        let clients = map
            .surfaces
            .iter()
            .filter(|surface| {
                surface.kind == AttackSurfaceKind::ExternalServiceClient
                    && surface
                        .metadata
                        .pointer("/detector")
                        .and_then(Value::as_str)
                        == Some("jvm.external-client")
            })
            .collect::<Vec<_>>();

        assert_eq!(clients.len(), 10, "{:#?}", map.surfaces);
        assert!(clients
            .iter()
            .all(|surface| surface.framework.as_deref() == Some("Spring")));
        assert!(clients
            .iter()
            .all(|surface| surface.boundary.as_deref() == Some("external_service")));
    }

    #[test]
    fn attack_surface_detects_jvm_spring_http_clients_as_external_services() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/HttpClients.java"),
            r#"
              import org.springframework.web.service.annotation.HttpExchange;
              @HttpExchange("/billing")
              interface BillingHttpApi {
                @GetExchange("/accounts/{id}")
                Account account(String id);
                @PostExchange("/accounts")
                Account create(Account account);
              }
              class HttpClients {
                RestClient restClient = RestClient.create(baseUrl);
                WebClient.Builder webClientBuilder;
                WebClient.create(baseUrl);
                HttpServiceProxyFactory.builderFor(adapter).build();
              }
            "#,
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();
        let clients = map
            .surfaces
            .iter()
            .filter(|surface| {
                surface.kind == AttackSurfaceKind::ExternalServiceClient
                    && surface
                        .metadata
                        .pointer("/detector")
                        .and_then(Value::as_str)
                        == Some("jvm.external-client")
            })
            .collect::<Vec<_>>();

        assert_eq!(clients.len(), 7, "{:#?}", map.surfaces);
        assert!(clients
            .iter()
            .all(|surface| surface.framework.as_deref() == Some("Spring")));
        assert!(clients
            .iter()
            .all(|surface| surface.boundary.as_deref() == Some("external_service")));
    }

    #[test]
    fn attack_surface_detects_jvm_object_storage_clients_as_external_services() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/ObjectStorageClients.java"),
            r#"
              import org.springframework.stereotype.Service;
              @Service
              class ObjectStorageClients {
                S3Client s3Client;
                S3Presigner s3Presigner;
                AmazonS3 amazonS3;
                TransferManager transferManager;
                BlobServiceClient blobServiceClient;
                BlobClient blobClient;
                com.google.cloud.storage.Storage storage = StorageOptions.getDefaultInstance().getService();
                MinioClient minioClient;
                OSSClient ossClient;
              }
            "#,
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();
        let clients = map
            .surfaces
            .iter()
            .filter(|surface| {
                surface.kind == AttackSurfaceKind::ExternalServiceClient
                    && surface
                        .metadata
                        .pointer("/detector")
                        .and_then(Value::as_str)
                        == Some("jvm.external-client")
            })
            .collect::<Vec<_>>();

        assert_eq!(clients.len(), 9, "{:#?}", map.surfaces);
        assert!(clients
            .iter()
            .all(|surface| surface.framework.as_deref() == Some("Spring")));
        assert!(clients
            .iter()
            .all(|surface| surface.boundary.as_deref() == Some("external_service")));
    }

    #[test]
    fn attack_surface_detects_jvm_actuator_and_openapi_routes() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/ObservabilityConfig.java"),
            r#"
              import org.springframework.boot.actuate.endpoint.annotation.Endpoint;
              import org.springdoc.core.models.GroupedOpenApi;
              @Endpoint(id = "tenantDiagnostics")
              class TenantDiagnosticsEndpoint {}
              class ApiDocsConfig {
                OpenAPI api() { return new OpenAPI(); }
                GroupedOpenApi publicApi() { return GroupedOpenApi.builder().group("public").build(); }
                void swagger(SwaggerUiConfigParameters swagger) {}
              }
            "#,
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();
        for (route, detector) in [
            ("/actuator/tenantDiagnostics", "jvm.spring-actuator-route"),
            ("/v3/api-docs", "jvm.spring-openapi-route"),
            ("/swagger-ui/index.html", "jvm.spring-openapi-route"),
        ] {
            assert!(map.surfaces.iter().any(|surface| {
                surface.kind == AttackSurfaceKind::HttpRoute
                    && surface.method.as_deref() == Some("GET")
                    && surface.route.as_deref() == Some(route)
                    && surface.framework.as_deref() == Some("Spring")
                    && surface
                        .metadata
                        .pointer("/detector")
                        .and_then(Value::as_str)
                        == Some(detector)
            }));
        }
    }

    #[test]
    fn attack_surface_detects_jvm_data_frameworks_as_data_stores() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/BillingStores.java"),
            r#"
              import org.springframework.data.jpa.repository.JpaRepository;
              @Repository
              interface InvoiceRepository extends JpaRepository<Invoice, String> {}
              interface TenantRepository extends CrudRepository<Tenant, String> {}
              class BillingStores {
                @Query("select i from Invoice i")
                List<Invoice> activeInvoices() {}
                void query(EntityManager entityManager, JdbcTemplate jdbcTemplate) {
                  entityManager.createNativeQuery("select * from invoice");
                  entityManager.createQuery("select i from Invoice i");
                  jdbcTemplate.update("update invoice set status = ?", status);
                  namedParameterJdbcTemplate.query(sql, params, mapper);
                  databaseClient.sql(sql).fetch();
                  r2dbcEntityTemplate.select(Invoice.class);
                  sessionFactory.openSession();
                  mongoTemplate.find(query, Invoice.class);
                }
              }
            "#,
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();
        let stores = map
            .surfaces
            .iter()
            .filter(|surface| {
                surface.kind == AttackSurfaceKind::DbQueryBoundary
                    && surface
                        .metadata
                        .pointer("/detector")
                        .and_then(Value::as_str)
                        == Some("jvm.db-query")
            })
            .collect::<Vec<_>>();

        assert_eq!(stores.len(), 12, "{:#?}", map.surfaces);
        assert!(stores
            .iter()
            .all(|surface| surface.framework.as_deref() == Some("Spring")));
        assert!(stores
            .iter()
            .all(|surface| surface.boundary.as_deref() == Some("data_store")));
    }

    #[test]
    fn attack_surface_detects_jvm_direct_jdbc_and_transaction_stores() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/DirectJdbcStores.java"),
            r#"
              import org.springframework.jdbc.core.simple.JdbcClient;
              class DirectJdbcStores {
                JdbcClient jdbcClient;
                SimpleJdbcInsert simpleJdbcInsert;
                SimpleJdbcCall simpleJdbcCall;
                TransactionTemplate transactionTemplate;
                void query(DataSource dataSource, Connection connection) {
                  JdbcClient.create(dataSource);
                  jdbcClient.sql("select * from invoice").query(Invoice.class);
                  dataSource.getConnection();
                  connection.prepareStatement("select * from invoice where id = ?");
                  transactionTemplate.execute(status -> jdbcTemplate.update(sql));
                }
              }
            "#,
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();
        let stores = map
            .surfaces
            .iter()
            .filter(|surface| {
                surface.kind == AttackSurfaceKind::DbQueryBoundary
                    && surface
                        .metadata
                        .pointer("/detector")
                        .and_then(Value::as_str)
                        == Some("jvm.db-query")
            })
            .collect::<Vec<_>>();

        assert_eq!(stores.len(), 8, "{:#?}", map.surfaces);
        assert!(stores
            .iter()
            .all(|surface| surface.framework.as_deref() == Some("Spring")));
        assert!(stores
            .iter()
            .all(|surface| surface.boundary.as_deref() == Some("data_store")));
    }

    #[test]
    fn attack_surface_detects_jvm_spring_data_store_clients() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/SearchStores.java"),
            r#"
              import org.springframework.data.elasticsearch.core.ElasticsearchOperations;
              import org.springframework.data.elasticsearch.repository.ElasticsearchRepository;
              import org.springframework.data.neo4j.core.Neo4jClient;
              import org.springframework.data.neo4j.repository.Neo4jRepository;
              @DynamoDBTable(tableName = "tenant_records")
              class TenantRecord {}
              interface SearchRepository extends ElasticsearchRepository<SearchDoc, String> {}
              interface GraphRepository extends Neo4jRepository<Node, String> {}
              interface AccountRepository extends CassandraRepository<Account, String> {}
              interface AuditRepository extends MongoRepository<Audit, String> {}
              interface SessionRepository extends RedisRepository<Session, String> {}
              class SearchStores {
                ElasticsearchOperations elasticsearchOperations;
                Neo4jClient neo4jClient;
                Neo4jTemplate neo4jTemplate;
                CassandraOperations cassandraOperations;
                ReactiveCassandraOperations reactiveCassandraOperations;
                ReactiveMongoTemplate reactiveMongoTemplate;
                DynamoDBMapper dynamoDbMapper;
                DynamoDbTemplate dynamoDbTemplate;
              }
            "#,
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();
        let stores = map
            .surfaces
            .iter()
            .filter(|surface| {
                surface.kind == AttackSurfaceKind::DbQueryBoundary
                    && surface
                        .metadata
                        .pointer("/detector")
                        .and_then(Value::as_str)
                        == Some("jvm.db-query")
            })
            .collect::<Vec<_>>();

        assert_eq!(stores.len(), 14, "{:#?}", map.surfaces);
        assert!(stores
            .iter()
            .all(|surface| surface.framework.as_deref() == Some("Spring")));
        assert!(stores
            .iter()
            .all(|surface| surface.boundary.as_deref() == Some("data_store")));
    }

    #[test]
    fn attack_surface_detects_jvm_sql_mapper_and_dsl_stores() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/SqlDslStores.java"),
            r#"
              import org.springframework.stereotype.Repository;
              @Repository
              interface InvoiceMapper {
                @Select("select * from invoice")
                Invoice find(String id);
              }
              interface InvoiceRepository extends QuerydslPredicateExecutor<Invoice> {}
              class SqlDslStores {
                DSLContext dslContext;
                SqlSession sqlSession;
                Jdbi jdbi;
                MyBatis mapper;
                void query() {
                  dslContext.selectFrom(INVOICE).fetch();
                  sqlSession.selectList("Invoice.find");
                  jdbi.withHandle(handle -> handle.createQuery(sql).mapTo(Invoice.class).list());
                }
              }
            "#,
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();
        let stores = map
            .surfaces
            .iter()
            .filter(|surface| {
                surface.kind == AttackSurfaceKind::DbQueryBoundary
                    && surface
                        .metadata
                        .pointer("/detector")
                        .and_then(Value::as_str)
                        == Some("jvm.db-query")
            })
            .collect::<Vec<_>>();

        assert_eq!(stores.len(), 8, "{:#?}", map.surfaces);
        assert!(stores
            .iter()
            .all(|surface| surface.framework.as_deref() == Some("Spring")));
        assert!(stores
            .iter()
            .all(|surface| surface.boundary.as_deref() == Some("data_store")));
    }

    #[test]
    fn attack_surface_detects_jvm_cache_frameworks_as_data_stores() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(
            temp.path().join("build.gradle"),
            "plugins { id 'java' }\ndependencies { implementation 'org.springframework.boot:spring-boot-starter-cache' }\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("src/main/java/app/CacheStores.java"),
            r#"
              import org.springframework.cache.annotation.Cacheable;
              import org.springframework.cache.annotation.EnableCaching;
              @EnableCaching
              class CacheStores {
                @Cacheable("tenantProfiles")
                Profile cachedProfile(String tenantId) {}
                @CachePut("tenantProfiles")
                Profile updateProfile(Profile profile) {}
                @CacheEvict("tenantProfiles")
                void evictProfile(String tenantId) {}
                RedisTemplate<String, Profile> redisTemplate;
                ReactiveRedisTemplate<String, Profile> reactiveRedisTemplate;
                StringRedisTemplate stringRedisTemplate;
                CacheManager cacheManager;
                HazelcastInstance hazelcastInstance;
                void caffeine() { Caffeine.newBuilder().maximumSize(1000); }
                void ehcache(Ehcache tenantCache) {}
              }
            "#,
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();
        let stores = map
            .surfaces
            .iter()
            .filter(|surface| {
                surface.kind == AttackSurfaceKind::DbQueryBoundary
                    && surface
                        .metadata
                        .pointer("/detector")
                        .and_then(Value::as_str)
                        == Some("jvm.cache-store")
            })
            .collect::<Vec<_>>();

        assert_eq!(stores.len(), 11, "{:#?}", map.surfaces);
        assert!(stores
            .iter()
            .all(|surface| surface.framework.as_deref() == Some("Spring")));
        assert!(stores
            .iter()
            .all(|surface| surface.boundary.as_deref() == Some("data_store")));
    }

    #[test]
    fn attack_surface_detects_jvm_distributed_cache_clients_as_data_stores() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(
            temp.path().join("build.gradle"),
            "plugins { id 'java' }\ndependencies { implementation 'org.springframework.boot:spring-boot-starter-cache' }\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("src/main/java/app/DistributedCaches.java"),
            r#"
              import org.springframework.stereotype.Service;
              @Service
              class DistributedCaches {
                IgniteCache<String, Profile> igniteCache;
                IgniteClient igniteClient;
                RemoteCacheManager remoteCacheManager;
                org.infinispan.Cache<String, Profile> infinispanCache;
                MemcachedClient memcachedClient;
                Cache2kBuilder.of(String.class, Profile.class).build();
                CacheBuilder.newBuilder().maximumSize(1000).build();
              }
            "#,
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();
        let stores = map
            .surfaces
            .iter()
            .filter(|surface| {
                surface.kind == AttackSurfaceKind::DbQueryBoundary
                    && surface
                        .metadata
                        .pointer("/detector")
                        .and_then(Value::as_str)
                        == Some("jvm.cache-store")
            })
            .collect::<Vec<_>>();

        assert_eq!(stores.len(), 7, "{:#?}", map.surfaces);
        assert!(stores
            .iter()
            .all(|surface| surface.framework.as_deref() == Some("Spring")));
        assert!(stores
            .iter()
            .all(|surface| surface.boundary.as_deref() == Some("data_store")));
    }

    #[test]
    fn attack_surface_detects_jvm_rpc_frameworks_as_rpc_handlers() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/RealtimeApis.java"),
            r#"
              import org.springframework.graphql.data.method.annotation.QueryMapping;
              class GraphQlApi {
                @QueryMapping
                Account account() {}
                @MutationMapping
                Account updateAccount() {}
                @SubscriptionMapping
                Publisher<Account> accountEvents() {}
                @SchemaMapping(typeName = "Account")
                Team team(Account account) {}
              }
              class MessagingApi implements WebSocketConfigurer {
                @MessageMapping("/billing")
                @SendTo("/topic/billing")
                BillingEvent billing(BillingCommand command) {}
                void register(StompEndpointRegistry registry) {}
                void configure(WebSocketHandlerRegistry registry) {}
                void publish(SimpMessagingTemplate template) {}
                void rsocket(RSocketMessageHandler handler) {}
              }
              @GrpcService
              class BillingGrpc extends BillingGrpc.BillingImplBase {
                ServerServiceDefinition bindService() { return super.bindService(); }
                void intercept() { ServerInterceptors.intercept(service, interceptor); }
              }
            "#,
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();
        let rpc_handlers = map
            .surfaces
            .iter()
            .filter(|surface| {
                surface.kind == AttackSurfaceKind::RpcHandler
                    && surface
                        .metadata
                        .pointer("/detector")
                        .and_then(Value::as_str)
                        == Some("jvm.rpc-handler")
            })
            .collect::<Vec<_>>();

        assert_eq!(rpc_handlers.len(), 12, "{:#?}", map.surfaces);
        assert!(rpc_handlers
            .iter()
            .all(|surface| surface.language == "Java"));
        assert!(rpc_handlers
            .iter()
            .all(|surface| surface.boundary.as_deref() == Some("rpc_handler")));
    }

    #[test]
    fn attack_surface_detects_jvm_plain_grpc_servers_as_rpc_handlers() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/PlainGrpcServer.java"),
            r#"
              class PlainGrpcServer {
                BindableService billingService;
                ServerServiceDefinition serviceDefinition;
                void start() {
                  ServerBuilder.forPort(8443);
                  NettyServerBuilder.forPort(9443);
                  grpc.server.Server server;
                }
              }
            "#,
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();
        let rpc_handlers = map
            .surfaces
            .iter()
            .filter(|surface| {
                surface.kind == AttackSurfaceKind::RpcHandler
                    && surface
                        .metadata
                        .pointer("/detector")
                        .and_then(Value::as_str)
                        == Some("jvm.rpc-handler")
            })
            .collect::<Vec<_>>();

        assert_eq!(rpc_handlers.len(), 5, "{:#?}", map.surfaces);
        assert!(rpc_handlers
            .iter()
            .all(|surface| surface.language == "Java"));
        assert!(rpc_handlers
            .iter()
            .all(|surface| surface.boundary.as_deref() == Some("rpc_handler")));
    }

    #[test]
    fn attack_surface_detects_jvm_rsocket_and_stomp_broker_rpc_handlers() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/RSocketBroker.java"),
            r#"
              import org.springframework.messaging.simp.config.MessageBrokerRegistry;
              import org.springframework.web.socket.config.annotation.EnableWebSocketMessageBroker;
              @EnableWebSocketMessageBroker
              class BrokerConfig extends AbstractWebSocketMessageBrokerConfigurer {
                void configureMessageBroker(MessageBrokerRegistry registry) {}
                void registerStompEndpoints(StompEndpointRegistry registry) {}
              }
              interface AccountRSocket {
                @RSocketExchange("accounts.find")
                Account find(AccountRequest request);
                @ConnectMapping("accounts.connect")
                void connect(AccountSession session) {}
              }
              class RSocketClients {
                RSocketRequester requester;
                RSocketServiceProxyFactory proxyFactory;
              }
            "#,
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();
        let rpc_handlers = map
            .surfaces
            .iter()
            .filter(|surface| {
                surface.kind == AttackSurfaceKind::RpcHandler
                    && surface
                        .metadata
                        .pointer("/detector")
                        .and_then(Value::as_str)
                        == Some("jvm.rpc-handler")
            })
            .collect::<Vec<_>>();

        assert_eq!(rpc_handlers.len(), 8, "{:#?}", map.surfaces);
        assert!(rpc_handlers
            .iter()
            .all(|surface| surface.language == "Java"));
        assert!(rpc_handlers
            .iter()
            .all(|surface| surface.boundary.as_deref() == Some("rpc_handler")));
    }

    #[test]
    fn attack_surface_detects_jvm_service_rpc_framework_handlers() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path()
                .join("src/main/java/app/ServiceRpcHandlers.java"),
            r#"
              import org.apache.dubbo.config.annotation.DubboService;
              @DubboService
              class BillingDubboService {}
              class ServiceRpcHandlers {
                TProcessor processor;
                TServer server;
                TServlet servlet;
                void thrift() { new TThreadPoolServer(args).serve(); }
                void avro() { AvroIPC.startServer(protocol, responder); }
                void dubbo() { registry.add("dubbo.protocol.name", "dubbo"); }
              }
            "#,
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();
        let rpc_handlers = map
            .surfaces
            .iter()
            .filter(|surface| {
                surface.kind == AttackSurfaceKind::RpcHandler
                    && surface
                        .metadata
                        .pointer("/detector")
                        .and_then(Value::as_str)
                        == Some("jvm.rpc-handler")
            })
            .collect::<Vec<_>>();

        assert_eq!(rpc_handlers.len(), 6, "{:#?}", map.surfaces);
        assert!(rpc_handlers
            .iter()
            .all(|surface| surface.language == "Java"));
        assert!(rpc_handlers
            .iter()
            .all(|surface| surface.boundary.as_deref() == Some("rpc_handler")));
    }

    #[test]
    fn attack_surface_detects_jvm_streaming_response_handlers_as_rpc_handlers() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path()
                .join("src/main/java/app/StreamingController.java"),
            r#"
              import org.springframework.web.bind.annotation.GetMapping;
              class StreamingController {
                @GetMapping("/events/sse")
                SseEmitter sse() { return emitter; }
                @GetMapping("/events/server")
                Flux<ServerSentEvent<AccountEvent>> serverEvents() { return events; }
                @GetMapping("/events/body")
                StreamingResponseBody body() { return output -> {}; }
                @GetMapping("/events/emitter")
                ResponseBodyEmitter emitter() { return emitter; }
              }
            "#,
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();
        let rpc_handlers = map
            .surfaces
            .iter()
            .filter(|surface| {
                surface.kind == AttackSurfaceKind::RpcHandler
                    && surface
                        .metadata
                        .pointer("/detector")
                        .and_then(Value::as_str)
                        == Some("jvm.rpc-handler")
            })
            .collect::<Vec<_>>();

        assert_eq!(rpc_handlers.len(), 4, "{:#?}", map.surfaces);
        assert!(rpc_handlers
            .iter()
            .all(|surface| surface.framework.as_deref() == Some("Spring")));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/events/sse")
        }));
    }

    #[test]
    fn attack_surface_preserves_aspnet_core_routes() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("Controllers")).unwrap();
        fs::write(
            temp.path().join("Program.cs"),
            "using Microsoft.AspNetCore.Builder;\nvar builder = WebApplication.CreateBuilder(args);\nvar app = builder.Build();\napp.MapPost(\"/imports/file\", (IFormFile file) => Results.Ok(file.FileName)).RequireAuthorization();\napp.MapHead(\"/health\", () => Results.Ok());\napp.MapHealthChecks(\"/health/live\");\napp.MapOpenApi();\napp.MapOpenApi(\"/internal/openapi/{documentName}.json\");\napp.MapSwagger();\napp.UseSwagger(\"docs/{documentName}/swagger.json\");\napp.MapGraphQL();\napp.UseGraphQL(\"/query\");\napp.MapOptions(\"/saml/callback\", () => Results.Ok());\napp.MapFallback(\"/{*path:nonfile}\", () => Results.Ok());\napp.MapFallbackToFile(\"index.html\");\napp.MapFallbackToPage(\"/_Host\");\napp.MapMethods(\"/imports/batch\", new[] { \"POST\" }, () => Results.Ok());\napp.MapMethods(\"/imports/constants\", new[] { HttpMethods.Put, HttpMethods.Patch }, () => Results.Ok());\napp.MapMethods(\"/imports/tunnel\", new[] { \"TRACE\", HttpMethods.Connect }, () => Results.Ok());\napp.MapHub<AdminHub>(\"/hubs/admin\");\napp.MapBlazorHub();\napp.MapBlazorHub(\"/live/blazor\");\napp.MapRazorPages();\napp.MapGrpcService<GreeterService>();\napp.MapControllerRoute(name: \"default\", pattern: \"mvc/{controller}/{action}\");\napp.MapAreaControllerRoute(name: \"admin-area\", areaName: \"Admin\", pattern: \"admin/{controller}/{action}\");\napp.MapDefaultControllerRoute();\napp.MapGroup(\"/api/direct\").MapPost(\"invite\", () => Results.Ok());\napp.MapGroup(\"/api/direct\").MapMethods(\"audit\", new[] { \"POST\", \"DELETE\" }, () => Results.Ok());\napp.MapGroup(\"/api/chained\").MapGroup(\"admin\").MapGet(\"settings\", () => Results.Ok());\nvar assigned = app.MapGroup(\"/api/assigned\").MapGroup(\"admin\");\nassigned.MapGet(\"settings\", () => Results.Ok());\nvar assignedMethods = app.MapGroup(\"/api/assigned-methods\").MapGroup(\"admin\");\nassignedMethods.MapMethods(\"audit\", new[] { \"POST\", \"DELETE\" }, () => Results.Ok());\nvar assignedConstants = app.MapGroup(\"/api/assigned-constants\").MapGroup(\"admin\");\nassignedConstants.MapMethods(\"flags\", new[] { HttpMethods.Put, HttpMethods.Patch }, () => Results.Ok());\nvar assignedTunnel = app.MapGroup(\"/api/assigned-tunnel\").MapGroup(\"admin\");\nassignedTunnel.MapMethods(\"proxy\", new[] { \"TRACE\", HttpMethods.Connect }, () => Results.Ok());\nvar admin = app.MapGroup(\"/api/admin\");\nadmin.MapPost(\"bulk-invite\", () => Results.Ok()).RequireAuthorization();\nadmin.MapHead(\"group-status\", () => Results.Ok());\nadmin.MapOptions(\"preflight\", () => Results.Ok());\nadmin.MapPut(\"roles/{id}\", () => Results.Ok());\nadmin.MapPatch(\"profile/{id}\", () => Results.Ok());\nadmin.MapDelete(\"sessions/{id}\", () => Results.Ok());\nvar nested = admin.MapGroup(\"nested\");\nnested.MapGet(\"settings\", () => Results.Ok());\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("Controllers/AdminController.cs"),
            "using Microsoft.AspNetCore.Mvc;\n[Route(\"api/admin\")]\nclass AdminController {\n[Authorize]\n[HttpPost(\"invite\")]\npublic IActionResult Invite() => Ok(Request.Headers[\"X-Team\"]);\n[Route(\"export\")]\n[HttpPost]\npublic IActionResult Export() => Ok();\n[HttpHead(\"status\")]\npublic IActionResult Status() => Ok();\n[HttpOptions]\npublic IActionResult Options() => Ok();\n[HttpGet]\npublic IActionResult Index() => Ok();\n}\n",
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();

        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/imports/file")
                && surface.method.as_deref() == Some("POST")
                && surface.framework.as_deref() == Some("ASP.NET Core")
                && surface.language == "C#"
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/health")
                && surface.method.as_deref() == Some("HEAD")
                && surface.framework.as_deref() == Some("ASP.NET Core")
                && surface.language == "C#"
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/health/live")
                && surface.method.as_deref() == Some("GET")
                && surface.framework.as_deref() == Some("ASP.NET Core")
                && surface.language == "C#"
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/openapi/{documentName}.json")
                && surface.method.as_deref() == Some("GET")
                && surface.framework.as_deref() == Some("ASP.NET Core")
                && surface.language == "C#"
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/internal/openapi/{documentName}.json")
                && surface.method.as_deref() == Some("GET")
                && surface.framework.as_deref() == Some("ASP.NET Core")
                && surface.language == "C#"
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/swagger/{documentName}/swagger.json")
                && surface.method.as_deref() == Some("GET")
                && surface.framework.as_deref() == Some("ASP.NET Core")
                && surface.language == "C#"
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/docs/{documentName}/swagger.json")
                && surface.method.as_deref() == Some("GET")
                && surface.framework.as_deref() == Some("ASP.NET Core")
                && surface.language == "C#"
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::RpcHandler
                && surface.route.as_deref() == Some("/graphql")
                && surface.method.as_deref() == Some("ANY")
                && surface.framework.as_deref() == Some("ASP.NET Core")
                && surface.boundary.as_deref() == Some("remote_rpc")
                && surface
                    .metadata
                    .pointer("/detector")
                    .and_then(Value::as_str)
                    == Some("dotnet.graphql")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::RpcHandler
                && surface.route.as_deref() == Some("/query")
                && surface.method.as_deref() == Some("ANY")
                && surface.framework.as_deref() == Some("ASP.NET Core")
                && surface.boundary.as_deref() == Some("remote_rpc")
                && surface
                    .metadata
                    .pointer("/detector")
                    .and_then(Value::as_str)
                    == Some("dotnet.graphql")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/saml/callback")
                && surface.method.as_deref() == Some("OPTIONS")
                && surface.framework.as_deref() == Some("ASP.NET Core")
                && surface.language == "C#"
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/{*path:nonfile}")
                && surface.method.as_deref() == Some("ANY")
                && surface.framework.as_deref() == Some("ASP.NET Core")
                && surface.language == "C#"
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("*")
                && surface.method.as_deref() == Some("ANY")
                && surface.framework.as_deref() == Some("ASP.NET Core")
                && surface.language == "C#"
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/imports/batch")
                && surface.method.as_deref() == Some("POST")
                && surface.framework.as_deref() == Some("ASP.NET Core")
                && surface.language == "C#"
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::RpcHandler
                && surface.route.as_deref() == Some("/hubs/admin")
                && surface.method.as_deref() == Some("ANY")
                && surface.framework.as_deref() == Some("ASP.NET Core")
                && surface.boundary.as_deref() == Some("remote_rpc")
                && surface
                    .metadata
                    .pointer("/detector")
                    .and_then(Value::as_str)
                    == Some("dotnet.signalr-hub")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::RpcHandler
                && surface.route.as_deref() == Some("/_blazor")
                && surface.method.as_deref() == Some("ANY")
                && surface.framework.as_deref() == Some("ASP.NET Core")
                && surface.boundary.as_deref() == Some("remote_rpc")
                && surface
                    .metadata
                    .pointer("/detector")
                    .and_then(Value::as_str)
                    == Some("dotnet.blazor-hub")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::RpcHandler
                && surface.route.as_deref() == Some("/live/blazor")
                && surface.method.as_deref() == Some("ANY")
                && surface.framework.as_deref() == Some("ASP.NET Core")
                && surface.boundary.as_deref() == Some("remote_rpc")
                && surface
                    .metadata
                    .pointer("/detector")
                    .and_then(Value::as_str)
                    == Some("dotnet.blazor-hub")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/{page}")
                && surface.method.as_deref() == Some("ANY")
                && surface.framework.as_deref() == Some("ASP.NET Core")
                && surface.language == "C#"
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::RpcHandler
                && surface.method.as_deref() == Some("ANY")
                && surface.framework.as_deref() == Some("ASP.NET Core")
                && surface.boundary.as_deref() == Some("rpc_handler")
                && surface
                    .metadata
                    .pointer("/detector")
                    .and_then(Value::as_str)
                    == Some("dotnet.grpc-service")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/mvc/{controller}/{action}")
                && surface.method.as_deref() == Some("ANY")
                && surface.framework.as_deref() == Some("ASP.NET Core")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/admin/{controller}/{action}")
                && surface.method.as_deref() == Some("ANY")
                && surface.framework.as_deref() == Some("ASP.NET Core")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/{controller=Home}/{action=Index}/{id?}")
                && surface.method.as_deref() == Some("ANY")
                && surface.framework.as_deref() == Some("ASP.NET Core")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/api/direct/invite")
                && surface.method.as_deref() == Some("POST")
                && surface.framework.as_deref() == Some("ASP.NET Core")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/imports/constants")
                && surface.method.as_deref() == Some("PUT")
                && surface.framework.as_deref() == Some("ASP.NET Core")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/imports/constants")
                && surface.method.as_deref() == Some("PATCH")
                && surface.framework.as_deref() == Some("ASP.NET Core")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/imports/tunnel")
                && surface.method.as_deref() == Some("TRACE")
                && surface.framework.as_deref() == Some("ASP.NET Core")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/imports/tunnel")
                && surface.method.as_deref() == Some("CONNECT")
                && surface.framework.as_deref() == Some("ASP.NET Core")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/api/direct/audit")
                && surface.method.as_deref() == Some("POST")
                && surface.framework.as_deref() == Some("ASP.NET Core")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/api/direct/audit")
                && surface.method.as_deref() == Some("DELETE")
                && surface.framework.as_deref() == Some("ASP.NET Core")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/api/chained/admin/settings")
                && surface.method.as_deref() == Some("GET")
                && surface.framework.as_deref() == Some("ASP.NET Core")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/api/assigned/admin/settings")
                && surface.method.as_deref() == Some("GET")
                && surface.framework.as_deref() == Some("ASP.NET Core")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/api/assigned-methods/admin/audit")
                && surface.method.as_deref() == Some("POST")
                && surface.framework.as_deref() == Some("ASP.NET Core")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/api/assigned-methods/admin/audit")
                && surface.method.as_deref() == Some("DELETE")
                && surface.framework.as_deref() == Some("ASP.NET Core")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/api/assigned-constants/admin/flags")
                && surface.method.as_deref() == Some("PUT")
                && surface.framework.as_deref() == Some("ASP.NET Core")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/api/assigned-constants/admin/flags")
                && surface.method.as_deref() == Some("PATCH")
                && surface.framework.as_deref() == Some("ASP.NET Core")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/api/assigned-tunnel/admin/proxy")
                && surface.method.as_deref() == Some("TRACE")
                && surface.framework.as_deref() == Some("ASP.NET Core")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/api/assigned-tunnel/admin/proxy")
                && surface.method.as_deref() == Some("CONNECT")
                && surface.framework.as_deref() == Some("ASP.NET Core")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/api/admin/bulk-invite")
                && surface.method.as_deref() == Some("POST")
                && surface.framework.as_deref() == Some("ASP.NET Core")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/api/admin/group-status")
                && surface.method.as_deref() == Some("HEAD")
                && surface.framework.as_deref() == Some("ASP.NET Core")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/api/admin/preflight")
                && surface.method.as_deref() == Some("OPTIONS")
                && surface.framework.as_deref() == Some("ASP.NET Core")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/api/admin/roles/{id}")
                && surface.method.as_deref() == Some("PUT")
                && surface.framework.as_deref() == Some("ASP.NET Core")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/api/admin/profile/{id}")
                && surface.method.as_deref() == Some("PATCH")
                && surface.framework.as_deref() == Some("ASP.NET Core")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/api/admin/sessions/{id}")
                && surface.method.as_deref() == Some("DELETE")
                && surface.framework.as_deref() == Some("ASP.NET Core")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/api/admin/nested/settings")
                && surface.method.as_deref() == Some("GET")
                && surface.framework.as_deref() == Some("ASP.NET Core")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/api/admin/invite")
                && surface.method.as_deref() == Some("POST")
                && surface.framework.as_deref() == Some("ASP.NET Core")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/api/admin/export")
                && surface.method.as_deref() == Some("POST")
                && surface.framework.as_deref() == Some("ASP.NET Core")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/api/admin/status")
                && surface.method.as_deref() == Some("HEAD")
                && surface.framework.as_deref() == Some("ASP.NET Core")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/api/admin")
                && surface.method.as_deref() == Some("OPTIONS")
                && surface.framework.as_deref() == Some("ASP.NET Core")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/api/admin")
                && surface.method.as_deref() == Some("GET")
                && surface.framework.as_deref() == Some("ASP.NET Core")
        }));
        assert_detector(&map, "dotnet.auth-guard");
        assert_detector(&map, "dotnet.file-upload");
        assert_detector(&map, "dotnet.request-trust");
    }

    #[test]
    fn attack_surface_detects_aspnet_identity_api_routes() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Web.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk.Web\"></Project>\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("Program.cs"),
            "var app = WebApplication.CreateBuilder(args).Build();\nvar account = app.MapGroup(\"/account\");\naccount.MapIdentityApi<AppUser>();\nvar nestedAccount = app.MapGroup(\"/api\").MapGroup(\"account\");\nnestedAccount.MapIdentityApi<AppUser>();\napp.MapGroup(\"/chained-account\").MapIdentityApi<AppUser>();\napp.MapGroup(\"/chained\").MapGroup(\"account\").MapIdentityApi<AppUser>();\napp.MapIdentityApi<AppUser>();\n",
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();

        assert!(map.surfaces.iter().any(|surface| {
            surface.route.as_deref() == Some("/account")
                && surface.method.as_deref() == Some("ANY")
                && surface.framework.as_deref() == Some("ASP.NET Core")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.route.as_deref() == Some("/api/account")
                && surface.method.as_deref() == Some("ANY")
                && surface.framework.as_deref() == Some("ASP.NET Core")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.route.as_deref() == Some("/chained-account")
                && surface.method.as_deref() == Some("ANY")
                && surface.framework.as_deref() == Some("ASP.NET Core")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.route.as_deref() == Some("/chained/account")
                && surface.method.as_deref() == Some("ANY")
                && surface.framework.as_deref() == Some("ASP.NET Core")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.route.as_deref() == Some("/identity")
                && surface.method.as_deref() == Some("ANY")
                && surface.framework.as_deref() == Some("ASP.NET Core")
        }));
    }

    #[test]
    fn attack_surface_detects_aspnet_metrics_routes() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Web.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk.Web\"></Project>\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("Program.cs"),
            "var app = WebApplication.CreateBuilder(args).Build();\napp.MapMetrics();\napp.MapPrometheusScrapingEndpoint(\"/internal/metrics\");\nvar observability = app.MapGroup(\"/ops\");\nobservability.MapMetrics();\nobservability.MapPrometheusScrapingEndpoint(\"prometheus\");\napp.MapGroup(\"/chained-ops\").MapMetrics();\napp.MapGroup(\"/chained-prom\").MapPrometheusScrapingEndpoint();\napp.MapGroup(\"/chained-prom\").MapPrometheusScrapingEndpoint(\"custom-prometheus\");\napp.MapGroup(\"/internal\").MapGroup(\"ops\").MapMetrics();\nvar assignedOps = app.MapGroup(\"/assigned\").MapGroup(\"ops\");\nassignedOps.MapMetrics();\n",
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();

        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/metrics")
                && surface.method.as_deref() == Some("GET")
                && surface.framework.as_deref() == Some("ASP.NET Core")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/internal/metrics")
                && surface.method.as_deref() == Some("GET")
                && surface.framework.as_deref() == Some("ASP.NET Core")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/ops/metrics")
                && surface.method.as_deref() == Some("GET")
                && surface.framework.as_deref() == Some("ASP.NET Core")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/ops/prometheus")
                && surface.method.as_deref() == Some("GET")
                && surface.framework.as_deref() == Some("ASP.NET Core")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/chained-ops/metrics")
                && surface.method.as_deref() == Some("GET")
                && surface.framework.as_deref() == Some("ASP.NET Core")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/chained-prom/metrics")
                && surface.method.as_deref() == Some("GET")
                && surface.framework.as_deref() == Some("ASP.NET Core")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/chained-prom/custom-prometheus")
                && surface.method.as_deref() == Some("GET")
                && surface.framework.as_deref() == Some("ASP.NET Core")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/internal/ops/metrics")
                && surface.method.as_deref() == Some("GET")
                && surface.framework.as_deref() == Some("ASP.NET Core")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/assigned/ops/metrics")
                && surface.method.as_deref() == Some("GET")
                && surface.framework.as_deref() == Some("ASP.NET Core")
        }));
    }

    #[test]
    fn attack_surface_detects_aspnet_static_asset_routes() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Web.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk.Web\"></Project>\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("Program.cs"),
            "var app = WebApplication.CreateBuilder(args).Build();\napp.MapStaticAssets();\napp.MapStaticAssets(\"/assets/{**path}\");\nvar publicAssets = app.MapGroup(\"/public\");\npublicAssets.MapStaticAssets();\npublicAssets.MapStaticAssets(\"files/{**path}\");\napp.MapGroup(\"/chained-public\").MapStaticAssets();\napp.MapGroup(\"/chained-public\").MapStaticAssets(\"assets/{**path}\");\napp.MapGroup(\"/internal\").MapGroup(\"public\").MapStaticAssets();\nvar assignedPublic = app.MapGroup(\"/assigned\").MapGroup(\"public\");\nassignedPublic.MapStaticAssets();\n",
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();

        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/{staticAsset}")
                && surface.method.as_deref() == Some("GET")
                && surface.framework.as_deref() == Some("ASP.NET Core")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/assets/{**path}")
                && surface.method.as_deref() == Some("GET")
                && surface.framework.as_deref() == Some("ASP.NET Core")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/public/{staticAsset}")
                && surface.method.as_deref() == Some("GET")
                && surface.framework.as_deref() == Some("ASP.NET Core")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/chained-public/{staticAsset}")
                && surface.method.as_deref() == Some("GET")
                && surface.framework.as_deref() == Some("ASP.NET Core")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/chained-public/assets/{**path}")
                && surface.method.as_deref() == Some("GET")
                && surface.framework.as_deref() == Some("ASP.NET Core")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/internal/public/{staticAsset}")
                && surface.method.as_deref() == Some("GET")
                && surface.framework.as_deref() == Some("ASP.NET Core")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/assigned/public/{staticAsset}")
                && surface.method.as_deref() == Some("GET")
                && surface.framework.as_deref() == Some("ASP.NET Core")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/public/files/{**path}")
                && surface.method.as_deref() == Some("GET")
                && surface.framework.as_deref() == Some("ASP.NET Core")
        }));
    }

    #[test]
    fn attack_surface_detects_aspnet_reverse_proxy_routes() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Web.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk.Web\"></Project>\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("Program.cs"),
            "var app = WebApplication.CreateBuilder(args).Build();\napp.MapReverseProxy();\napp.MapReverseProxy(\"/proxy/{**catchAll}\");\nvar gateway = app.MapGroup(\"/gateway\");\ngateway.MapReverseProxy();\ngateway.MapReverseProxy(\"proxy/{**catchAll}\");\n",
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();

        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/{**proxy}")
                && surface.method.as_deref() == Some("ANY")
                && surface.framework.as_deref() == Some("ASP.NET Core")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/proxy/{**catchAll}")
                && surface.method.as_deref() == Some("ANY")
                && surface.framework.as_deref() == Some("ASP.NET Core")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/gateway/{**proxy}")
                && surface.method.as_deref() == Some("ANY")
                && surface.framework.as_deref() == Some("ASP.NET Core")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/gateway/proxy/{**catchAll}")
                && surface.method.as_deref() == Some("ANY")
                && surface.framework.as_deref() == Some("ASP.NET Core")
        }));
    }

    #[test]
    fn attack_surface_detects_aspnet_forwarder_routes() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Web.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk.Web\"></Project>\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("Program.cs"),
            "var app = WebApplication.CreateBuilder(args).Build();\napp.MapForwarder(\"/proxy/{**catchAll}\", \"https://backend.internal\");\nvar gateway = app.MapGroup(\"/gateway\");\ngateway.MapForwarder(\"proxy/{**catchAll}\", \"https://backend.internal\");\n",
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();

        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/proxy/{**catchAll}")
                && surface.method.as_deref() == Some("ANY")
                && surface.framework.as_deref() == Some("ASP.NET Core")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/gateway/proxy/{**catchAll}")
                && surface.method.as_deref() == Some("ANY")
                && surface.framework.as_deref() == Some("ASP.NET Core")
        }));
    }

    #[test]
    fn attack_surface_detects_aspnet_fallback_controller_routes() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Web.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk.Web\"></Project>\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("Program.cs"),
            "var app = WebApplication.CreateBuilder(args).Build();\napp.MapFallbackToController(\"Index\", \"Home\");\napp.MapFallbackToController(\"proxy/{**path}\", \"Proxy\", \"Gateway\");\napp.MapFallbackToAreaController(\"{*path:nonfile}\", \"Index\", \"Spa\", \"Public\");\nvar gateway = app.MapGroup(\"/gateway\");\ngateway.MapFallbackToController(\"proxy/{**path}\", \"Proxy\", \"Gateway\");\ngateway.MapFallbackToAreaController(\"spa/{*path:nonfile}\", \"Index\", \"Spa\", \"Public\");\n",
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();

        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("*")
                && surface.method.as_deref() == Some("ANY")
                && surface.framework.as_deref() == Some("ASP.NET Core")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/proxy/{**path}")
                && surface.method.as_deref() == Some("ANY")
                && surface.framework.as_deref() == Some("ASP.NET Core")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/{*path:nonfile}")
                && surface.method.as_deref() == Some("ANY")
                && surface.framework.as_deref() == Some("ASP.NET Core")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/gateway/proxy/{**path}")
                && surface.method.as_deref() == Some("ANY")
                && surface.framework.as_deref() == Some("ASP.NET Core")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/gateway/spa/{*path:nonfile}")
                && surface.method.as_deref() == Some("ANY")
                && surface.framework.as_deref() == Some("ASP.NET Core")
        }));
    }

    #[test]
    fn attack_surface_detects_aspnet_razor_components_routes() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Web.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk.Web\"></Project>\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("Program.cs"),
            "var app = WebApplication.CreateBuilder(args).Build();\napp.MapRazorComponents<App>();\napp.MapRazorComponents<App>(\"/ui/{**page}\");\nvar tenantUi = app.MapGroup(\"/tenant\");\ntenantUi.MapRazorComponents<App>();\ntenantUi.MapRazorComponents<App>(\"ui/{**page}\");\n",
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();

        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/{component}")
                && surface.method.as_deref() == Some("ANY")
                && surface.framework.as_deref() == Some("ASP.NET Core")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/ui/{**page}")
                && surface.method.as_deref() == Some("ANY")
                && surface.framework.as_deref() == Some("ASP.NET Core")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/tenant/{component}")
                && surface.method.as_deref() == Some("ANY")
                && surface.framework.as_deref() == Some("ASP.NET Core")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/tenant/ui/{**page}")
                && surface.method.as_deref() == Some("ANY")
                && surface.framework.as_deref() == Some("ASP.NET Core")
        }));
    }

    #[test]
    fn attack_surface_detects_aspnet_page_route_conventions() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Web.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk.Web\"></Project>\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("Program.cs"),
            "var app = WebApplication.CreateBuilder(args).Build();\napp.MapPageRoute(\"/Help\", \"help/{id?}\");\napp.MapAreaPageRoute(\"Admin\", \"/Audit\", \"admin/audit/{**path}\");\nvar docs = app.MapGroup(\"/docs\");\ndocs.MapPageRoute(\"/Guide\", \"guide/{id?}\");\ndocs.MapAreaPageRoute(\"Admin\", \"/Audit\", \"admin/audit/{**path}\");\n",
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();

        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/help/{id?}")
                && surface.method.as_deref() == Some("ANY")
                && surface.framework.as_deref() == Some("ASP.NET Core")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/admin/audit/{**path}")
                && surface.method.as_deref() == Some("ANY")
                && surface.framework.as_deref() == Some("ASP.NET Core")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/docs/guide/{id?}")
                && surface.method.as_deref() == Some("ANY")
                && surface.framework.as_deref() == Some("ASP.NET Core")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/docs/admin/audit/{**path}")
                && surface.method.as_deref() == Some("ANY")
                && surface.framework.as_deref() == Some("ASP.NET Core")
        }));
    }

    #[test]
    fn attack_surface_detects_aspnet_dynamic_routes() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Web.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk.Web\"></Project>\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("Program.cs"),
            "var app = WebApplication.CreateBuilder(args).Build();\napp.MapDynamicControllerRoute<SlugTransformer>(\"{**slug}\");\napp.MapDynamicPageRoute<PageTransformer>(\"cms/{**path}\");\nvar dynamic = app.MapGroup(\"/dynamic\");\ndynamic.MapDynamicControllerRoute<SlugTransformer>(\"{**slug}\");\ndynamic.MapDynamicPageRoute<PageTransformer>(\"cms/{**path}\");\n",
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();

        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/{**slug}")
                && surface.method.as_deref() == Some("ANY")
                && surface.framework.as_deref() == Some("ASP.NET Core")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/cms/{**path}")
                && surface.method.as_deref() == Some("ANY")
                && surface.framework.as_deref() == Some("ASP.NET Core")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/dynamic/{**slug}")
                && surface.method.as_deref() == Some("ANY")
                && surface.framework.as_deref() == Some("ASP.NET Core")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/dynamic/cms/{**path}")
                && surface.method.as_deref() == Some("ANY")
                && surface.framework.as_deref() == Some("ASP.NET Core")
        }));
    }

    #[test]
    fn attack_surface_detects_aspnet_map_controllers_routes() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Web.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk.Web\"></Project>\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("Program.cs"),
            "var app = WebApplication.CreateBuilder(args).Build();\napp.MapControllers();\n",
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();

        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/{controller}/{action}")
                && surface.method.as_deref() == Some("ANY")
                && surface.framework.as_deref() == Some("ASP.NET Core")
        }));
    }

    #[test]
    fn attack_surface_detects_aspnet_chained_nested_map_methods_ignore_group_segments() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Web.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk.Web\"></Project>\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("Program.cs"),
            "var app = WebApplication.CreateBuilder(args).Build();\napp.MapGroup(\"/api\").MapGroup(\"put\").MapGroup(\"admin\").MapMethods(\"audit\", new[] { \"DELETE\" }, DeleteAudit);\napp.MapGroup(\"/api\").MapGroup(\"trace\").MapGroup(\"tunnel\").MapMethods(\"proxy\", new[] { HttpMethods.Connect }, Tunnel);\n",
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();

        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/api/put/admin/audit")
                && surface.method.as_deref() == Some("DELETE")
                && surface.framework.as_deref() == Some("ASP.NET Core")
        }));
        assert!(map.surfaces.iter().all(|surface| {
            surface.route.as_deref() != Some("/api/put/admin/audit")
                || surface.method.as_deref() != Some("PUT")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/api/trace/tunnel/proxy")
                && surface.method.as_deref() == Some("CONNECT")
                && surface.framework.as_deref() == Some("ASP.NET Core")
        }));
        assert!(map.surfaces.iter().all(|surface| {
            surface.route.as_deref() != Some("/api/trace/tunnel/proxy")
                || surface.method.as_deref() != Some("TRACE")
        }));
    }

    #[test]
    fn attack_surface_detects_aspnet_chained_grouped_routes_after_metadata() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Web.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk.Web\"></Project>\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("Program.cs"),
            "var app = WebApplication.CreateBuilder(args).Build();\napp.MapGroup(\"/api\").WithTags(\"admin\").MapGet(\"settings\", Settings);\napp.MapGroup(\"/api\").MapGroup(\"v1\").WithName(\"ignored-name\").MapPost(\"users\", Users);\n",
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();

        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/api/settings")
                && surface.method.as_deref() == Some("GET")
                && surface.framework.as_deref() == Some("ASP.NET Core")
        }));
        assert!(map.surfaces.iter().all(|surface| {
            surface.route.as_deref() != Some("/api/admin")
                || surface.method.as_deref() != Some("GET")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/api/v1/users")
                && surface.method.as_deref() == Some("POST")
                && surface.framework.as_deref() == Some("ASP.NET Core")
        }));
        assert!(map.surfaces.iter().all(|surface| {
            surface.route.as_deref() != Some("/api/v1/ignored-name")
                || surface.method.as_deref() != Some("POST")
        }));
    }

    #[test]
    fn attack_surface_detects_aspnet_positional_controller_routes() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Web.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk.Web\"></Project>\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("Program.cs"),
            "var app = WebApplication.CreateBuilder(args).Build();\napp.MapControllerRoute(\"catalog\", \"catalog/{controller}/{action}\");\napp.MapAreaControllerRoute(\"admin\", \"Admin\", \"admin/{controller}/{action}\");\napp.MapGroup(\"/tenant\").MapControllerRoute(\"catalog\", \"catalog/{controller}/{action}\");\napp.MapGroup(\"/tenant\").MapAreaControllerRoute(\"admin\", \"Admin\", \"admin/{controller}/{action}\");\napp.MapGroup(\"/named\").MapControllerRoute(name: \"catalog\", pattern: \"catalog/{controller}/{action}\");\napp.MapGroup(\"/named\").MapAreaControllerRoute(name: \"admin\", pattern: \"admin/{controller}/{action}\", areaName: \"Admin\");\n",
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();

        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/catalog/{controller}/{action}")
                && surface.method.as_deref() == Some("ANY")
                && surface.framework.as_deref() == Some("ASP.NET Core")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/admin/{controller}/{action}")
                && surface.method.as_deref() == Some("ANY")
                && surface.framework.as_deref() == Some("ASP.NET Core")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/tenant/catalog/{controller}/{action}")
                && surface.method.as_deref() == Some("ANY")
                && surface.framework.as_deref() == Some("ASP.NET Core")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/tenant/admin/{controller}/{action}")
                && surface.method.as_deref() == Some("ANY")
                && surface.framework.as_deref() == Some("ASP.NET Core")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/named/catalog/{controller}/{action}")
                && surface.method.as_deref() == Some("ANY")
                && surface.framework.as_deref() == Some("ASP.NET Core")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/named/admin/{controller}/{action}")
                && surface.method.as_deref() == Some("ANY")
                && surface.framework.as_deref() == Some("ASP.NET Core")
        }));
    }

    #[test]
    fn attack_surface_detects_aspnet_accept_verbs_routes() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Web.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk.Web\"></Project>\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("AdminController.cs"),
            "using Microsoft.AspNetCore.Mvc;\n[Route(\"api\")]\nclass AdminController {\n[AcceptVerbs(\"POST\", HttpMethods.Patch, \"DELETE\", Route = \"admin/export\")]\npublic IActionResult Export() => Ok();\n}\n",
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();

        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/api/admin/export")
                && surface.method.as_deref() == Some("POST")
                && surface.framework.as_deref() == Some("ASP.NET Core")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/api/admin/export")
                && surface.method.as_deref() == Some("DELETE")
                && surface.framework.as_deref() == Some("ASP.NET Core")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/api/admin/export")
                && surface.method.as_deref() == Some("PATCH")
                && surface.framework.as_deref() == Some("ASP.NET Core")
        }));
    }

    #[test]
    fn attack_surface_ignores_aspnet_http_attribute_name_metadata() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Web.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk.Web\"></Project>\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("AdminController.cs"),
            "using Microsoft.AspNetCore.Mvc;\n[Route(\"api/admin\")]\nclass AdminController {\n[HttpGet(Name = \"GetAdmin\")]\npublic IActionResult Index() => Ok();\n[HttpPost(Template = \"reports/export\")]\npublic IActionResult Export() => Ok();\n}\n",
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();

        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/api/admin")
                && surface.method.as_deref() == Some("GET")
                && surface.framework.as_deref() == Some("ASP.NET Core")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/api/admin/reports/export")
                && surface.method.as_deref() == Some("POST")
                && surface.framework.as_deref() == Some("ASP.NET Core")
        }));
        assert!(map
            .surfaces
            .iter()
            .all(|surface| surface.route.as_deref() != Some("/api/admin/GetAdmin")));
    }

    #[test]
    fn attack_surface_ignores_aspnet_route_attribute_name_metadata() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Web.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk.Web\"></Project>\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("AdminController.cs"),
            "using Microsoft.AspNetCore.Mvc;\n[Route(Name = \"AdminRoot\")]\nclass AdminController {\n[HttpGet(\"status\")]\npublic IActionResult Status() => Ok();\n[Route(Template = \"reports/export\")]\n[HttpPost]\npublic IActionResult Export() => Ok();\n}\n",
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();

        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/status")
                && surface.method.as_deref() == Some("GET")
                && surface.framework.as_deref() == Some("ASP.NET Core")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/reports/export")
                && surface.method.as_deref() == Some("POST")
                && surface.framework.as_deref() == Some("ASP.NET Core")
        }));
        assert!(map
            .surfaces
            .iter()
            .all(|surface| surface.route.as_deref() != Some("/AdminRoot/status")));
    }

    #[test]
    fn attack_surface_normalizes_aspnet_route_tokens() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Web.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk.Web\"></Project>\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("AdminController.cs"),
            "using Microsoft.AspNetCore.Mvc;\n[Route(\"admin/[area]/[controller]\")]\nclass AdminController {\n[HttpGet(\"[action]\")]\npublic IActionResult Status() => Ok();\n}\n",
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();

        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/admin/{area}/{controller}/{action}")
                && surface.method.as_deref() == Some("GET")
                && surface.framework.as_deref() == Some("ASP.NET Core")
        }));
    }

    #[test]
    fn attack_surface_detects_aspnet_short_circuit_routes() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Web.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk.Web\"></Project>\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("Program.cs"),
            "var app = WebApplication.CreateBuilder(args).Build();\napp.MapShortCircuit(404, \"robots.txt\");\napp.MapGroup(\"/static\").MapShortCircuit(404, \"robots.txt\");\napp.MapGroup(\"/internal\").MapGroup(\"static\").MapShortCircuit(404, \"favicon.ico\");\nvar assignedStatic = app.MapGroup(\"/assigned\").MapGroup(\"static\");\nassignedStatic.MapShortCircuit(404, \"health.txt\");\n",
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();

        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/robots.txt")
                && surface.method.as_deref() == Some("ANY")
                && surface.framework.as_deref() == Some("ASP.NET Core")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/static/robots.txt")
                && surface.method.as_deref() == Some("ANY")
                && surface.framework.as_deref() == Some("ASP.NET Core")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/internal/static/favicon.ico")
                && surface.method.as_deref() == Some("ANY")
                && surface.framework.as_deref() == Some("ASP.NET Core")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/assigned/static/health.txt")
                && surface.method.as_deref() == Some("ANY")
                && surface.framework.as_deref() == Some("ASP.NET Core")
        }));
    }

    #[test]
    fn attack_surface_detects_aspnet_grouped_health_check_routes() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Web.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk.Web\"></Project>\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("Program.cs"),
            "var app = WebApplication.CreateBuilder(args).Build();\napp.MapHealthChecks(\"/health/live\");\napp.MapGroup(\"/ops\").MapHealthChecks(\"live\");\napp.MapGroup(\"/internal\").MapGroup(\"ops\").MapHealthChecks(\"ready\");\nvar assignedOps = app.MapGroup(\"/assigned\").MapGroup(\"ops\");\nassignedOps.MapHealthChecks(\"startup\");\n",
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();

        for route in [
            "/health/live",
            "/ops/live",
            "/internal/ops/ready",
            "/assigned/ops/startup",
        ] {
            assert!(
                map.surfaces.iter().any(|surface| {
                    surface.kind == AttackSurfaceKind::HttpRoute
                        && surface.route.as_deref() == Some(route)
                        && surface.method.as_deref() == Some("GET")
                        && surface.framework.as_deref() == Some("ASP.NET Core")
                }),
                "missing grouped health-check route: {route}"
            );
        }
    }

    #[test]
    fn attack_surface_detects_aspnet_grouped_fallback_routes() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Web.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk.Web\"></Project>\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("Program.cs"),
            "var app = WebApplication.CreateBuilder(args).Build();\napp.MapFallback(\"/{*path:nonfile}\", SpaFallback);\napp.MapGroup(\"/spa\").MapFallback(\"{*path:nonfile}\", SpaFallback);\napp.MapGroup(\"/spa\").MapFallbackToFile(\"index.html\");\napp.MapGroup(\"/tenant\").MapGroup(\"spa\").MapFallbackToPage(\"/_Host\");\nvar assignedSpa = app.MapGroup(\"/assigned\").MapGroup(\"spa\");\nassignedSpa.MapFallback(\"{*path:nonfile}\", AssignedFallback);\nassignedSpa.MapFallbackToFile(\"index.html\");\n",
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();

        for route in [
            "/{*path:nonfile}",
            "/spa/{*path:nonfile}",
            "/spa/*",
            "/tenant/spa/*",
            "/assigned/spa/{*path:nonfile}",
            "/assigned/spa/*",
        ] {
            assert!(
                map.surfaces.iter().any(|surface| {
                    surface.kind == AttackSurfaceKind::HttpRoute
                        && surface.route.as_deref() == Some(route)
                        && surface.method.as_deref() == Some("ANY")
                        && surface.framework.as_deref() == Some("ASP.NET Core")
                }),
                "missing grouped fallback route: {route}"
            );
        }
    }

    #[test]
    fn attack_surface_detects_aspnet_chained_grouped_default_routes() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Web.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk.Web\"></Project>\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("Program.cs"),
            "var app = WebApplication.CreateBuilder(args).Build();\napp.MapGroup(\"/docs\").MapOpenApi();\napp.MapGroup(\"/docs\").MapOpenApi(\"custom/{documentName}.json\");\napp.MapGroup(\"/docs\").MapSwagger();\napp.MapGroup(\"/docs\").MapSwagger(\"custom/{documentName}/swagger.json\");\napp.MapGroup(\"/api\").MapGraphQL();\napp.MapGroup(\"/api\").MapGraphQL(\"query\");\napp.MapGroup(\"/internal\").MapGroup(\"docs\").MapOpenApi();\napp.MapGroup(\"/internal\").MapGroup(\"api\").MapGraphQL(\"query\");\nvar assignedDocs = app.MapGroup(\"/assigned\").MapGroup(\"docs\");\nassignedDocs.MapOpenApi();\nassignedDocs.MapOpenApi(\"custom/{documentName}.json\");\nvar assignedApi = app.MapGroup(\"/assigned\").MapGroup(\"api\");\nassignedApi.MapGraphQL(\"query\");\n",
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();

        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/docs/openapi/{documentName}.json")
                && surface.method.as_deref() == Some("GET")
                && surface.framework.as_deref() == Some("ASP.NET Core")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/docs/custom/{documentName}.json")
                && surface.method.as_deref() == Some("GET")
                && surface.framework.as_deref() == Some("ASP.NET Core")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/docs/swagger/{documentName}/swagger.json")
                && surface.method.as_deref() == Some("GET")
                && surface.framework.as_deref() == Some("ASP.NET Core")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/docs/custom/{documentName}/swagger.json")
                && surface.method.as_deref() == Some("GET")
                && surface.framework.as_deref() == Some("ASP.NET Core")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::RpcHandler
                && surface.route.as_deref() == Some("/api/graphql")
                && surface.method.as_deref() == Some("ANY")
                && surface.framework.as_deref() == Some("ASP.NET Core")
                && surface.boundary.as_deref() == Some("remote_rpc")
                && surface
                    .metadata
                    .pointer("/detector")
                    .and_then(Value::as_str)
                    == Some("dotnet.graphql")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::RpcHandler
                && surface.route.as_deref() == Some("/api/query")
                && surface.method.as_deref() == Some("ANY")
                && surface.framework.as_deref() == Some("ASP.NET Core")
                && surface.boundary.as_deref() == Some("remote_rpc")
                && surface
                    .metadata
                    .pointer("/detector")
                    .and_then(Value::as_str)
                    == Some("dotnet.graphql")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/internal/docs/openapi/{documentName}.json")
                && surface.method.as_deref() == Some("GET")
                && surface.framework.as_deref() == Some("ASP.NET Core")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::RpcHandler
                && surface.route.as_deref() == Some("/internal/api/query")
                && surface.method.as_deref() == Some("ANY")
                && surface.framework.as_deref() == Some("ASP.NET Core")
                && surface.boundary.as_deref() == Some("remote_rpc")
                && surface
                    .metadata
                    .pointer("/detector")
                    .and_then(Value::as_str)
                    == Some("dotnet.graphql")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/assigned/docs/openapi/{documentName}.json")
                && surface.method.as_deref() == Some("GET")
                && surface.framework.as_deref() == Some("ASP.NET Core")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/assigned/docs/custom/{documentName}.json")
                && surface.method.as_deref() == Some("GET")
                && surface.framework.as_deref() == Some("ASP.NET Core")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::RpcHandler
                && surface.route.as_deref() == Some("/assigned/api/query")
                && surface.method.as_deref() == Some("ANY")
                && surface.framework.as_deref() == Some("ASP.NET Core")
                && surface.boundary.as_deref() == Some("remote_rpc")
                && surface
                    .metadata
                    .pointer("/detector")
                    .and_then(Value::as_str)
                    == Some("dotnet.graphql")
        }));
    }

    #[test]
    fn attack_surface_detects_aspnet_chained_grouped_ui_defaults() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Web.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk.Web\"></Project>\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("Program.cs"),
            "var app = WebApplication.CreateBuilder(args).Build();\napp.MapGroup(\"/admin\").MapRazorPages();\napp.MapGroup(\"/live\").MapBlazorHub();\napp.MapGroup(\"/live\").MapBlazorHub(\"custom-blazor\");\napp.MapGroup(\"/tenant\").MapRazorComponents<App>();\napp.MapGroup(\"/tenant\").MapRazorComponents<App>(\"ui/{**page}\");\napp.MapGroup(\"/internal\").MapGroup(\"live\").MapBlazorHub();\napp.MapGroup(\"/internal\").MapGroup(\"tenant\").MapRazorComponents<App>(\"ui/{**page}\");\nvar assignedLive = app.MapGroup(\"/assigned\").MapGroup(\"live\");\nassignedLive.MapBlazorHub();\nvar assignedTenant = app.MapGroup(\"/assigned\").MapGroup(\"tenant\");\nassignedTenant.MapRazorComponents<App>(\"ui/{**page}\");\n",
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();

        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/admin/{page}")
                && surface.method.as_deref() == Some("ANY")
                && surface.framework.as_deref() == Some("ASP.NET Core")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::RpcHandler
                && surface.route.as_deref() == Some("/live/_blazor")
                && surface.method.as_deref() == Some("ANY")
                && surface.framework.as_deref() == Some("ASP.NET Core")
                && surface.boundary.as_deref() == Some("remote_rpc")
                && surface
                    .metadata
                    .pointer("/detector")
                    .and_then(Value::as_str)
                    == Some("dotnet.blazor-hub")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::RpcHandler
                && surface.route.as_deref() == Some("/live/custom-blazor")
                && surface.method.as_deref() == Some("ANY")
                && surface.framework.as_deref() == Some("ASP.NET Core")
                && surface.boundary.as_deref() == Some("remote_rpc")
                && surface
                    .metadata
                    .pointer("/detector")
                    .and_then(Value::as_str)
                    == Some("dotnet.blazor-hub")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/tenant/{component}")
                && surface.method.as_deref() == Some("ANY")
                && surface.framework.as_deref() == Some("ASP.NET Core")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/tenant/ui/{**page}")
                && surface.method.as_deref() == Some("ANY")
                && surface.framework.as_deref() == Some("ASP.NET Core")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::RpcHandler
                && surface.route.as_deref() == Some("/internal/live/_blazor")
                && surface.method.as_deref() == Some("ANY")
                && surface.framework.as_deref() == Some("ASP.NET Core")
                && surface.boundary.as_deref() == Some("remote_rpc")
                && surface
                    .metadata
                    .pointer("/detector")
                    .and_then(Value::as_str)
                    == Some("dotnet.blazor-hub")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/internal/tenant/ui/{**page}")
                && surface.method.as_deref() == Some("ANY")
                && surface.framework.as_deref() == Some("ASP.NET Core")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::RpcHandler
                && surface.route.as_deref() == Some("/assigned/live/_blazor")
                && surface.method.as_deref() == Some("ANY")
                && surface.framework.as_deref() == Some("ASP.NET Core")
                && surface.boundary.as_deref() == Some("remote_rpc")
                && surface
                    .metadata
                    .pointer("/detector")
                    .and_then(Value::as_str)
                    == Some("dotnet.blazor-hub")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/assigned/tenant/ui/{**page}")
                && surface.method.as_deref() == Some("ANY")
                && surface.framework.as_deref() == Some("ASP.NET Core")
        }));
    }

    #[test]
    fn attack_surface_detects_jvm_async_event_workers() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/WorkerHandlers.java"),
            r#"
              class WorkerHandlers {
                @Async
                void sendEmail(EmailCommand command) {}
                @EventListener
                void onTenantEvent(TenantEvent event) {}
                @JmsListener(destination = "invoice-events")
                void consumeInvoice(String message) {}
              }
            "#,
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();
        let jvm_jobs = map
            .surfaces
            .iter()
            .filter(|surface| {
                surface.kind == AttackSurfaceKind::BackgroundJob
                    && surface
                        .metadata
                        .pointer("/detector")
                        .and_then(Value::as_str)
                        == Some("jvm.background-job")
            })
            .collect::<Vec<_>>();

        assert_eq!(jvm_jobs.len(), 3, "{:#?}", map.surfaces);
        assert!(jvm_jobs
            .iter()
            .any(|surface| surface.evidence.contains("@Async")));
        assert!(jvm_jobs
            .iter()
            .any(|surface| surface.evidence.contains("@EventListener")));
        assert!(jvm_jobs
            .iter()
            .any(|surface| surface.evidence.contains("@JmsListener")));
    }

    #[test]
    fn attack_surface_detects_jvm_messaging_batch_and_scheduler_jobs() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/JobConfig.java"),
            r#"
              import org.springframework.batch.core.configuration.annotation.EnableBatchProcessing;
              import org.springframework.scheduling.annotation.Scheduled;
              @EnableBatchProcessing
              class JobConfig {
                @Scheduled(cron = "0 0 * * * *")
                void hourlyDigest() {}
                void launch(JobLauncher jobLauncher, Job job) { jobLauncher.run(job, params); }
                void publish(KafkaTemplate<String, Event> kafkaTemplate) { kafkaTemplate.send("events", event); }
                void queue(RabbitTemplate rabbitTemplate) { rabbitTemplate.convertAndSend("jobs", job); }
                void notify(SqsAsyncClient sqsAsyncClient) { sqsAsyncClient.sendMessage(request); }
                TaskExecutor taskExecutor;
              }
              class NightlyQuartzJob extends QuartzJobBean {}
              class BillingQuartzJob implements Job {}
            "#,
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();
        let jobs = map
            .surfaces
            .iter()
            .filter(|surface| {
                surface.kind == AttackSurfaceKind::BackgroundJob
                    && surface
                        .metadata
                        .pointer("/detector")
                        .and_then(Value::as_str)
                        == Some("jvm.background-job")
            })
            .collect::<Vec<_>>();

        assert_eq!(jobs.len(), 9, "{:#?}", map.surfaces);
        assert!(jobs
            .iter()
            .all(|surface| surface.framework.as_deref() == Some("Spring")));
        assert!(jobs
            .iter()
            .all(|surface| surface.boundary.as_deref() == Some("async_job")));
    }

    #[test]
    fn attack_surface_detects_jvm_batch_step_and_item_jobs() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/BatchStepJobs.java"),
            r#"
              import org.springframework.batch.core.job.builder.JobBuilder;
              class BatchStepJobs {
                Tasklet cleanupTasklet;
                ItemReader<Customer> itemReader;
                ItemProcessor<Customer, Customer> itemProcessor;
                ItemWriter<Customer> itemWriter;
                RepositoryItemReader<Customer> repositoryItemReader;
                JdbcPagingItemReader<Customer> jdbcPagingItemReader;
                void build(JobRepository jobRepository, PlatformTransactionManager tx) {
                  new JobBuilder("billingImport", jobRepository);
                  new StepBuilder("loadCustomers", jobRepository);
                  stepBuilder.chunk(100, tx);
                  stepBuilder.tasklet(cleanupTasklet, tx);
                }
              }
            "#,
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();
        let jobs = map
            .surfaces
            .iter()
            .filter(|surface| {
                surface.kind == AttackSurfaceKind::BackgroundJob
                    && surface
                        .metadata
                        .pointer("/detector")
                        .and_then(Value::as_str)
                        == Some("jvm.background-job")
            })
            .collect::<Vec<_>>();

        assert_eq!(jobs.len(), 11, "{:#?}", map.surfaces);
        assert!(jobs
            .iter()
            .all(|surface| surface.framework.as_deref() == Some("Spring")));
        assert!(jobs
            .iter()
            .all(|surface| surface.boundary.as_deref() == Some("async_job")));
    }

    #[test]
    fn attack_surface_detects_jvm_scheduler_infrastructure_jobs() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/SchedulerConfig.java"),
            r#"
              import org.springframework.scheduling.annotation.EnableScheduling;
              @EnableScheduling
              class SchedulerConfig implements SchedulingConfigurer {
                TaskScheduler taskScheduler;
                ThreadPoolTaskScheduler threadPoolTaskScheduler;
                ScheduledTaskRegistrar taskRegistrar;
                ScheduledExecutorService executorService;
                void configureTasks(ScheduledTaskRegistrar registrar) {
                  registrar.setTaskScheduler(taskScheduler);
                  Executors.newScheduledThreadPool(4);
                }
              }
            "#,
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();
        let jobs = map
            .surfaces
            .iter()
            .filter(|surface| {
                surface.kind == AttackSurfaceKind::BackgroundJob
                    && surface
                        .metadata
                        .pointer("/detector")
                        .and_then(Value::as_str)
                        == Some("jvm.background-job")
            })
            .collect::<Vec<_>>();

        assert_eq!(jobs.len(), 9, "{:#?}", map.surfaces);
        assert!(jobs
            .iter()
            .all(|surface| surface.framework.as_deref() == Some("Spring")));
        assert!(jobs
            .iter()
            .all(|surface| surface.boundary.as_deref() == Some("async_job")));
    }

    #[test]
    fn attack_surface_detects_jvm_cloud_event_and_pulsar_jobs() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/CloudEventJobs.java"),
            r#"
              import org.springframework.pulsar.annotation.PulsarListener;
              class CloudEventJobs {
                @PulsarListener(topics = "tenant-events")
                void onPulsar(Event event) {}
                void publish(
                    SnsClient snsClient,
                    SnsAsyncClient snsAsyncClient,
                    EventBridgeClient eventBridgeClient,
                    EventBridgeAsyncClient eventBridgeAsyncClient,
                    KinesisClient kinesisClient,
                    KinesisAsyncClient kinesisAsyncClient,
                    PulsarClient pulsarClient,
                    SnsTemplate snsTemplate,
                    PulsarTemplate<Event> pulsarTemplate
                ) {}
              }
            "#,
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();
        let jobs = map
            .surfaces
            .iter()
            .filter(|surface| {
                surface.kind == AttackSurfaceKind::BackgroundJob
                    && surface
                        .metadata
                        .pointer("/detector")
                        .and_then(Value::as_str)
                        == Some("jvm.background-job")
            })
            .collect::<Vec<_>>();

        assert_eq!(jobs.len(), 10, "{:#?}", map.surfaces);
        assert!(jobs
            .iter()
            .all(|surface| surface.framework.as_deref() == Some("Spring")));
        assert!(jobs
            .iter()
            .all(|surface| surface.boundary.as_deref() == Some("async_job")));
    }

    #[test]
    fn attack_surface_detects_jvm_integration_handlers_as_background_jobs() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path()
                .join("src/main/java/app/IntegrationHandlers.java"),
            r#"
              import org.springframework.integration.annotation.InboundChannelAdapter;
              import org.springframework.integration.annotation.ServiceActivator;
              import org.springframework.integration.annotation.Transformer;
              import org.springframework.integration.dsl.IntegrationFlow;
              import org.springframework.kafka.annotation.KafkaHandler;
              import org.springframework.kafka.annotation.RetryableTopic;
              class IntegrationHandlers {
                @KafkaHandler
                void onKafka(Event event) {}
                @RabbitHandler
                void onRabbit(Event event) {}
                @JmsHandler
                void onJms(Event event) {}
                @StreamListener("orders")
                void onStream(Event event) {}
                @ServiceActivator(inputChannel = "orders")
                void activate(Event event) {}
                @Transformer(inputChannel = "orders")
                Event transform(Event event) { return event; }
                @InboundChannelAdapter(channel = "polling")
                MessageSource<?> poll() { return source; }
                @RetryableTopic
                void retry(Event event) {}
                IntegrationFlow inboundFlow;
                MessageHandler deadLetterHandler;
                Pollers.fixedRate(5000);
              }
            "#,
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();
        let jobs = map
            .surfaces
            .iter()
            .filter(|surface| {
                surface.kind == AttackSurfaceKind::BackgroundJob
                    && surface
                        .metadata
                        .pointer("/detector")
                        .and_then(Value::as_str)
                        == Some("jvm.background-job")
            })
            .collect::<Vec<_>>();

        assert_eq!(jobs.len(), 11, "{:#?}", map.surfaces);
        assert!(jobs
            .iter()
            .all(|surface| surface.framework.as_deref() == Some("Spring")));
        assert!(jobs
            .iter()
            .all(|surface| surface.boundary.as_deref() == Some("async_job")));
    }

    #[test]
    fn attack_surface_detects_dotnet_background_workers() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Web.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk.Web\"></Project>\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("Program.cs"),
            "builder.Services.AddHostedService<ReportWorker>();\nRecurringJob.AddOrUpdate(\"nightly-report\", () => RunReport());\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("ReportWorker.cs"),
            "class ReportWorker : BackgroundService { protected override Task ExecuteAsync(CancellationToken token) => Task.CompletedTask; }\n",
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();
        let dotnet_jobs = map
            .surfaces
            .iter()
            .filter(|surface| {
                surface.kind == AttackSurfaceKind::BackgroundJob
                    && surface
                        .metadata
                        .pointer("/detector")
                        .and_then(Value::as_str)
                        == Some("dotnet.background-job")
            })
            .collect::<Vec<_>>();

        assert_eq!(dotnet_jobs.len(), 3, "{:#?}", map.surfaces);
        assert!(dotnet_jobs
            .iter()
            .all(|surface| surface.framework.as_deref() == Some("ASP.NET Core")));
    }

    #[test]
    fn attack_surface_detects_dotnet_message_consumers() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Web.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk.Web\"></Project>\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("BillingConsumer.cs"),
            "class BillingConsumer : IConsumer<BillingEvent> { public Task Consume(ConsumeContext<BillingEvent> context) => Task.CompletedTask; }\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("Program.cs"),
            "builder.Services.AddMassTransit(x => x.AddConsumer<BillingConsumer>());\ncfg.ReceiveEndpoint(\"billing-events\", e => e.ConfigureConsumer<BillingConsumer>(context));\n",
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();
        let consumers = map
            .surfaces
            .iter()
            .filter(|surface| {
                surface.kind == AttackSurfaceKind::BackgroundJob
                    && surface
                        .metadata
                        .pointer("/detector")
                        .and_then(Value::as_str)
                        == Some("dotnet.background-job")
            })
            .collect::<Vec<_>>();

        assert_eq!(consumers.len(), 3, "{:#?}", map.surfaces);
        assert!(consumers
            .iter()
            .all(|surface| surface.framework.as_deref() == Some("ASP.NET Core")));
    }

    #[test]
    fn attack_surface_detects_dotnet_quartz_scheduled_jobs() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Web.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk.Web\"></Project>\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("Program.cs"),
            "builder.Services.AddQuartz(q => {});\nbuilder.Services.AddQuartzHostedService(options => {});\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("NightlyJob.cs"),
            "class NightlyJob : IJob {\npublic Task Execute(IJobExecutionContext context) => Task.CompletedTask;\n}\n",
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();
        let quartz_jobs = map
            .surfaces
            .iter()
            .filter(|surface| {
                surface.kind == AttackSurfaceKind::BackgroundJob
                    && surface
                        .metadata
                        .pointer("/detector")
                        .and_then(Value::as_str)
                        == Some("dotnet.background-job")
            })
            .collect::<Vec<_>>();

        assert_eq!(quartz_jobs.len(), 4, "{:#?}", map.surfaces);
        assert!(quartz_jobs
            .iter()
            .all(|surface| surface.framework.as_deref() == Some("ASP.NET Core")));
    }

    #[test]
    fn attack_surface_detects_dotnet_websocket_boundaries() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Web.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk.Web\"></Project>\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("Program.cs"),
            "app.UseWebSockets();\nvar socket = await context.WebSockets.AcceptWebSocketAsync();\n",
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();
        let websockets = map
            .surfaces
            .iter()
            .filter(|surface| {
                surface.kind == AttackSurfaceKind::RpcHandler
                    && surface
                        .metadata
                        .pointer("/detector")
                        .and_then(Value::as_str)
                        == Some("dotnet.websocket")
            })
            .collect::<Vec<_>>();

        assert_eq!(websockets.len(), 2, "{:#?}", map.surfaces);
        assert!(websockets
            .iter()
            .all(|surface| surface.framework.as_deref() == Some("ASP.NET Core")));
        assert!(websockets
            .iter()
            .all(|surface| surface.boundary.as_deref() == Some("remote_rpc")));
    }

    #[test]
    fn attack_surface_detects_dotnet_signalr_service_boundaries() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Web.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk.Web\"></Project>\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("Program.cs"),
            "builder.Services.AddSignalR();\nclass AdminHub : Hub {}\nclass ChatHub : Hub<IChatClient> {}\n",
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();
        let signalr = map
            .surfaces
            .iter()
            .filter(|surface| {
                surface.kind == AttackSurfaceKind::RpcHandler
                    && surface
                        .metadata
                        .pointer("/detector")
                        .and_then(Value::as_str)
                        == Some("dotnet.signalr-service")
            })
            .collect::<Vec<_>>();

        assert_eq!(signalr.len(), 3, "{:#?}", map.surfaces);
        assert!(signalr
            .iter()
            .all(|surface| surface.framework.as_deref() == Some("ASP.NET Core")));
        assert!(signalr
            .iter()
            .all(|surface| surface.boundary.as_deref() == Some("remote_rpc")));
    }

    #[test]
    fn attack_surface_detects_aspnet_grouped_signalr_hub_routes() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Web.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk.Web\"></Project>\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("Program.cs"),
            "var app = WebApplication.CreateBuilder(args).Build();\napp.MapHub<AdminHub>(\"/hubs/admin\");\napp.MapGroup(\"/realtime\").MapHub<AdminHub>(\"admin\");\napp.MapGroup(\"/internal\").MapGroup(\"realtime\").MapHub<AuditHub>(\"audit\");\nvar assignedRealtime = app.MapGroup(\"/assigned\").MapGroup(\"realtime\");\nassignedRealtime.MapHub<ChatHub>(\"chat\");\n",
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();

        for route in [
            "/hubs/admin",
            "/realtime/admin",
            "/internal/realtime/audit",
            "/assigned/realtime/chat",
        ] {
            assert!(
                map.surfaces.iter().any(|surface| {
                    surface.kind == AttackSurfaceKind::RpcHandler
                        && surface.route.as_deref() == Some(route)
                        && surface.method.as_deref() == Some("ANY")
                        && surface.framework.as_deref() == Some("ASP.NET Core")
                        && surface.boundary.as_deref() == Some("remote_rpc")
                        && surface
                            .metadata
                            .pointer("/detector")
                            .and_then(Value::as_str)
                            == Some("dotnet.signalr-hub")
                }),
                "missing grouped SignalR hub route: {route}"
            );
        }
    }

    #[test]
    fn attack_surface_detects_dotnet_grpc_web_boundaries() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Web.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk.Web\"></Project>\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("Program.cs"),
            "builder.Services.AddGrpc();\napp.UseGrpcWeb();\napp.MapGrpcService<GreeterService>().EnableGrpcWeb();\n",
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();
        let grpc_web = map
            .surfaces
            .iter()
            .filter(|surface| {
                surface.kind == AttackSurfaceKind::RpcHandler
                    && surface
                        .metadata
                        .pointer("/detector")
                        .and_then(Value::as_str)
                        == Some("dotnet.grpc-web")
            })
            .collect::<Vec<_>>();

        assert_eq!(grpc_web.len(), 3, "{:#?}", map.surfaces);
        assert!(grpc_web
            .iter()
            .all(|surface| surface.framework.as_deref() == Some("ASP.NET Core")));
        assert!(grpc_web
            .iter()
            .all(|surface| surface.boundary.as_deref() == Some("remote_rpc")));
    }

    #[test]
    fn attack_surface_detects_aspnet_grouped_grpc_service_routes() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Web.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk.Web\"></Project>\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("Program.cs"),
            "builder.Services.AddGrpc();\nvar app = WebApplication.CreateBuilder(args).Build();\napp.MapGrpcService<GreeterService>();\napp.MapGroup(\"/grpc\").MapGrpcService<GreeterService>();\napp.MapGroup(\"/internal\").MapGroup(\"grpc\").MapGrpcService<AdminService>();\nvar assignedGrpc = app.MapGroup(\"/assigned\").MapGroup(\"grpc\");\nassignedGrpc.MapGrpcService<AuditService>();\n",
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();

        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::RpcHandler
                && surface.route.is_none()
                && surface.method.as_deref() == Some("ANY")
                && surface.framework.as_deref() == Some("ASP.NET Core")
                && surface.boundary.as_deref() == Some("rpc_handler")
                && surface
                    .metadata
                    .pointer("/detector")
                    .and_then(Value::as_str)
                    == Some("dotnet.grpc-service")
        }));
        for route in ["/grpc", "/internal/grpc", "/assigned/grpc"] {
            assert!(
                map.surfaces.iter().any(|surface| {
                    surface.kind == AttackSurfaceKind::RpcHandler
                        && surface.route.as_deref() == Some(route)
                        && surface.method.as_deref() == Some("ANY")
                        && surface.framework.as_deref() == Some("ASP.NET Core")
                        && surface.boundary.as_deref() == Some("rpc_handler")
                        && surface
                            .metadata
                            .pointer("/detector")
                            .and_then(Value::as_str)
                            == Some("dotnet.grpc-service")
                }),
                "missing grouped gRPC service route: {route}"
            );
        }
    }

    #[test]
    fn attack_surface_detects_dotnet_graphql_service_boundaries() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Web.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk.Web\"></Project>\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("Graphql.cs"),
            r#"
              builder.Services.AddGraphQLServer();
              builder.Services.AddGraphQL(options => {});
              builder.Services.AddGraphQLServer().AddQueryType<Query>();
              builder.Services.AddGraphQLServer().AddMutationType<Mutation>();
              builder.Services.AddGraphQLServer().AddSubscriptionType<Subscription>();
              [ExtendObjectType("Query")]
              class UserQueries {}
              [GraphQLName("account")]
              class AccountQueries {}
              class UserType : ObjectType<User> {}
            "#,
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();
        let graphql = map
            .surfaces
            .iter()
            .filter(|surface| {
                surface.kind == AttackSurfaceKind::RpcHandler
                    && surface
                        .metadata
                        .pointer("/detector")
                        .and_then(Value::as_str)
                        == Some("dotnet.graphql-service")
            })
            .collect::<Vec<_>>();

        assert_eq!(graphql.len(), 8, "{:#?}", map.surfaces);
        assert!(graphql
            .iter()
            .all(|surface| surface.framework.as_deref() == Some("ASP.NET Core")));
        assert!(graphql
            .iter()
            .all(|surface| surface.boundary.as_deref() == Some("remote_rpc")));
    }

    #[test]
    fn attack_surface_detects_dotnet_upload_limits_as_file_upload_parser() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Web.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk.Web\"></Project>\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("UploadController.cs"),
            r#"
              [RequestSizeLimit(10485760)]
              [RequestFormLimits(MultipartBodyLengthLimit = 10485760)]
              [DisableRequestSizeLimit]
              class UploadController {
                void Import(IFormFile file) {}
              }
            "#,
        )
        .unwrap();
        fs::write(
            temp.path().join("Program.cs"),
            "builder.Services.Configure<FormOptions>(options => options.MultipartBodyLengthLimit = 10485760);\n",
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();
        let upload_surfaces = map
            .surfaces
            .iter()
            .filter(|surface| {
                surface.kind == AttackSurfaceKind::FileUploadParsePath
                    && surface
                        .metadata
                        .pointer("/detector")
                        .and_then(Value::as_str)
                        == Some("dotnet.file-upload")
            })
            .count();

        assert_eq!(upload_surfaces, 5, "{:#?}", map.surfaces);
    }

    #[test]
    fn attack_surface_detects_dotnet_data_external_and_process_boundaries() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Web.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk.Web\"></Project>\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("AdminTasks.cs"),
            r#"
              class AdminTasks {
                void Run() {
                  using var cmd = new SqlCommand("select * from users", connection);
                  var response = new HttpClient().GetAsync(remoteUrl);
                  Process.Start(new ProcessStartInfo("sh", "-c " + input));
                }
              }
            "#,
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();
        assert_detector(&map, "dotnet.db-query");
        assert_detector(&map, "dotnet.external-client");
        assert_detector(&map, "dotnet.command-exec");
        assert_has_kind(&map, AttackSurfaceKind::DbQueryBoundary);
        assert_has_kind(&map, AttackSurfaceKind::ExternalServiceClient);
        assert_has_kind(&map, AttackSurfaceKind::CommandExecutionBoundary);
    }

    #[test]
    fn attack_surface_detects_dotnet_process_start_configuration_as_command_exec() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Web.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk.Web\"></Project>\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("ShellRunner.cs"),
            r#"
              class ShellRunner {
                void Run(string input) {
                  var startInfo = new ProcessStartInfo();
                  startInfo.FileName = "cmd.exe";
                  startInfo.Arguments = "/c " + input;
                  startInfo.UseShellExecute = false;
                  startInfo.RedirectStandardOutput = true;
                  startInfo.RedirectStandardError = true;
                  System.Diagnostics.Process.Start(startInfo);
                }
              }
            "#,
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();
        let command_surfaces = map
            .surfaces
            .iter()
            .filter(|surface| {
                surface.kind == AttackSurfaceKind::CommandExecutionBoundary
                    && surface
                        .metadata
                        .pointer("/detector")
                        .and_then(Value::as_str)
                        == Some("dotnet.command-exec")
            })
            .collect::<Vec<_>>();

        assert_eq!(command_surfaces.len(), 7, "{:#?}", map.surfaces);
        assert!(command_surfaces
            .iter()
            .all(|surface| surface.framework.as_deref() == Some("ASP.NET Core")));
        assert!(command_surfaces
            .iter()
            .all(|surface| surface.boundary.as_deref() == Some("process_execution")));
    }

    #[test]
    fn attack_surface_detects_dotnet_grpc_clients_as_external_services() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Web.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk.Web\"></Project>\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("Program.cs"),
            "builder.Services.AddGrpcClient<Billing.BillingClient>(options => options.Address = billingUri);\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("BillingClient.cs"),
            "var channel = GrpcChannel.ForAddress(remoteUrl, new GrpcChannelOptions { HttpClient = httpClient });\n",
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();
        let grpc_clients = map
            .surfaces
            .iter()
            .filter(|surface| {
                surface.kind == AttackSurfaceKind::ExternalServiceClient
                    && surface
                        .metadata
                        .pointer("/detector")
                        .and_then(Value::as_str)
                        == Some("dotnet.external-client")
            })
            .collect::<Vec<_>>();

        assert_eq!(grpc_clients.len(), 2, "{:#?}", map.surfaces);
        assert!(grpc_clients
            .iter()
            .all(|surface| surface.framework.as_deref() == Some("ASP.NET Core")));
        assert!(grpc_clients
            .iter()
            .all(|surface| surface.boundary.as_deref() == Some("external_service")));
    }

    #[test]
    fn attack_surface_detects_dotnet_legacy_rest_clients_as_external_services() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Web.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk.Web\"></Project>\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("LegacyClients.cs"),
            r#"
              class LegacyClients {
                void Fetch() {
                  using var web = new WebClient();
                  var body = web.DownloadString(remoteUrl);
                  var upload = web.UploadString(remoteUrl, payload);
                  var request = WebRequest.Create(remoteUrl);
                  var typed = (HttpWebRequest)WebRequest.Create(apiUrl);
                  var client = new RestClient(remoteUrl);
                  var restRequest = new RestRequest("/invoices");
                }
              }
            "#,
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();
        let rest_clients = map
            .surfaces
            .iter()
            .filter(|surface| {
                surface.kind == AttackSurfaceKind::ExternalServiceClient
                    && surface
                        .metadata
                        .pointer("/detector")
                        .and_then(Value::as_str)
                        == Some("dotnet.external-client")
            })
            .collect::<Vec<_>>();

        assert_eq!(rest_clients.len(), 7, "{:#?}", map.surfaces);
        assert!(rest_clients
            .iter()
            .all(|surface| surface.framework.as_deref() == Some("ASP.NET Core")));
        assert!(rest_clients
            .iter()
            .all(|surface| surface.boundary.as_deref() == Some("external_service")));
    }

    #[test]
    fn attack_surface_detects_dotnet_cache_data_store_boundaries() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Web.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk.Web\"></Project>\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("Program.cs"),
            "builder.Services.AddStackExchangeRedisCache(options => options.Configuration = redisUrl);\nbuilder.Services.AddDistributedMemoryCache();\nvar mux = ConnectionMultiplexer.Connect(redisUrl);\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("CacheStore.cs"),
            "class CacheStore { private readonly IDistributedCache cache; private readonly IMemoryCache memory; }\n",
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();
        let data_stores = map
            .surfaces
            .iter()
            .filter(|surface| {
                surface.kind == AttackSurfaceKind::DbQueryBoundary
                    && surface
                        .metadata
                        .pointer("/detector")
                        .and_then(Value::as_str)
                        == Some("dotnet.db-query")
            })
            .collect::<Vec<_>>();

        assert_eq!(data_stores.len(), 4, "{:#?}", map.surfaces);
        assert!(data_stores
            .iter()
            .all(|surface| surface.framework.as_deref() == Some("ASP.NET Core")));
        assert!(data_stores
            .iter()
            .all(|surface| surface.boundary.as_deref() == Some("data_store")));
    }

    #[test]
    fn attack_surface_detects_dotnet_output_cache_data_store_boundaries() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Web.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk.Web\"></Project>\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("Program.cs"),
            r#"
              builder.Services.AddOutputCache();
              builder.Services.AddResponseCaching();
              app.UseOutputCache();
              app.UseResponseCaching();
              app.MapGet("/reports", Reports).CacheOutput();
              [OutputCache]
              [ResponseCache(Duration = 60)]
              class ReportsController {}
            "#,
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();
        let data_stores = map
            .surfaces
            .iter()
            .filter(|surface| {
                surface.kind == AttackSurfaceKind::DbQueryBoundary
                    && surface
                        .metadata
                        .pointer("/detector")
                        .and_then(Value::as_str)
                        == Some("dotnet.db-query")
            })
            .collect::<Vec<_>>();

        assert_eq!(data_stores.len(), 7, "{:#?}", map.surfaces);
        assert!(data_stores
            .iter()
            .all(|surface| surface.framework.as_deref() == Some("ASP.NET Core")));
        assert!(data_stores
            .iter()
            .all(|surface| surface.boundary.as_deref() == Some("data_store")));
    }

    #[test]
    fn attack_surface_detects_dotnet_ef_core_data_store_boundaries() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Web.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk.Web\"></Project>\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("Program.cs"),
            r#"
              builder.Services.AddDbContext<AppDbContext>(options => options.UseSqlServer(connectionString));
              builder.Services.AddDbContextPool<AuditDbContext>(options => options.UseNpgsql(auditConnection));
            "#,
        )
        .unwrap();
        fs::write(
            temp.path().join("AppDbContext.cs"),
            r#"
              class AppDbContext : DbContext {
                AppDbContext(DbContextOptions<AppDbContext> options) : base(options) {}
                DbSet<User> Users { get; set; }
              }
            "#,
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();
        let data_stores = map
            .surfaces
            .iter()
            .filter(|surface| {
                surface.kind == AttackSurfaceKind::DbQueryBoundary
                    && surface
                        .metadata
                        .pointer("/detector")
                        .and_then(Value::as_str)
                        == Some("dotnet.db-query")
            })
            .collect::<Vec<_>>();

        assert_eq!(data_stores.len(), 4, "{:#?}", map.surfaces);
        assert!(data_stores
            .iter()
            .all(|surface| surface.framework.as_deref() == Some("ASP.NET Core")));
        assert!(data_stores
            .iter()
            .all(|surface| surface.boundary.as_deref() == Some("data_store")));
    }

    #[test]
    fn attack_surface_detects_ruby_rails_security_boundaries() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("app/controllers")).unwrap();
        fs::create_dir_all(temp.path().join("config")).unwrap();
        fs::write(temp.path().join("Gemfile"), "gem 'rails'\ngem 'sidekiq'\n").unwrap();
        fs::write(
            temp.path().join("config/routes.rb"),
            r#"
              Rails.application.routes.draw do
                post "/admin/invite", to: "admin#invite"
                post "/webhooks/signed", to: "admin#signed"
                post "admin#invite", to: "admin#invite"
              end
            "#,
        )
        .unwrap();
        fs::write(
            temp.path().join("app/controllers/admin_controller.rb"),
            r#"
              class AdminController < ApplicationController
                before_action :authenticate_user!
                protect_from_forgery with: :exception
                has_one_attached :import_file
                def invite
                  authorize current_user
                  session[:user_id] = current_user.id
                  tenant_id = current_user.tenant_id
                  account = current_account
                  uploaded_file = params[:file]
                  YAML.load(params[:payload])
                  ActiveRecord::Base.connection.execute(params[:sql])
                  Faraday.post(params[:url])
                  system(params[:cmd])
                  InviteWorker.perform_async(params[:user_id])
                end
                def signed
                  signature = request.headers["X-Signature"]
                  render json: { signature: signature }
                end
              end
            "#,
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();

        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/admin/invite")
                && surface.framework.as_deref() == Some("Rails")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/webhooks/signed")
                && surface.framework.as_deref() == Some("Rails")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::RequestTrustBoundary
                && surface.evidence.contains("request.headers")
                && surface
                    .metadata
                    .pointer("/detector")
                    .and_then(Value::as_str)
                    == Some("ruby.request-trust")
        }));
        assert_has_kind(&map, AttackSurfaceKind::AuthBoundary);
        assert_has_kind(&map, AttackSurfaceKind::SessionStateBoundary);
        assert_has_kind(&map, AttackSurfaceKind::RequestTrustBoundary);
        assert_has_kind(&map, AttackSurfaceKind::TenantIsolationBoundary);
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::TenantIsolationBoundary
                && surface.evidence.contains("current_account")
                && surface
                    .metadata
                    .pointer("/detector")
                    .and_then(Value::as_str)
                    == Some("ruby.tenant-isolation")
        }));
        assert_has_kind(&map, AttackSurfaceKind::DeserializationPoint);
        assert_has_kind(&map, AttackSurfaceKind::FileUploadParsePath);
        assert_detector(&map, "ruby.file-upload");
        assert_has_kind(&map, AttackSurfaceKind::DbQueryBoundary);
        assert_has_kind(&map, AttackSurfaceKind::ExternalServiceClient);
        assert_has_kind(&map, AttackSurfaceKind::CommandExecutionBoundary);
        assert_has_kind(&map, AttackSurfaceKind::BackgroundJob);
        assert_no_surface_route(&map, AttackSurfaceKind::HttpRoute, "admin#invite");
    }

    #[test]
    fn attack_surface_detects_ruby_worker_definitions() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("app/jobs")).unwrap();
        fs::create_dir_all(temp.path().join("app/workers")).unwrap();
        fs::write(temp.path().join("Gemfile"), "gem 'rails'\ngem 'sidekiq'\n").unwrap();
        fs::write(
            temp.path().join("app/jobs/report_job.rb"),
            "class ReportJob < ApplicationJob\n  def perform(account_id); end\nend\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("app/workers/invite_worker.rb"),
            "class InviteWorker\n  include Sidekiq::Job\n  def perform(user_id); end\nend\n",
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();
        let ruby_jobs = map
            .surfaces
            .iter()
            .filter(|surface| {
                surface.kind == AttackSurfaceKind::BackgroundJob
                    && surface
                        .metadata
                        .pointer("/detector")
                        .and_then(Value::as_str)
                        == Some("ruby.background-job")
            })
            .collect::<Vec<_>>();

        assert_eq!(ruby_jobs.len(), 2, "{:#?}", map.surfaces);
        assert!(ruby_jobs
            .iter()
            .any(|surface| surface.evidence.contains("ApplicationJob")));
        assert!(ruby_jobs
            .iter()
            .any(|surface| surface.evidence.contains("Sidekiq::Job")));
    }

    #[test]
    fn attack_surface_detects_php_laravel_security_boundaries() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("routes")).unwrap();
        fs::create_dir_all(temp.path().join("app/Http/Controllers")).unwrap();
        fs::write(
            temp.path().join("composer.json"),
            r#"{"require":{"laravel/framework":"^10"}}"#,
        )
        .unwrap();
        fs::write(
            temp.path().join("routes/web.php"),
            r#"
              <?php
              use Illuminate\Support\Facades\Route;
              Route::post('/admin/invite', [AdminController::class, 'invite'])->middleware('auth');
              Route::post('/webhooks/signed', [AdminController::class, 'signed']);
              Route::get('users.index', [AdminController::class, 'index']);
            "#,
        )
        .unwrap();
        fs::write(
            temp.path().join("app/Http/Controllers/AdminController.php"),
            r#"
              <?php
              class AdminController {
                public function invite(Request $request) {
                  $this->authorize('invite', User::class);
                  session(['user_id' => Auth::id()]);
                  VerifyCsrfToken::class;
                  $tenant_id = $request->user()->tenant_id;
                  $team = $request->user()->currentTeam;
                  json_decode($request->input('payload'));
                  if ($request->hasFile('import')) {
                    $request->file('import')->store('imports');
                  }
                  DB::select($request->input('sql'));
                  Http::post($request->input('url'));
                  shell_exec($request->input('cmd'));
                  InviteJob::dispatch($request->input('user_id'));
                }
                public function signed(Request $request) {
                  $signature = $request->header('X-Signature');
                  return response()->json(['signature' => $signature]);
                }
              }
            "#,
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();

        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/admin/invite")
                && surface.framework.as_deref() == Some("Laravel")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/webhooks/signed")
                && surface.framework.as_deref() == Some("Laravel")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::RequestTrustBoundary
                && surface.evidence.contains("$request->header")
                && surface
                    .metadata
                    .pointer("/detector")
                    .and_then(Value::as_str)
                    == Some("php.request-trust")
        }));
        assert_has_kind(&map, AttackSurfaceKind::AuthBoundary);
        assert_has_kind(&map, AttackSurfaceKind::SessionStateBoundary);
        assert_has_kind(&map, AttackSurfaceKind::RequestTrustBoundary);
        assert_has_kind(&map, AttackSurfaceKind::TenantIsolationBoundary);
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::TenantIsolationBoundary
                && surface.evidence.contains("currentTeam")
                && surface
                    .metadata
                    .pointer("/detector")
                    .and_then(Value::as_str)
                    == Some("php.tenant-isolation")
        }));
        assert_has_kind(&map, AttackSurfaceKind::DeserializationPoint);
        assert_has_kind(&map, AttackSurfaceKind::FileUploadParsePath);
        assert_detector(&map, "php.file-upload");
        assert_has_kind(&map, AttackSurfaceKind::DbQueryBoundary);
        assert_has_kind(&map, AttackSurfaceKind::ExternalServiceClient);
        assert_has_kind(&map, AttackSurfaceKind::CommandExecutionBoundary);
        assert_has_kind(&map, AttackSurfaceKind::BackgroundJob);
        assert_no_surface_route(&map, AttackSurfaceKind::HttpRoute, "users.index");
    }

    #[test]
    fn attack_surface_preserves_laravel_match_methods() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("routes")).unwrap();
        fs::create_dir_all(temp.path().join("app/Http/Controllers")).unwrap();
        fs::write(
            temp.path().join("composer.json"),
            r#"{"require":{"laravel/framework":"^10"}}"#,
        )
        .unwrap();
        fs::write(
            temp.path().join("routes/web.php"),
            "<?php\nRoute::match(['post'], '/imports/file', [ImportController::class, 'store']);\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("app/Http/Controllers/ImportController.php"),
            "<?php\nclass ImportController { public function store(Request $request) { $request->file('import')->store('imports'); } }\n",
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();

        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/imports/file")
                && surface.method.as_deref() == Some("POST")
                && surface.framework.as_deref() == Some("Laravel")
        }));
        assert_detector(&map, "php.file-upload");
    }

    #[test]
    fn attack_surface_detects_symfony_messenger_handlers() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/MessageHandler")).unwrap();
        fs::write(
            temp.path().join("composer.json"),
            r#"{"require":{"symfony/messenger":"^7.0"}}"#,
        )
        .unwrap();
        fs::write(
            temp.path().join("src/MessageHandler/InvoiceHandler.php"),
            "<?php\n#[AsMessageHandler]\nclass InvoiceHandler implements MessageHandlerInterface {\npublic function __invoke(InvoiceMessage $message): void {}\n}\n",
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();
        let php_jobs = map
            .surfaces
            .iter()
            .filter(|surface| {
                surface.kind == AttackSurfaceKind::BackgroundJob
                    && surface
                        .metadata
                        .pointer("/detector")
                        .and_then(Value::as_str)
                        == Some("php.background-job")
            })
            .collect::<Vec<_>>();

        assert_eq!(php_jobs.len(), 2, "{:#?}", map.surfaces);
        assert!(php_jobs
            .iter()
            .any(|surface| surface.evidence.contains("AsMessageHandler")));
        assert!(php_jobs
            .iter()
            .any(|surface| surface.evidence.contains("MessageHandlerInterface")));
    }

    #[test]
    fn attack_surface_detects_symfony_request_file_uploads() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/Controller")).unwrap();
        fs::write(
            temp.path().join("composer.json"),
            r#"{"require":{"symfony/http-foundation":"^7.0"}}"#,
        )
        .unwrap();
        fs::write(
            temp.path().join("src/Controller/ImportController.php"),
            "<?php\nclass ImportController {\npublic function upload(Request $request): Response {\n$archive = $request->files->get('archive');\nreturn new Response($archive->getClientOriginalName());\n}\n}\n",
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();
        let upload_surface = map
            .surfaces
            .iter()
            .find(|surface| {
                surface.kind == AttackSurfaceKind::FileUploadParsePath
                    && surface.evidence.contains("files->get")
                    && surface
                        .metadata
                        .pointer("/detector")
                        .and_then(Value::as_str)
                        == Some("php.file-upload")
            })
            .unwrap_or_else(|| {
                panic!("missing Symfony request file upload in {:#?}", map.surfaces)
            });

        assert!(upload_surface
            .risk
            .reasons
            .contains(&"evidence references request-controlled data".to_string()));
    }

    #[test]
    fn attack_surface_promotes_django_urlpatterns_to_http_routes() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("requirements.txt"), "django\n").unwrap();
        fs::write(
            temp.path().join("urls.py"),
            "from django.urls import path\nurlpatterns = [path('billing/api-keys/', views.keys)]\n",
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();

        let surface = map
            .surfaces
            .iter()
            .find(|surface| {
                surface.kind == AttackSurfaceKind::HttpRoute
                    && surface.route.as_deref() == Some("/billing/api-keys/")
            })
            .unwrap_or_else(|| panic!("missing Django route in {:#?}", map.surfaces));
        assert_eq!(surface.framework.as_deref(), Some("Django"));
        assert_eq!(surface.method.as_deref(), Some("ANY"));
        assert!(surface
            .risk
            .reasons
            .contains(&"route touches auth or admin workflow".to_string()));
    }

    #[test]
    fn attack_surface_preserves_django_as_view_methods() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("requirements.txt"),
            "django\ndjangorestframework\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("urls.py"),
            "from django.urls import path\nurlpatterns = [path('imports/file/', ImportView.as_view({'post': 'create'}))]\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("views.py"),
            "from rest_framework.parsers import MultiPartParser\n@parser_classes([MultiPartParser])\ndef create(request): pass\n",
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();

        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/imports/file/")
                && surface.method.as_deref() == Some("POST")
                && surface.framework.as_deref() == Some("Django")
        }));
        assert_detector(&map, "python.file-upload");
    }

    #[test]
    fn attack_surface_preserves_fastapi_api_route_methods() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("requirements.txt"), "fastapi\n").unwrap();
        fs::write(
            temp.path().join("main.py"),
            "from fastapi import FastAPI, File, UploadFile\napp = FastAPI()\n@app.api_route('/imports/file', methods=['POST'])\ndef ingest(file: UploadFile = File(...)): pass\n@app.api_route('/saml/callback', methods=['OPTIONS', 'HEAD'])\ndef preflight(): pass\n",
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();

        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/imports/file")
                && surface.method.as_deref() == Some("POST")
                && surface.framework.as_deref() == Some("FastAPI")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/saml/callback")
                && surface.method.as_deref() == Some("OPTIONS,HEAD")
                && surface.framework.as_deref() == Some("FastAPI")
        }));
        assert_detector(&map, "python.file-upload");
    }

    #[test]
    fn attack_surface_preserves_flask_add_url_rule_methods() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("requirements.txt"), "flask\n").unwrap();
        fs::write(
            temp.path().join("app.py"),
            "from flask import Flask, request\napp = Flask(__name__)\napp.add_url_rule('/imports/file', view_func=upload, methods=['POST'])\ndef upload():\n    return request.files['file'].filename\n",
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();

        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/imports/file")
                && surface.method.as_deref() == Some("POST")
                && surface.framework.as_deref() == Some("Flask")
        }));
        assert_detector(&map, "python.file-upload");
    }

    #[test]
    fn attack_surface_preserves_starlette_route_methods() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("requirements.txt"), "starlette\n").unwrap();
        fs::write(
            temp.path().join("app.py"),
            "from starlette.applications import Starlette\nfrom starlette.datastructures import UploadFile\nfrom starlette.routing import Route\nroutes = [Route('/imports/file', upload, methods=['POST'])]\nasync def upload(request):\n    form = await request.form()\n    uploaded: UploadFile = form['file']\n    return uploaded.filename\napp = Starlette(routes=routes)\n",
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();

        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/imports/file")
                && surface.method.as_deref() == Some("POST")
                && surface.framework.as_deref() == Some("Starlette")
        }));
        assert_detector(&map, "python.file-upload");
    }

    #[test]
    fn attack_surface_preserves_aiohttp_route_methods() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("requirements.txt"), "aiohttp\n").unwrap();
        fs::write(
            temp.path().join("app.py"),
            "from aiohttp import web\napp = web.Application()\napp.router.add_post('/imports/file', upload)\napp.router.add_route('OPTIONS', '/saml/callback', callback)\nasync def upload(request):\n    reader = await request.multipart()\n    return reader\n",
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();

        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/imports/file")
                && surface.method.as_deref() == Some("POST")
                && surface.framework.as_deref() == Some("aiohttp")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/saml/callback")
                && surface.method.as_deref() == Some("OPTIONS")
                && surface.framework.as_deref() == Some("aiohttp")
        }));
        assert_detector(&map, "python.file-upload");
    }

    #[test]
    fn attack_surface_preserves_tornado_route_methods() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("requirements.txt"), "tornado\n").unwrap();
        fs::write(
            temp.path().join("app.py"),
            "import tornado.web\nclass UploadHandler(tornado.web.RequestHandler):\n    def post(self):\n        upload = self.request.files['file'][0]\n        return upload.filename\napp = tornado.web.Application([\n    (r\"/imports/file\", UploadHandler),\n])\n",
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();

        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/imports/file")
                && surface.method.as_deref() == Some("POST")
                && surface.framework.as_deref() == Some("Tornado")
        }));
        assert_detector(&map, "python.file-upload");
    }

    #[test]
    fn attack_surface_preserves_bottle_route_methods() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("requirements.txt"), "bottle\n").unwrap();
        fs::write(
            temp.path().join("app.py"),
            "from bottle import post, request, route\n@post('/imports/file')\ndef upload():\n    return request.files.get('file').filename\n@route('/webhooks/signed', method='POST')\ndef webhook(): pass\n",
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();

        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/imports/file")
                && surface.method.as_deref() == Some("POST")
                && surface.framework.as_deref() == Some("Bottle")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/webhooks/signed")
                && surface.method.as_deref() == Some("POST")
                && surface.framework.as_deref() == Some("Bottle")
        }));
        assert_detector(&map, "python.file-upload");
    }

    #[test]
    fn attack_surface_preserves_sanic_route_methods() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("requirements.txt"), "sanic\n").unwrap();
        fs::write(
            temp.path().join("app.py"),
            "from sanic import Sanic\napp = Sanic('svc')\n@app.post('/imports/file')\nasync def upload(request):\n    return request.files.get('file').name\n@app.route('/webhooks/signed', methods=['POST'])\nasync def webhook(request): pass\n",
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();

        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/imports/file")
                && surface.method.as_deref() == Some("POST")
                && surface.framework.as_deref() == Some("Sanic")
        }));
        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/webhooks/signed")
                && surface.method.as_deref() == Some("POST")
                && surface.framework.as_deref() == Some("Sanic")
        }));
        assert_detector(&map, "python.file-upload");
    }

    #[test]
    fn attack_surface_preserves_pyramid_route_methods() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("requirements.txt"), "pyramid\n").unwrap();
        fs::write(
            temp.path().join("app.py"),
            "from pyramid.config import Configurator\nconfig = Configurator()\nconfig.add_route('import_file', '/imports/file', request_method='POST')\ndef upload(request):\n    return request.POST['file'].filename\n",
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();

        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/imports/file")
                && surface.method.as_deref() == Some("POST")
                && surface.framework.as_deref() == Some("Pyramid")
        }));
        assert_detector(&map, "python.file-upload");
    }

    #[test]
    fn attack_surface_preserves_falcon_route_methods() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("requirements.txt"), "falcon\n").unwrap();
        fs::write(
            temp.path().join("app.py"),
            "import falcon\nclass UploadResource:\n    def on_post(self, req, resp):\n        upload = req.get_param('file')\n        resp.text = upload.filename\napp = falcon.App()\napp.add_route('/imports/file', UploadResource())\n",
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();

        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/imports/file")
                && surface.method.as_deref() == Some("POST")
                && surface.framework.as_deref() == Some("Falcon")
        }));
        assert_detector(&map, "python.file-upload");
    }

    #[test]
    fn attack_surface_preserves_litestar_route_methods() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("requirements.txt"), "litestar\n").unwrap();
        fs::write(
            temp.path().join("app.py"),
            "from litestar import Litestar, UploadFile, post\n@post('/imports/file')\nasync def upload(file: UploadFile) -> str:\n    return file.filename\napp = Litestar(route_handlers=[upload])\n",
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();

        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/imports/file")
                && surface.method.as_deref() == Some("POST")
                && surface.framework.as_deref() == Some("Litestar")
        }));
        assert_detector(&map, "python.file-upload");
    }

    #[test]
    fn attack_surface_preserves_starlite_route_methods() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("requirements.txt"), "starlite\n").unwrap();
        fs::write(
            temp.path().join("app.py"),
            "from starlite import Starlite, UploadFile, post\n@post('/imports/file')\nasync def upload(file: UploadFile) -> str:\n    return file.filename\napp = Starlite(route_handlers=[upload])\n",
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();

        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/imports/file")
                && surface.method.as_deref() == Some("POST")
                && surface.framework.as_deref() == Some("Litestar")
        }));
        assert_detector(&map, "python.file-upload");
    }

    #[test]
    fn attack_surface_scores_header_controlled_webhooks_as_request_input() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src")).unwrap();
        fs::write(
            temp.path().join("package.json"),
            r#"{"dependencies":{"express":"^4.18.0"}}"#,
        )
        .unwrap();
        fs::write(
            temp.path().join("src/webhooks.ts"),
            r#"
              import express from 'express';
              const app = express();
              app.post('/webhooks/signed', (req, res) => verify(req.headers['x-signature']));
            "#,
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();

        assert_route_risk_reason(
            &map,
            "/webhooks/signed",
            "evidence references request-controlled data",
        );
    }

    #[test]
    fn attack_surface_detects_flask_header_trust_boundaries() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("requirements.txt"), "flask\n").unwrap();
        fs::write(
            temp.path().join("app.py"),
            r#"
              from flask import Flask, request
              app = Flask(__name__)
              @app.route('/webhooks/signed', methods=['POST'])
              def signed():
                  signature = request.headers.get('X-Signature')
                  session_id = request.cookies.get('sid')
                  return signature or session_id
            "#,
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();

        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.method.as_deref() == Some("POST")
                && surface.route.as_deref() == Some("/webhooks/signed")
                && surface.framework.as_deref() == Some("Flask")
        }));
        let trust_surfaces = map
            .surfaces
            .iter()
            .filter(|surface| {
                surface.path.ends_with("app.py")
                    && surface.kind == AttackSurfaceKind::RequestTrustBoundary
                    && surface
                        .metadata
                        .pointer("/detector")
                        .and_then(Value::as_str)
                        == Some("python.request-trust")
            })
            .collect::<Vec<_>>();
        assert_eq!(trust_surfaces.len(), 2, "{:#?}", map.surfaces);
        for surface in trust_surfaces {
            assert!(surface
                .risk
                .reasons
                .contains(&"evidence references request-controlled data".to_string()));
        }
    }

    #[test]
    fn attack_surface_detects_django_meta_header_trust_boundaries() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("requirements.txt"), "django\n").unwrap();
        fs::write(
            temp.path().join("urls.py"),
            "from django.urls import path\nurlpatterns = [path('webhooks/signed/', views.signed)]\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("views.py"),
            r#"
              def signed(request):
                  signature = request.META.get("HTTP_X_SIGNATURE")
                  return signature
            "#,
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();

        assert!(map.surfaces.iter().any(|surface| {
            surface.kind == AttackSurfaceKind::HttpRoute
                && surface.route.as_deref() == Some("/webhooks/signed/")
                && surface.framework.as_deref() == Some("Django")
        }));
        let surface = map
            .surfaces
            .iter()
            .find(|surface| {
                surface.kind == AttackSurfaceKind::RequestTrustBoundary
                    && surface.evidence.contains("request.META")
                    && surface
                        .metadata
                        .pointer("/detector")
                        .and_then(Value::as_str)
                        == Some("python.request-trust")
            })
            .unwrap_or_else(|| {
                panic!("missing Django request META surface in {:#?}", map.surfaces)
            });
        assert!(surface
            .risk
            .reasons
            .contains(&"evidence references request-controlled data".to_string()));
    }

    #[test]
    fn attack_surface_scores_python_body_parsers_as_request_input() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("svc")).unwrap();
        fs::write(
            temp.path().join("svc/views.py"),
            r#"
              import yaml
              def import_view(request):
                  payload = yaml.load(request.body)
                  filters = request.query_params.get("filter")
                  return payload, filters
            "#,
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();
        let surface = map
            .surfaces
            .iter()
            .find(|surface| surface.kind == AttackSurfaceKind::DeserializationPoint)
            .unwrap_or_else(|| panic!("missing Python parser surface in {:#?}", map.surfaces));

        assert!(surface
            .risk
            .reasons
            .contains(&"evidence references request-controlled data".to_string()));
    }

    #[test]
    fn attack_surface_scores_ruby_and_php_params_as_request_input() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("app/controllers")).unwrap();
        fs::write(
            temp.path().join("app/controllers/imports_controller.rb"),
            r#"
              class ImportsController
                def create
                  YAML.load(params[:payload])
                end
              end
            "#,
        )
        .unwrap();
        fs::write(
            temp.path().join("app/controllers/ImportController.php"),
            r#"
              <?php
              class ImportController {
                public function store(Request $request) {
                  json_decode($request->input('payload'));
                }
              }
            "#,
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();
        let parser_surfaces = map
            .surfaces
            .iter()
            .filter(|surface| surface.kind == AttackSurfaceKind::DeserializationPoint)
            .collect::<Vec<_>>();

        assert_eq!(parser_surfaces.len(), 2, "{:#?}", map.surfaces);
        for surface in parser_surfaces {
            assert!(
                surface
                    .risk
                    .reasons
                    .contains(&"evidence references request-controlled data".to_string()),
                "missing request-controlled risk reason: {surface:#?}"
            );
        }
    }

    #[test]
    fn attack_surface_scores_cookie_and_file_aliases_as_request_input() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("app/controllers")).unwrap();
        fs::write(
            temp.path().join("app/controllers/session_controller.rb"),
            r#"
              class SessionController
                def show
                  token = cookies.signed[:session_token]
                end
              end
            "#,
        )
        .unwrap();
        fs::write(
            temp.path().join("app/controllers/ImportController.php"),
            r#"
              <?php
              class ImportController {
                public function store() {
                  $upload = $_FILES['import'];
                }
              }
            "#,
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();
        for kind in [
            AttackSurfaceKind::SessionStateBoundary,
            AttackSurfaceKind::FileUploadParsePath,
        ] {
            assert_surface_request_controlled(&map, kind);
        }
    }

    #[test]
    fn attack_surface_scores_spring_request_body_as_request_input() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(
            temp.path().join("src/main/java/app/ImportController.java"),
            r#"
              class ImportController {
                void importPayload(@RequestBody String body, @RequestParam String tenant) { objectMapper.readValue(body, Payload.class); }
              }
            "#,
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();
        let surface = map
            .surfaces
            .iter()
            .find(|surface| surface.kind == AttackSurfaceKind::DeserializationPoint)
            .unwrap_or_else(|| panic!("missing Spring parser surface in {:#?}", map.surfaces));

        assert!(surface
            .risk
            .reasons
            .contains(&"evidence references request-controlled data".to_string()));
    }

    #[test]
    fn attack_surface_scores_go_and_rust_extractors_as_request_input() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("svc")).unwrap();
        fs::write(
            temp.path().join("svc/handler.go"),
            r#"
              package svc
              func handler(r *http.Request) {
                json.NewDecoder(r.Body).Decode(&payload)
              }
            "#,
        )
        .unwrap();
        fs::write(
            temp.path().join("svc/handler.rs"),
            r#"
              async fn handler(Json(payload): Json<Value>) { serde_json::from_value::<Payload>(payload); }
            "#,
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();
        let parser_surfaces = map
            .surfaces
            .iter()
            .filter(|surface| surface.kind == AttackSurfaceKind::DeserializationPoint)
            .collect::<Vec<_>>();

        assert_eq!(parser_surfaces.len(), 2, "{:#?}", map.surfaces);
        for surface in parser_surfaces {
            assert!(
                surface
                    .risk
                    .reasons
                    .contains(&"evidence references request-controlled data".to_string()),
                "missing request-controlled risk reason: {surface:#?}"
            );
        }
    }

    #[test]
    fn attack_surface_scores_aspnet_body_and_upload_as_request_input() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("Controllers")).unwrap();
        fs::write(
            temp.path().join("Controllers/ImportController.cs"),
            r#"
              using System.Text.Json;
              class ImportController {
                void Import(IFormFile file) {
                  JsonSerializer.Deserialize<Payload>(Request.Body);
                }
              }
            "#,
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();
        for kind in [
            AttackSurfaceKind::DeserializationPoint,
            AttackSurfaceKind::FileUploadParsePath,
        ] {
            assert_surface_request_controlled(&map, kind);
        }
    }

    #[test]
    fn attack_surface_detects_aspnet_request_decompression_as_parser_boundary() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Program.cs"),
            r#"
              builder.Services.AddRequestDecompression();
              builder.Services.Configure<RequestDecompressionOptions>(options => {});
              options.DecompressionProviders.Add("br", new RequestDecompressionProvider());
              app.UseRequestDecompression();
            "#,
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();
        let decompression_surfaces = map
            .surfaces
            .iter()
            .filter(|surface| {
                surface.kind == AttackSurfaceKind::DeserializationPoint
                    && surface
                        .metadata
                        .pointer("/detector")
                        .and_then(Value::as_str)
                        == Some("dotnet.deserialization")
            })
            .count();

        assert_eq!(decompression_surfaces, 4, "{:#?}", map.surfaces);
    }

    #[test]
    fn attack_surface_detects_dotnet_serializer_apis_as_parser_boundaries() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Web.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk.Web\"></Project>\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("Parsers.cs"),
            r#"
              class Parsers {
                void Parse() {
                  var binary = new BinaryFormatter().Deserialize(stream);
                  var soap = new SoapFormatter().Deserialize(stream);
                  var los = new LosFormatter().Deserialize(input);
                  var state = new ObjectStateFormatter().Deserialize(input);
                  var xml = new XmlSerializer(typeof(Payload)).Deserialize(reader);
                  var data = new DataContractSerializer(typeof(Payload)).ReadObject(stream);
                  var net = new NetDataContractSerializer().ReadObject(stream);
                  var msg = MessagePackSerializer.Deserialize<Payload>(bytes);
                  var proto = ProtoBuf.Serializer.Deserialize<Payload>(stream);
                  var yaml = new Deserializer().Deserialize<Payload>(text);
                }
              }
            "#,
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();
        let parser_surfaces = map
            .surfaces
            .iter()
            .filter(|surface| {
                surface.kind == AttackSurfaceKind::DeserializationPoint
                    && surface
                        .metadata
                        .pointer("/detector")
                        .and_then(Value::as_str)
                        == Some("dotnet.deserialization")
            })
            .collect::<Vec<_>>();

        assert_eq!(parser_surfaces.len(), 10, "{:#?}", map.surfaces);
        assert!(parser_surfaces
            .iter()
            .all(|surface| surface.framework.as_deref() == Some("ASP.NET Core")));
        assert!(parser_surfaces
            .iter()
            .all(|surface| surface.boundary.as_deref() == Some("parser_boundary")));
    }

    #[test]
    fn attack_surface_scores_aspnet_binding_attributes_as_request_input() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("Controllers")).unwrap();
        fs::write(
            temp.path().join("Controllers/SearchController.cs"),
            r#"
              using Microsoft.AspNetCore.Mvc;
              class SearchController {
                IActionResult Search([FromQuery] string q, [FromHeader(Name = "X-Team")] string team) {
                  return Ok(Request.Query["q"]);
                }
                IActionResult Import([FromBody] Payload payload, [FromForm] string mode) {
                  return Ok(Request.Form["mode"]);
                }
              }
            "#,
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();
        assert_surface_request_controlled(&map, AttackSurfaceKind::RequestTrustBoundary);
        assert_surface_request_controlled(&map, AttackSurfaceKind::DeserializationPoint);
        assert_detector(&map, "dotnet.request-trust");
        assert_detector(&map, "dotnet.deserialization");
    }

    #[test]
    fn attack_surface_detects_aspnet_antiforgery_as_request_trust() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("Controllers")).unwrap();
        fs::write(temp.path().join("Program.cs"), "app.UseAntiforgery();\n").unwrap();
        fs::write(
            temp.path().join("Controllers/CheckoutController.cs"),
            r#"
              using Microsoft.AspNetCore.Mvc;
              [AutoValidateAntiforgeryToken]
              class CheckoutController {
                [ValidateAntiForgeryToken]
                IActionResult Pay(IAntiforgery antiforgery) => Ok();
              }
            "#,
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();
        assert_has_kind(&map, AttackSurfaceKind::RequestTrustBoundary);
        assert_detector(&map, "dotnet.request-trust");
    }

    #[test]
    fn attack_surface_detects_aspnet_auth_middleware_and_services() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Program.cs"),
            r#"
              builder.Services.AddAuthentication("Bearer");
              builder.Services.AddAuthorization();
              app.UseAuthentication();
              app.UseAuthorization();
            "#,
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();
        let auth_surfaces = map
            .surfaces
            .iter()
            .filter(|surface| {
                surface.kind == AttackSurfaceKind::AuthBoundary
                    && surface
                        .metadata
                        .pointer("/detector")
                        .and_then(Value::as_str)
                        == Some("dotnet.auth-guard")
            })
            .collect::<Vec<_>>();

        assert_eq!(auth_surfaces.len(), 4, "{:#?}", map.surfaces);
        assert!(auth_surfaces
            .iter()
            .all(|surface| surface.framework.as_deref() == Some("ASP.NET Core")));
    }

    #[test]
    fn attack_surface_detects_aspnet_anonymous_and_filter_auth_metadata() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Program.cs"),
            r#"
              app.MapGet("/public/status", Status)
                 .AllowAnonymous();
              [AllowAnonymous]
              class PublicController {}
              class AdminFilter : IAuthorizationFilter {}
              class AdminAuthorizeAttribute : AuthorizeAttribute {}
            "#,
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();
        let auth_surfaces = map
            .surfaces
            .iter()
            .filter(|surface| {
                surface.kind == AttackSurfaceKind::AuthBoundary
                    && surface
                        .metadata
                        .pointer("/detector")
                        .and_then(Value::as_str)
                        == Some("dotnet.auth-guard")
            })
            .count();

        assert_eq!(auth_surfaces, 4, "{:#?}", map.surfaces);
    }

    #[test]
    fn attack_surface_detects_aspnet_endpoint_filters_as_request_trust() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Program.cs"),
            r#"
              app.MapPost("/admin/export", Export)
                 .AddEndpointFilter<AdminAuditFilter>();
              app.MapPost("/admin/import", Import)
                 .AddEndpointFilterFactory((context, next) => next);
              class AdminAuditFilter : IEndpointFilter {}
            "#,
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();
        let filter_surfaces = map
            .surfaces
            .iter()
            .filter(|surface| {
                surface.kind == AttackSurfaceKind::RequestTrustBoundary
                    && surface
                        .metadata
                        .pointer("/detector")
                        .and_then(Value::as_str)
                        == Some("dotnet.request-trust")
            })
            .count();

        assert_eq!(filter_surfaces, 3, "{:#?}", map.surfaces);
    }

    #[test]
    fn attack_surface_detects_aspnet_cors_and_host_metadata_as_request_trust() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Program.cs"),
            r#"
              app.MapPost("/admin/export", Export)
                 .RequireCors("AdminCors")
                 .RequireHost("admin.example.com");
              app.MapPost("/public/import", Import)
                 .DisableCors();
              [DisableCors]
              class PublicController {}
            "#,
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();
        let metadata_surfaces = map
            .surfaces
            .iter()
            .filter(|surface| {
                surface.kind == AttackSurfaceKind::RequestTrustBoundary
                    && surface
                        .metadata
                        .pointer("/detector")
                        .and_then(Value::as_str)
                        == Some("dotnet.request-trust")
            })
            .count();

        assert_eq!(metadata_surfaces, 4, "{:#?}", map.surfaces);
    }

    #[test]
    fn attack_surface_detects_aspnet_rate_limiting_as_request_trust() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Program.cs"),
            r#"
              builder.Services.AddRateLimiter(options => {});
              app.UseRateLimiter();
              app.MapPost("/login", Login)
                 .RequireRateLimiting("login");
              app.MapGet("/health", Health)
                 .DisableRateLimiting();
            "#,
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();
        let rate_limit_surfaces = map
            .surfaces
            .iter()
            .filter(|surface| {
                surface.kind == AttackSurfaceKind::RequestTrustBoundary
                    && surface
                        .metadata
                        .pointer("/detector")
                        .and_then(Value::as_str)
                        == Some("dotnet.request-trust")
            })
            .count();

        assert_eq!(rate_limit_surfaces, 4, "{:#?}", map.surfaces);
    }

    #[test]
    fn attack_surface_detects_aspnet_forwarded_headers_as_request_trust() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Program.cs"),
            r#"
              app.UseForwardedHeaders();
              builder.Services.Configure<ForwardedHeadersOptions>(options => {
                options.KnownProxies.Add(proxyAddress);
                options.KnownNetworks.Clear();
              });
            "#,
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();
        let forwarded_header_surfaces = map
            .surfaces
            .iter()
            .filter(|surface| {
                surface.kind == AttackSurfaceKind::RequestTrustBoundary
                    && surface
                        .metadata
                        .pointer("/detector")
                        .and_then(Value::as_str)
                        == Some("dotnet.request-trust")
            })
            .count();

        assert_eq!(forwarded_header_surfaces, 4, "{:#?}", map.surfaces);
    }

    #[test]
    fn attack_surface_scores_aspnet_cookies_as_request_input() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("Controllers")).unwrap();
        fs::write(
            temp.path().join("Controllers/SessionController.cs"),
            r#"
              class SessionController {
                string Show() {
                  var sid = Request.Cookies["sid"];
                  return sid;
                }
              }
            "#,
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();
        assert_surface_request_controlled(&map, AttackSurfaceKind::SessionStateBoundary);
        assert_detector(&map, "dotnet.session-state");
    }

    #[test]
    fn attack_surface_detects_aspnet_cookie_policy_as_session_state() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Program.cs"),
            r#"
              app.UseCookiePolicy();
              builder.Services.Configure<CookiePolicyOptions>(options => {
                options.MinimumSameSitePolicy = SameSiteMode.Strict;
                options.HttpOnly = CookieHttpOnlyPolicy.Always;
                options.Secure = CookieSecurePolicy.Always;
              });
            "#,
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();
        let cookie_policy_surfaces = map
            .surfaces
            .iter()
            .filter(|surface| {
                surface.kind == AttackSurfaceKind::SessionStateBoundary
                    && surface
                        .metadata
                        .pointer("/detector")
                        .and_then(Value::as_str)
                        == Some("dotnet.session-state")
            })
            .count();

        assert_eq!(cookie_policy_surfaces, 5, "{:#?}", map.surfaces);
    }

    #[test]
    fn attack_surface_detects_aspnet_session_middleware_as_session_state() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Program.cs"),
            r#"
              builder.Services.AddSession();
              builder.Services.Configure<SessionOptions>(options => {
                options.IdleTimeout = TimeSpan.FromMinutes(20);
              });
              app.UseSession();
            "#,
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();
        let session_middleware_surfaces = map
            .surfaces
            .iter()
            .filter(|surface| {
                surface.kind == AttackSurfaceKind::SessionStateBoundary
                    && surface
                        .metadata
                        .pointer("/detector")
                        .and_then(Value::as_str)
                        == Some("dotnet.session-state")
            })
            .count();

        assert_eq!(session_middleware_surfaces, 4, "{:#?}", map.surfaces);
    }

    #[test]
    fn attack_surface_scores_go_and_rust_cookie_access_as_request_input() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("svc")).unwrap();
        fs::write(
            temp.path().join("svc/session.go"),
            r#"
              package svc
              func handler(r *http.Request) {
                sessionCookie, _ := r.Cookie("session")
                _ = sessionCookie
              }
            "#,
        )
        .unwrap();
        fs::write(
            temp.path().join("svc/session.rs"),
            r#"
              async fn handler(cookies: CookieJar) {
                let sid = cookies.get("sid");
              }
            "#,
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();
        let session_surfaces = map
            .surfaces
            .iter()
            .filter(|surface| surface.kind == AttackSurfaceKind::SessionStateBoundary)
            .collect::<Vec<_>>();

        assert_eq!(session_surfaces.len(), 2, "{:#?}", map.surfaces);
        for surface in session_surfaces {
            assert!(
                surface
                    .risk
                    .reasons
                    .contains(&"evidence references request-controlled data".to_string()),
                "missing request-controlled risk reason: {surface:#?}"
            );
        }
    }

    #[test]
    fn attack_surface_scores_go_and_rust_header_access_as_request_input() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("svc")).unwrap();
        fs::write(
            temp.path().join("svc/webhook.go"),
            r#"
              package svc
              func handler(r *http.Request) {
                signature := r.Header.Get("X-Signature")
                verify(signature)
              }
            "#,
        )
        .unwrap();
        fs::write(
            temp.path().join("svc/webhook.rs"),
            r#"
              async fn handler(headers: HeaderMap) {
                let signature = headers.get("x-signature");
              }
            "#,
        )
        .unwrap();

        let map = build_attack_surface_map(temp.path()).unwrap();
        let trust_surfaces = map
            .surfaces
            .iter()
            .filter(|surface| surface.kind == AttackSurfaceKind::RequestTrustBoundary)
            .collect::<Vec<_>>();

        assert_eq!(trust_surfaces.len(), 2, "{:#?}", map.surfaces);
        for surface in trust_surfaces {
            assert!(
                surface
                    .risk
                    .reasons
                    .contains(&"evidence references request-controlled data".to_string()),
                "missing request-controlled risk reason: {surface:#?}"
            );
        }
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
        assert_eq!(
            first.surfaces.first().map(|surface| surface.risk.rank),
            Some(1)
        );
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

    #[test]
    fn attack_surface_language_from_path_matches_supported_inventory_languages() {
        for (path, language) in [
            ("src/App.java", "Java"),
            ("src/App.kt", "Kotlin"),
            ("Controllers/AdminController.cs", "C#"),
            ("app/controllers/users_controller.rb", "Ruby"),
            ("app/Http/Controllers/UserController.php", "PHP"),
        ] {
            assert_eq!(language_from_path(path), Some(language));
        }
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

    fn assert_detector(map: &AttackSurfaceMap, detector: &str) {
        assert!(
            map.surfaces.iter().any(|surface| {
                surface
                    .metadata
                    .pointer("/detector")
                    .and_then(Value::as_str)
                    == Some(detector)
            }),
            "missing detector {detector:?} in {:#?}",
            map.surfaces
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

    fn assert_no_surface_route(map: &AttackSurfaceMap, kind: AttackSurfaceKind, route: &str) {
        assert!(
            map.surfaces
                .iter()
                .all(|surface| surface.kind != kind || surface.route.as_deref() != Some(route)),
            "unexpected {kind:?} for {route} in {:#?}",
            map.surfaces
        );
    }

    fn assert_surface_request_controlled(map: &AttackSurfaceMap, kind: AttackSurfaceKind) {
        let surface = map
            .surfaces
            .iter()
            .find(|surface| surface.kind == kind)
            .unwrap_or_else(|| panic!("missing {kind:?} in {:#?}", map.surfaces));
        assert!(
            surface
                .risk
                .reasons
                .contains(&"evidence references request-controlled data".to_string()),
            "missing request-controlled risk reason: {surface:#?}"
        );
    }

    fn assert_route_risk_reason(map: &AttackSurfaceMap, route: &str, reason: &str) {
        let surface = map
            .surfaces
            .iter()
            .find(|surface| {
                surface.kind == AttackSurfaceKind::HttpRoute
                    && surface.route.as_deref() == Some(route)
            })
            .unwrap_or_else(|| panic!("missing route {route} in {:#?}", map.surfaces));
        assert!(
            surface.risk.reasons.iter().any(|entry| entry == reason),
            "route {route} missing risk reason {reason:?}: {:#?}",
            surface.risk
        );
    }
}
