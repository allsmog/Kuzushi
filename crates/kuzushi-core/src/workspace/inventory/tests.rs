#[cfg(test)]
mod tests {
    use std::fs;

    use super::super::*;

    #[test]
    fn repository_inventory_detects_node_express_routes_and_manifests() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/controllers")).unwrap();
        fs::create_dir_all(temp.path().join("node_modules/express")).unwrap();
        fs::write(
            temp.path().join("package.json"),
            r#"{"scripts":{"start":"node src/server.js"},"dependencies":{"express":"^4.18.0"}}"#,
        )
        .unwrap();
        fs::write(temp.path().join("package-lock.json"), "{}\n").unwrap();
        fs::write(temp.path().join("tsconfig.json"), "{}\n").unwrap();
        fs::write(
            temp.path().join("src/server.ts"),
            "import express from 'express';\nconst app = express();\napp.get('/users', handler);\nheaders.get('x-signature');\napp.listen(3000);\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("src/controllers/userController.ts"),
            "export function handler() {}\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("node_modules/express/index.js"),
            "module.exports = {}\n",
        )
        .unwrap();

        let inventory = build_repository_inventory(temp.path()).unwrap();

        assert_language(&inventory, "TypeScript", 2);
        assert_has_file(&inventory.manifests, "package.json", "node-package");
        assert_has_file(
            &inventory.dependency_manifests,
            "package-lock.json",
            "npm-lockfile",
        );
        assert_has_file(
            &inventory.config_files,
            "tsconfig.json",
            "typescript-config",
        );
        assert_framework(&inventory, "Express", "JavaScript");
        assert!(inventory.entrypoints.iter().any(|entrypoint| {
            entrypoint.kind == "node-start-script" && entrypoint.path == "package.json"
        }));
        assert!(inventory.entrypoints.iter().any(|entrypoint| {
            entrypoint.kind == "node-server" && entrypoint.path == "src/server.ts"
        }));
        assert!(inventory.routes_controllers.iter().any(|item| {
            item.kind == "route"
                && item.method.as_deref() == Some("GET")
                && item.route.as_deref() == Some("/users")
        }));
        assert!(inventory
            .routes_controllers
            .iter()
            .all(|item| item.route.as_deref() != Some("x-signature")));
        assert!(inventory.routes_controllers.iter().any(|item| {
            item.kind == "controller" && item.path == "src/controllers/userController.ts"
        }));
        assert!(inventory
            .generated_vendor_paths
            .iter()
            .any(|item| item.path == "node_modules" && item.kind == "vendor"));
        assert!(!inventory
            .source_files
            .iter()
            .any(|file| file.path.starts_with("node_modules/")));
    }

    #[test]
    fn repository_inventory_detects_python_frameworks_and_routes() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("requirements.txt"), "django\nfastapi\nflask\n").unwrap();
        fs::write(
            temp.path().join("app.py"),
            "from fastapi import FastAPI\napp = FastAPI()\n@app.post('/items')\ndef create_item(): pass\nif __name__ == '__main__':\n    pass\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("urls.py"),
            "from django.urls import path, re_path\nurlpatterns = [path('billing/api-keys/', views.keys)]\nre_path(r'^oauth/callback/$', views.callback)\n",
        )
        .unwrap();

        let inventory = build_repository_inventory(temp.path()).unwrap();

        assert_language(&inventory, "Python", 2);
        assert_has_file(
            &inventory.manifests,
            "requirements.txt",
            "python-requirements",
        );
        assert_framework(&inventory, "Django", "Python");
        assert_framework(&inventory, "FastAPI", "Python");
        assert_framework(&inventory, "Flask", "Python");
        assert!(inventory
            .entrypoints
            .iter()
            .any(|entrypoint| entrypoint.kind == "python-app" && entrypoint.path == "app.py"));
        assert!(inventory.routes_controllers.iter().any(|item| {
            item.kind == "route"
                && item.method.as_deref() == Some("POST")
                && item.route.as_deref() == Some("/items")
        }));
        assert!(inventory.routes_controllers.iter().any(|item| {
            item.kind == "route"
                && item.method.as_deref() == Some("ANY")
                && item.route.as_deref() == Some("/billing/api-keys/")
                && item.framework.as_deref() == Some("Django")
        }));
        assert!(inventory.routes_controllers.iter().any(|item| {
            item.kind == "route"
                && item.method.as_deref() == Some("ANY")
                && item.route.as_deref() == Some("/^oauth/callback/$")
                && item.framework.as_deref() == Some("Django")
        }));
    }

    #[test]
    fn python_route_methods_extracts_declared_method_lists() {
        assert_eq!(
            python_route_methods("@app.route('/items', methods=['GET', 'POST'])").as_deref(),
            Some("GET,POST")
        );
        assert_eq!(
            python_route_methods("@bp.route('/item', methods=['delete', 'PATCH'])").as_deref(),
            Some("PATCH,DELETE")
        );
        assert_eq!(
            python_route_methods("@app.api_route('/saml/callback', methods=['OPTIONS', 'HEAD'])")
                .as_deref(),
            Some("OPTIONS,HEAD")
        );
        assert_eq!(python_route_methods("@app.get('/items')"), None);
        assert_eq!(
            python_route_methods("@app.route('/items', methods=[])"),
            None
        );
    }

    #[test]
    fn repository_inventory_detects_django_as_view_methods() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("requirements.txt"), "django\ndjangorestframework\n").unwrap();
        fs::write(
            temp.path().join("urls.py"),
            "from django.urls import path\nurlpatterns = [path('imports/file/', ImportView.as_view({'post': 'create'}))]\n",
        )
        .unwrap();

        let inventory = build_repository_inventory(temp.path()).unwrap();

        assert_framework(&inventory, "Django", "Python");
        assert_route(&inventory, "POST", "/imports/file/", "Django");
    }

    #[test]
    fn repository_inventory_detects_fastapi_api_route_methods() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("requirements.txt"), "fastapi\n").unwrap();
        fs::write(
            temp.path().join("main.py"),
            "from fastapi import FastAPI\napp = FastAPI()\n@app.api_route('/imports/file', methods=['POST'])\ndef ingest(): pass\n@app.api_route('/saml/callback', methods=['OPTIONS', 'HEAD'])\ndef preflight(): pass\n",
        )
        .unwrap();

        let inventory = build_repository_inventory(temp.path()).unwrap();

        assert_framework(&inventory, "FastAPI", "Python");
        assert_route(&inventory, "POST", "/imports/file", "FastAPI");
        assert_route(&inventory, "OPTIONS,HEAD", "/saml/callback", "FastAPI");
    }

    #[test]
    fn repository_inventory_detects_flask_add_url_rule_methods() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("requirements.txt"), "flask\n").unwrap();
        fs::write(
            temp.path().join("app.py"),
            "from flask import Flask\napp = Flask(__name__)\napp.add_url_rule('/imports/file', view_func=upload, methods=['POST'])\n",
        )
        .unwrap();

        let inventory = build_repository_inventory(temp.path()).unwrap();

        assert_framework(&inventory, "Flask", "Python");
        assert_route(&inventory, "POST", "/imports/file", "Flask");
    }

    #[test]
    fn repository_inventory_detects_starlette_route_methods() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("requirements.txt"), "starlette\n").unwrap();
        fs::write(
            temp.path().join("app.py"),
            "from starlette.applications import Starlette\nfrom starlette.routing import Route\nroutes = [Route('/imports/file', upload, methods=['POST'])]\napp = Starlette(routes=routes)\n",
        )
        .unwrap();

        let inventory = build_repository_inventory(temp.path()).unwrap();

        assert_framework(&inventory, "Starlette", "Python");
        assert_route(&inventory, "POST", "/imports/file", "Starlette");
    }

    #[test]
    fn repository_inventory_detects_aiohttp_route_methods() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("requirements.txt"), "aiohttp\n").unwrap();
        fs::write(
            temp.path().join("app.py"),
            "from aiohttp import web\napp = web.Application()\napp.router.add_post('/imports/file', upload)\napp.router.add_route('OPTIONS', '/saml/callback', callback)\napp.add_routes([web.post('/webhooks/signed', webhook)])\n",
        )
        .unwrap();

        let inventory = build_repository_inventory(temp.path()).unwrap();

        assert_framework(&inventory, "aiohttp", "Python");
        assert_route(&inventory, "POST", "/imports/file", "aiohttp");
        assert_route(&inventory, "OPTIONS", "/saml/callback", "aiohttp");
        assert_route(&inventory, "POST", "/webhooks/signed", "aiohttp");
    }

    #[test]
    fn repository_inventory_detects_tornado_route_methods() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("requirements.txt"), "tornado\n").unwrap();
        fs::write(
            temp.path().join("app.py"),
            "import tornado.web\nclass UploadHandler(tornado.web.RequestHandler):\n    def post(self): pass\napp = tornado.web.Application([\n    (r\"/imports/file\", UploadHandler),\n])\n",
        )
        .unwrap();

        let inventory = build_repository_inventory(temp.path()).unwrap();

        assert_framework(&inventory, "Tornado", "Python");
        assert_route(&inventory, "POST", "/imports/file", "Tornado");
    }

    #[test]
    fn repository_inventory_detects_bottle_route_methods() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("requirements.txt"), "bottle\n").unwrap();
        fs::write(
            temp.path().join("app.py"),
            "from bottle import post, route\n@post('/imports/file')\ndef upload(): pass\n@route('/webhooks/signed', method='POST')\ndef webhook(): pass\n",
        )
        .unwrap();

        let inventory = build_repository_inventory(temp.path()).unwrap();

        assert_framework(&inventory, "Bottle", "Python");
        assert_route(&inventory, "POST", "/imports/file", "Bottle");
        assert_route(&inventory, "POST", "/webhooks/signed", "Bottle");
    }

    #[test]
    fn repository_inventory_detects_sanic_route_methods() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("requirements.txt"), "sanic\n").unwrap();
        fs::write(
            temp.path().join("app.py"),
            "from sanic import Sanic\napp = Sanic('svc')\n@app.post('/imports/file')\nasync def upload(request): pass\n@app.route('/webhooks/signed', methods=['POST'])\nasync def webhook(request): pass\n",
        )
        .unwrap();

        let inventory = build_repository_inventory(temp.path()).unwrap();

        assert_framework(&inventory, "Sanic", "Python");
        assert_route(&inventory, "POST", "/imports/file", "Sanic");
        assert_route(&inventory, "POST", "/webhooks/signed", "Sanic");
    }

    #[test]
    fn repository_inventory_detects_pyramid_route_methods() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("requirements.txt"), "pyramid\n").unwrap();
        fs::write(
            temp.path().join("app.py"),
            "from pyramid.config import Configurator\nconfig = Configurator()\nconfig.add_route('import_file', '/imports/file', request_method='POST')\n",
        )
        .unwrap();

        let inventory = build_repository_inventory(temp.path()).unwrap();

        assert_framework(&inventory, "Pyramid", "Python");
        assert_route(&inventory, "POST", "/imports/file", "Pyramid");
    }

    #[test]
    fn repository_inventory_detects_falcon_route_methods() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("requirements.txt"), "falcon\n").unwrap();
        fs::write(
            temp.path().join("app.py"),
            "import falcon\nclass UploadResource:\n    def on_post(self, req, resp): pass\napp = falcon.App()\napp.add_route('/imports/file', UploadResource())\n",
        )
        .unwrap();

        let inventory = build_repository_inventory(temp.path()).unwrap();

        assert_framework(&inventory, "Falcon", "Python");
        assert_route(&inventory, "POST", "/imports/file", "Falcon");
    }

    #[test]
    fn repository_inventory_detects_litestar_route_methods() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("requirements.txt"), "litestar\n").unwrap();
        fs::write(
            temp.path().join("app.py"),
            "from litestar import Litestar, post\n@post('/imports/file')\nasync def upload() -> None: pass\napp = Litestar(route_handlers=[upload])\n",
        )
        .unwrap();

        let inventory = build_repository_inventory(temp.path()).unwrap();

        assert_framework(&inventory, "Litestar", "Python");
        assert_route(&inventory, "POST", "/imports/file", "Litestar");
    }

    #[test]
    fn repository_inventory_detects_starlite_route_methods() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("requirements.txt"), "starlite\n").unwrap();
        fs::write(
            temp.path().join("app.py"),
            "from starlite import Starlite, post\n@post('/imports/file')\nasync def upload() -> None: pass\napp = Starlite(route_handlers=[upload])\n",
        )
        .unwrap();

        let inventory = build_repository_inventory(temp.path()).unwrap();

        assert_framework(&inventory, "Litestar", "Python");
        assert_route(&inventory, "POST", "/imports/file", "Litestar");
    }

    #[test]
    fn repository_inventory_detects_go_entrypoints_routes_and_vendor_paths() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("vendor/example")).unwrap();
        fs::write(
            temp.path().join("go.mod"),
            "module demo\nrequire github.com/gin-gonic/gin v1.9.0\n",
        )
        .unwrap();
        fs::write(temp.path().join("go.sum"), "example h1:abc\n").unwrap();
        fs::write(
            temp.path().join("main.go"),
            "package main\nimport \"net/http\"\nfunc main() { http.HandleFunc(\"/health\", health); r.GET(\"/users\", users); signature := req.Header.Get(\"X-Signature\"); _ = signature }\n",
        )
        .unwrap();

        let inventory = build_repository_inventory(temp.path()).unwrap();

        assert_language(&inventory, "Go", 1);
        assert_has_file(&inventory.manifests, "go.mod", "go-module");
        assert_has_file(&inventory.dependency_manifests, "go.sum", "go-checksums");
        assert_framework(&inventory, "Gin", "Go");
        assert_framework(&inventory, "net/http", "Go");
        assert!(inventory
            .entrypoints
            .iter()
            .any(|entrypoint| entrypoint.kind == "go-main" && entrypoint.path == "main.go"));
        assert!(inventory.routes_controllers.iter().any(|item| {
            item.route.as_deref() == Some("/health")
                && item.framework.as_deref() == Some("net/http")
        }));
        assert!(inventory
            .routes_controllers
            .iter()
            .any(|item| item.route.as_deref() == Some("/users")));
        assert!(inventory
            .routes_controllers
            .iter()
            .all(|item| item.route.as_deref() != Some("X-Signature")));
        assert!(inventory
            .generated_vendor_paths
            .iter()
            .any(|item| item.path == "vendor" && item.kind == "vendor"));
    }

    #[test]
    fn repository_inventory_labels_go_method_routes_by_framework() {
        for (framework, requirement, source) in [
            (
                "Fiber",
                "github.com/gofiber/fiber/v2 v2.52.0",
                "package main\nimport \"github.com/gofiber/fiber/v2\"\nfunc main() { app := fiber.New(); app.Post(\"/teams/projects\", createProject) }\n",
            ),
            (
                "Echo",
                "github.com/labstack/echo/v4 v4.12.0",
                "package main\nimport \"github.com/labstack/echo/v4\"\nfunc main() { e := echo.New(); e.POST(\"/teams/projects\", createProject) }\n",
            ),
            (
                "Chi",
                "github.com/go-chi/chi/v5 v5.0.12",
                "package main\nimport \"github.com/go-chi/chi/v5\"\nfunc main() { r := chi.NewRouter(); r.Post(\"/teams/projects\", createProject) }\n",
            ),
        ] {
            let temp = tempfile::tempdir().unwrap();
            fs::write(
                temp.path().join("go.mod"),
                format!("module demo\nrequire {requirement}\n"),
            )
            .unwrap();
            fs::write(temp.path().join("main.go"), source).unwrap();

            let inventory = build_repository_inventory(temp.path()).unwrap();

            assert_framework(&inventory, framework, "Go");
            assert_route(&inventory, "POST", "/teams/projects", framework);
        }
    }

    #[test]
    fn repository_inventory_detects_rust_entrypoints_and_config() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src")).unwrap();
        fs::create_dir_all(temp.path().join("target/debug")).unwrap();
        fs::write(
            temp.path().join("Cargo.toml"),
            "[package]\nname = \"demo\"\n[dependencies]\naxum = \"0.7\"\n",
        )
        .unwrap();
        fs::write(temp.path().join("Cargo.lock"), "# lock\n").unwrap();
        fs::write(
            temp.path().join("src/main.rs"),
            "use axum::{routing::get, Router};\n#[tokio::main]\nasync fn main() { let app = Router::new().route(\"/ready\", get(ready)); let label = builder.route(\"not-a-path\"); }\n",
        )
        .unwrap();
        fs::write(temp.path().join("Dockerfile"), "FROM scratch\n").unwrap();

        let inventory = build_repository_inventory(temp.path()).unwrap();

        assert_language(&inventory, "Rust", 1);
        assert_has_file(&inventory.manifests, "Cargo.toml", "rust-cargo");
        assert_has_file(
            &inventory.dependency_manifests,
            "Cargo.lock",
            "rust-cargo-lockfile",
        );
        assert_has_file(&inventory.config_files, "Dockerfile", "dockerfile");
        assert_framework(&inventory, "Axum", "Rust");
        assert!(
            inventory
                .entrypoints
                .iter()
                .any(|entrypoint| entrypoint.kind == "rust-binary"
                    && entrypoint.path == "src/main.rs")
        );
        assert!(inventory.routes_controllers.iter().any(|item| {
            item.route.as_deref() == Some("/ready") && item.framework.as_deref() == Some("Axum")
        }));
        assert!(inventory
            .routes_controllers
            .iter()
            .all(|item| item.route.as_deref() != Some("not-a-path")));
        assert!(inventory
            .generated_vendor_paths
            .iter()
            .any(|item| item.path == "target" && item.kind == "generated"));
    }

    #[test]
    fn repository_inventory_detects_actix_routes() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src")).unwrap();
        fs::write(
            temp.path().join("Cargo.toml"),
            "[package]\nname = \"demo\"\n[dependencies]\nactix-web = \"4\"\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("src/main.rs"),
            "use actix_web::{post, HttpResponse};\n#[post(\"/teams/projects\")]\nasync fn create_project() -> HttpResponse { HttpResponse::Ok().finish() }\n",
        )
        .unwrap();

        let inventory = build_repository_inventory(temp.path()).unwrap();

        assert_framework(&inventory, "Actix Web", "Rust");
        assert_route(&inventory, "POST", "/teams/projects", "Actix Web");
    }

    #[test]
    fn repository_inventory_detects_rocket_routes() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src")).unwrap();
        fs::write(
            temp.path().join("Cargo.toml"),
            "[package]\nname = \"demo\"\n[dependencies]\nrocket = \"0.5\"\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("src/main.rs"),
            "use rocket::{post, routes};\n#[post(\"/teams/projects\")]\nfn create_project() -> &'static str { \"ok\" }\n",
        )
        .unwrap();

        let inventory = build_repository_inventory(temp.path()).unwrap();

        assert_framework(&inventory, "Rocket", "Rust");
        assert_route(&inventory, "POST", "/teams/projects", "Rocket");
    }

    #[test]
    fn repository_inventory_detects_warp_routes() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src")).unwrap();
        fs::write(
            temp.path().join("Cargo.toml"),
            "[package]\nname = \"demo\"\n[dependencies]\nwarp = \"0.3\"\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("src/main.rs"),
            "fn routes() { let create = warp::path!(\"teams\" / \"projects\").and(warp::post()).and_then(create_project); }\n",
        )
        .unwrap();

        let inventory = build_repository_inventory(temp.path()).unwrap();

        assert_framework(&inventory, "Warp", "Rust");
        assert_route(&inventory, "POST", "/teams/projects", "Warp");
    }

    #[test]
    fn repository_inventory_detects_backend_frameworks_for_jvm_ruby_and_php() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::create_dir_all(temp.path().join("app/controllers")).unwrap();
        fs::create_dir_all(temp.path().join("app/Http/Controllers")).unwrap();
        fs::create_dir_all(temp.path().join("config")).unwrap();
        fs::write(
            temp.path().join("build.gradle"),
            "dependencies { implementation 'org.springframework.boot:spring-boot-starter-web' }\n",
        )
        .unwrap();
        fs::write(temp.path().join("Gemfile"), "gem 'rails'\n").unwrap();
        fs::write(
            temp.path().join("composer.json"),
            r#"{"require":{"laravel/framework":"^10"}}"#,
        )
        .unwrap();
        fs::write(
            temp.path().join("src/main/java/app/UserController.java"),
            "import org.springframework.web.bind.annotation.GetMapping;\n@GetMapping(\"/users\")\n@PostMapping\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("app/controllers/users_controller.rb"),
            "class UsersController < ApplicationController\nbefore_action :authenticate_user!\nend\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("config/routes.rb"),
            "Rails.application.routes.draw do\npost '/admin/invite', to: 'admin#invite'\npost 'admin#invite', to: 'admin#invite'\nend\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("app/Http/Controllers/UserController.php"),
            "<?php\nuse Illuminate\\Support\\Facades\\Route;\nRoute::get('/users', $handler);\nRoute::get('users.index', $handler);\n",
        )
        .unwrap();

        let inventory = build_repository_inventory(temp.path()).unwrap();

        assert_language(&inventory, "Java", 1);
        assert_language(&inventory, "PHP", 1);
        assert_language(&inventory, "Ruby", 2);
        assert_framework(&inventory, "Spring", "Java");
        assert_framework(&inventory, "Rails", "Ruby");
        assert_framework(&inventory, "Laravel", "PHP");
        assert_route(&inventory, "GET", "/users", "Spring");
        assert_route(&inventory, "POST", "/admin/invite", "Rails");
        assert_route(&inventory, "GET", "/users", "Laravel");
        assert_no_route(&inventory, "unknown");
        assert_no_route(&inventory, "admin#invite");
        assert_no_route(&inventory, "users.index");
    }

    #[test]
    fn repository_inventory_detects_rails_match_via_methods() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("config")).unwrap();
        fs::write(temp.path().join("Gemfile"), "gem 'rails'\n").unwrap();
        fs::write(
            temp.path().join("config/routes.rb"),
            "Rails.application.routes.draw do\nmatch '/imports/file', to: 'imports#create', via: :post\nend\n",
        )
        .unwrap();

        let inventory = build_repository_inventory(temp.path()).unwrap();

        assert_framework(&inventory, "Rails", "Ruby");
        assert_route(&inventory, "POST", "/imports/file", "Rails");
    }

    #[test]
    fn repository_inventory_detects_laravel_match_methods() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("routes")).unwrap();
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

        let inventory = build_repository_inventory(temp.path()).unwrap();

        assert_framework(&inventory, "Laravel", "PHP");
        assert_route(&inventory, "POST", "/imports/file", "Laravel");
    }

    #[test]
    fn repository_inventory_detects_spring_request_mapping_methods() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/java/app")).unwrap();
        fs::write(temp.path().join("build.gradle"), "plugins { id 'java' }\n").unwrap();
        fs::write(
            temp.path().join("src/main/java/app/ImportController.java"),
            "import org.springframework.web.bind.annotation.RequestMapping;\nclass ImportController {\n@RequestMapping(value = \"/imports/file\", method = RequestMethod.POST)\nvoid importFile() {}\n}\n",
        )
        .unwrap();

        let inventory = build_repository_inventory(temp.path()).unwrap();

        assert_framework(&inventory, "Spring", "Java");
        assert_route(&inventory, "POST", "/imports/file", "Spring");
    }

    #[test]
    fn repository_inventory_detects_kotlin_spring_request_mapping_methods() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/main/kotlin/app")).unwrap();
        fs::write(temp.path().join("build.gradle.kts"), "plugins { kotlin(\"jvm\") }\n").unwrap();
        fs::write(
            temp.path().join("src/main/kotlin/app/ImportController.kt"),
            "import org.springframework.web.bind.annotation.RequestMapping\nclass ImportController {\n@RequestMapping(value = [\"/imports/file\"], method = [RequestMethod.POST])\nfun importFile() {}\n}\n",
        )
        .unwrap();

        let inventory = build_repository_inventory(temp.path()).unwrap();

        assert_framework(&inventory, "Spring", "Kotlin");
        assert_route(&inventory, "POST", "/imports/file", "Spring");
    }

    #[test]
    fn repository_inventory_detects_aspnet_core_routes() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("Controllers")).unwrap();
        fs::write(
            temp.path().join("Web.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk.Web\"></Project>\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("Program.cs"),
            "var builder = WebApplication.CreateBuilder(args);\nvar app = builder.Build();\napp.MapPost(\"/imports/file\", Upload);\napp.MapHead(\"/health\", Health);\napp.MapHealthChecks(\"/health/live\");\napp.MapOpenApi();\napp.MapOpenApi(\"/internal/openapi/{documentName}.json\");\napp.MapSwagger();\napp.UseSwagger(\"docs/{documentName}/swagger.json\");\napp.MapGraphQL();\napp.UseGraphQL(\"/query\");\napp.MapOptions(\"/saml/callback\", CallbackOptions);\napp.MapFallback(\"/{*path:nonfile}\", SpaFallback);\napp.MapFallbackToFile(\"index.html\");\napp.MapFallbackToPage(\"/_Host\");\napp.MapMethods(\"/imports/batch\", new[] { \"POST\" }, BatchUpload);\napp.MapHub<AdminHub>(\"/hubs/admin\");\napp.MapBlazorHub();\napp.MapBlazorHub(\"/live/blazor\");\napp.MapRazorPages();\napp.MapControllerRoute(name: \"default\", pattern: \"mvc/{controller}/{action}\");\napp.MapAreaControllerRoute(name: \"admin-area\", areaName: \"Admin\", pattern: \"admin/{controller}/{action}\");\napp.MapDefaultControllerRoute();\napp.MapGroup(\"/api/direct\").MapPost(\"invite\", Invite);\napp.MapGroup(\"/api/direct\").MapMethods(\"audit\", new[] { \"POST\" }, Audit);\nvar admin = app.MapGroup(\"/api/admin\");\nadmin.MapPost(\"bulk-invite\", BulkInvite);\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("Controllers/AdminController.cs"),
            "using Microsoft.AspNetCore.Mvc;\n[Route(\"api/admin\")]\nclass AdminController {\n[HttpPost(\"invite\")]\npublic IActionResult Invite() => Ok();\n[Route(\"export\")]\n[HttpPost]\npublic IActionResult Export() => Ok();\n[HttpHead(\"status\")]\npublic IActionResult Status() => Ok();\n[HttpOptions]\npublic IActionResult Options() => Ok();\n[HttpGet]\npublic IActionResult Index() => Ok();\n}\n",
        )
        .unwrap();

        let inventory = build_repository_inventory(temp.path()).unwrap();

        assert_language(&inventory, "C#", 2);
        assert_framework(&inventory, "ASP.NET Core", "C#");
        assert_route(&inventory, "POST", "/imports/file", "ASP.NET Core");
        assert_route(&inventory, "HEAD", "/health", "ASP.NET Core");
        assert_route(&inventory, "GET", "/health/live", "ASP.NET Core");
        assert_route(
            &inventory,
            "GET",
            "/openapi/{documentName}.json",
            "ASP.NET Core",
        );
        assert_route(
            &inventory,
            "GET",
            "/internal/openapi/{documentName}.json",
            "ASP.NET Core",
        );
        assert_route(
            &inventory,
            "GET",
            "/swagger/{documentName}/swagger.json",
            "ASP.NET Core",
        );
        assert_route(
            &inventory,
            "GET",
            "/docs/{documentName}/swagger.json",
            "ASP.NET Core",
        );
        assert_route(&inventory, "ANY", "/graphql", "ASP.NET Core");
        assert_route(&inventory, "ANY", "/query", "ASP.NET Core");
        assert_route(&inventory, "OPTIONS", "/saml/callback", "ASP.NET Core");
        assert_route(&inventory, "ANY", "/{*path:nonfile}", "ASP.NET Core");
        assert_route(&inventory, "ANY", "*", "ASP.NET Core");
        assert_route(&inventory, "POST", "/imports/batch", "ASP.NET Core");
        assert_route(&inventory, "ANY", "/hubs/admin", "ASP.NET Core");
        assert_route(&inventory, "ANY", "/_blazor", "ASP.NET Core");
        assert_route(&inventory, "ANY", "/live/blazor", "ASP.NET Core");
        assert_route(&inventory, "ANY", "/{page}", "ASP.NET Core");
        assert_route(
            &inventory,
            "ANY",
            "/mvc/{controller}/{action}",
            "ASP.NET Core",
        );
        assert_route(
            &inventory,
            "ANY",
            "/admin/{controller}/{action}",
            "ASP.NET Core",
        );
        assert_route(
            &inventory,
            "ANY",
            "/{controller=Home}/{action=Index}/{id?}",
            "ASP.NET Core",
        );
        assert_route(&inventory, "POST", "/api/direct/invite", "ASP.NET Core");
        assert_route(&inventory, "POST", "/api/direct/audit", "ASP.NET Core");
        assert_route(&inventory, "POST", "/api/admin/bulk-invite", "ASP.NET Core");
        assert_route(&inventory, "POST", "/api/admin/invite", "ASP.NET Core");
        assert_route(&inventory, "POST", "/api/admin/export", "ASP.NET Core");
        assert_route(&inventory, "HEAD", "/api/admin/status", "ASP.NET Core");
        assert_route(&inventory, "OPTIONS", "/api/admin", "ASP.NET Core");
        assert_route(&inventory, "GET", "/api/admin", "ASP.NET Core");
    }

    #[test]
    fn repository_inventory_detects_aspnet_identity_api_routes() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Web.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk.Web\"></Project>\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("Program.cs"),
            "var app = WebApplication.CreateBuilder(args).Build();\nvar account = app.MapGroup(\"/account\");\naccount.MapIdentityApi<AppUser>();\napp.MapIdentityApi<AppUser>();\n",
        )
        .unwrap();

        let inventory = build_repository_inventory(temp.path()).unwrap();

        assert_route(&inventory, "ANY", "/account", "ASP.NET Core");
        assert_route(&inventory, "ANY", "/identity", "ASP.NET Core");
    }

    #[test]
    fn repository_inventory_ignores_aspnet_chained_grouped_route_metadata() {
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

        let inventory = build_repository_inventory(temp.path()).unwrap();

        assert_route(&inventory, "GET", "/api/settings", "ASP.NET Core");
        assert_route(&inventory, "POST", "/api/v1/users", "ASP.NET Core");
        assert_no_route(&inventory, "/api/admin");
        assert_no_route(&inventory, "/api/v1/ignored-name");
    }

    #[test]
    fn repository_inventory_preserves_aspnet_nested_assigned_route_groups() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Web.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk.Web\"></Project>\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("Program.cs"),
            "var app = WebApplication.CreateBuilder(args).Build();\nvar api = app.MapGroup(\"/api\");\nvar admin = api.MapGroup(\"admin\");\nadmin.MapGet(\"settings\", Settings);\nvar assigned = app.MapGroup(\"/tenant\").MapGroup(\"admin\");\nassigned.MapPost(\"users\", Users);\n",
        )
        .unwrap();

        let inventory = build_repository_inventory(temp.path()).unwrap();

        assert_route(&inventory, "GET", "/api/admin/settings", "ASP.NET Core");
        assert_route(
            &inventory,
            "POST",
            "/tenant/admin/users",
            "ASP.NET Core",
        );
        assert_no_route(&inventory, "/admin/settings");
        assert_no_route(&inventory, "/tenant/users");
    }

    #[test]
    fn repository_inventory_detects_aspnet_metrics_routes() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Web.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk.Web\"></Project>\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("Program.cs"),
            "var app = WebApplication.CreateBuilder(args).Build();\napp.MapMetrics();\napp.MapPrometheusScrapingEndpoint(\"/internal/metrics\");\n",
        )
        .unwrap();

        let inventory = build_repository_inventory(temp.path()).unwrap();

        assert_route(&inventory, "GET", "/metrics", "ASP.NET Core");
        assert_route(&inventory, "GET", "/internal/metrics", "ASP.NET Core");
    }

    #[test]
    fn repository_inventory_detects_aspnet_static_asset_routes() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Web.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk.Web\"></Project>\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("Program.cs"),
            "var app = WebApplication.CreateBuilder(args).Build();\napp.MapStaticAssets();\napp.MapStaticAssets(\"/assets/{**path}\");\n",
        )
        .unwrap();

        let inventory = build_repository_inventory(temp.path()).unwrap();

        assert_route(&inventory, "GET", "/{staticAsset}", "ASP.NET Core");
        assert_route(&inventory, "GET", "/assets/{**path}", "ASP.NET Core");
    }

    #[test]
    fn repository_inventory_detects_aspnet_reverse_proxy_routes() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Web.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk.Web\"></Project>\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("Program.cs"),
            "var app = WebApplication.CreateBuilder(args).Build();\napp.MapReverseProxy();\napp.MapReverseProxy(\"/proxy/{**catchAll}\");\n",
        )
        .unwrap();

        let inventory = build_repository_inventory(temp.path()).unwrap();

        assert_route(&inventory, "ANY", "/{**proxy}", "ASP.NET Core");
        assert_route(&inventory, "ANY", "/proxy/{**catchAll}", "ASP.NET Core");
    }

    #[test]
    fn repository_inventory_detects_aspnet_forwarder_routes() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Web.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk.Web\"></Project>\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("Program.cs"),
            "var app = WebApplication.CreateBuilder(args).Build();\napp.MapForwarder(\"/proxy/{**catchAll}\", \"https://backend.internal\");\n",
        )
        .unwrap();

        let inventory = build_repository_inventory(temp.path()).unwrap();

        assert_route(&inventory, "ANY", "/proxy/{**catchAll}", "ASP.NET Core");
    }

    #[test]
    fn repository_inventory_detects_aspnet_fallback_controller_routes() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Web.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk.Web\"></Project>\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("Program.cs"),
            "var app = WebApplication.CreateBuilder(args).Build();\napp.MapFallbackToController(\"Index\", \"Home\");\napp.MapFallbackToController(\"proxy/{**path}\", \"Proxy\", \"Gateway\");\napp.MapFallbackToAreaController(\"{*path:nonfile}\", \"Index\", \"Spa\", \"Public\");\n",
        )
        .unwrap();

        let inventory = build_repository_inventory(temp.path()).unwrap();

        assert_route(&inventory, "ANY", "*", "ASP.NET Core");
        assert_route(&inventory, "ANY", "/proxy/{**path}", "ASP.NET Core");
        assert_route(&inventory, "ANY", "/{*path:nonfile}", "ASP.NET Core");
    }

    #[test]
    fn repository_inventory_detects_aspnet_razor_components_routes() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Web.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk.Web\"></Project>\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("Program.cs"),
            "var app = WebApplication.CreateBuilder(args).Build();\napp.MapRazorComponents<App>();\napp.MapRazorComponents<App>(\"/ui/{**page}\");\n",
        )
        .unwrap();

        let inventory = build_repository_inventory(temp.path()).unwrap();

        assert_route(&inventory, "ANY", "/{component}", "ASP.NET Core");
        assert_route(&inventory, "ANY", "/ui/{**page}", "ASP.NET Core");
    }

    #[test]
    fn repository_inventory_detects_aspnet_page_route_conventions() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Web.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk.Web\"></Project>\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("Program.cs"),
            "var app = WebApplication.CreateBuilder(args).Build();\napp.MapPageRoute(\"/Help\", \"help/{id?}\");\napp.MapAreaPageRoute(\"Admin\", \"/Audit\", \"admin/audit/{**path}\");\n",
        )
        .unwrap();

        let inventory = build_repository_inventory(temp.path()).unwrap();

        assert_route(&inventory, "ANY", "/help/{id?}", "ASP.NET Core");
        assert_route(&inventory, "ANY", "/admin/audit/{**path}", "ASP.NET Core");
    }

    #[test]
    fn repository_inventory_detects_aspnet_dynamic_routes() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Web.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk.Web\"></Project>\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("Program.cs"),
            "var app = WebApplication.CreateBuilder(args).Build();\napp.MapDynamicControllerRoute<SlugTransformer>(\"{**slug}\");\napp.MapDynamicPageRoute<PageTransformer>(\"cms/{**path}\");\n",
        )
        .unwrap();

        let inventory = build_repository_inventory(temp.path()).unwrap();

        assert_route(&inventory, "ANY", "/{**slug}", "ASP.NET Core");
        assert_route(&inventory, "ANY", "/cms/{**path}", "ASP.NET Core");
    }

    #[test]
    fn repository_inventory_detects_aspnet_map_controllers_routes() {
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

        let inventory = build_repository_inventory(temp.path()).unwrap();

        assert_route(&inventory, "ANY", "/{controller}/{action}", "ASP.NET Core");
    }

    #[test]
    fn repository_inventory_detects_aspnet_positional_controller_routes() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Web.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk.Web\"></Project>\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("Program.cs"),
            "var app = WebApplication.CreateBuilder(args).Build();\napp.MapControllerRoute(\"catalog\", \"catalog/{controller}/{action}\");\napp.MapAreaControllerRoute(\"admin\", \"Admin\", \"admin/{controller}/{action}\");\n",
        )
        .unwrap();

        let inventory = build_repository_inventory(temp.path()).unwrap();

        assert_route(
            &inventory,
            "ANY",
            "/catalog/{controller}/{action}",
            "ASP.NET Core",
        );
        assert_route(
            &inventory,
            "ANY",
            "/admin/{controller}/{action}",
            "ASP.NET Core",
        );
    }

    #[test]
    fn repository_inventory_detects_aspnet_accept_verbs_routes() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Web.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk.Web\"></Project>\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("AdminController.cs"),
            "using Microsoft.AspNetCore.Mvc;\n[Route(\"api\")]\nclass AdminController {\n[AcceptVerbs(\"POST\", Route = \"admin/export\")]\npublic IActionResult Export() => Ok();\n}\n",
        )
        .unwrap();

        let inventory = build_repository_inventory(temp.path()).unwrap();

        assert_route(&inventory, "POST", "/api/admin/export", "ASP.NET Core");
    }

    #[test]
    fn repository_inventory_detects_aspnet_tunnel_method_routes() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Web.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk.Web\"></Project>\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("Program.cs"),
            "var app = WebApplication.CreateBuilder(args).Build();\napp.MapMethods(\"/imports/constants\", new[] { HttpMethods.Put, HttpMethods.Patch }, Constants);\napp.MapMethods(\"/imports/tunnel\", new[] { \"TRACE\", HttpMethods.Connect }, Tunnel);\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("AdminController.cs"),
            "using Microsoft.AspNetCore.Http;\nusing Microsoft.AspNetCore.Mvc;\n[Route(\"api\")]\nclass AdminController {\n[AcceptVerbs(\"POST\", HttpMethods.Trace, Route = \"tunnel\")]\npublic IActionResult Tunnel() => Ok();\n}\n",
        )
        .unwrap();

        let inventory = build_repository_inventory(temp.path()).unwrap();

        assert_route(&inventory, "PUT,PATCH", "/imports/constants", "ASP.NET Core");
        assert_route(&inventory, "TRACE,CONNECT", "/imports/tunnel", "ASP.NET Core");
        assert_route(&inventory, "POST,TRACE", "/api/tunnel", "ASP.NET Core");
    }

    #[test]
    fn repository_inventory_ignores_aspnet_http_attribute_name_metadata() {
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

        let inventory = build_repository_inventory(temp.path()).unwrap();

        assert_route(&inventory, "GET", "/api/admin", "ASP.NET Core");
        assert_route(
            &inventory,
            "POST",
            "/api/admin/reports/export",
            "ASP.NET Core",
        );
        assert_no_route(&inventory, "/api/admin/GetAdmin");
    }

    #[test]
    fn repository_inventory_ignores_aspnet_route_attribute_name_metadata() {
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

        let inventory = build_repository_inventory(temp.path()).unwrap();

        assert_route(&inventory, "GET", "/status", "ASP.NET Core");
        assert_route(&inventory, "POST", "/reports/export", "ASP.NET Core");
        assert_no_route(&inventory, "/AdminRoot/status");
    }

    #[test]
    fn repository_inventory_normalizes_aspnet_route_tokens() {
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

        let inventory = build_repository_inventory(temp.path()).unwrap();

        assert_route(
            &inventory,
            "GET",
            "/admin/{area}/{controller}/{action}",
            "ASP.NET Core",
        );
    }

    #[test]
    fn repository_inventory_detects_aspnet_short_circuit_routes() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(
            temp.path().join("Web.csproj"),
            "<Project Sdk=\"Microsoft.NET.Sdk.Web\"></Project>\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("Program.cs"),
            "var app = WebApplication.CreateBuilder(args).Build();\napp.MapShortCircuit(404, \"robots.txt\");\n",
        )
        .unwrap();

        let inventory = build_repository_inventory(temp.path()).unwrap();

        assert_route(&inventory, "ANY", "/robots.txt", "ASP.NET Core");
    }

    #[test]
    fn repository_inventory_is_deterministic_for_mixed_fixtures_and_skips_generated_sources() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/generated")).unwrap();
        fs::write(
            temp.path().join("package.json"),
            r#"{"dependencies":{"next":"14.0.0"}}"#,
        )
        .unwrap();
        fs::write(
            temp.path().join("pyproject.toml"),
            "[project]\ndependencies = ['django']\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("Cargo.toml"),
            "[package]\nname = \"mixed\"\n",
        )
        .unwrap();
        fs::write(temp.path().join("src/api.ts"), "export const ok = true;\n").unwrap();
        fs::write(temp.path().join("worker.py"), "print('ok')\n").unwrap();
        fs::write(temp.path().join("src/lib.rs"), "pub fn ok() {}\n").unwrap();
        fs::write(
            temp.path().join("src/generated/client.generated.ts"),
            "export const generated = true;\n",
        )
        .unwrap();

        let first = build_repository_inventory(temp.path()).unwrap();
        let second = build_repository_inventory(temp.path()).unwrap();

        assert_eq!(first, second);
        assert_eq!(
            first
                .languages
                .iter()
                .map(|language| language.name.as_str())
                .collect::<Vec<_>>(),
            vec!["Python", "Rust", "TypeScript"]
        );
        assert_framework(&first, "Next.js", "JavaScript");
        assert_framework(&first, "Django", "Python");
        assert!(first
            .generated_vendor_paths
            .iter()
            .any(|item| item.path == "src/generated" && item.kind == "generated"));
        assert!(!first
            .source_files
            .iter()
            .any(|file| file.path == "src/generated/client.generated.ts"));
    }

    #[test]
    fn repository_inventory_detects_nextjs_route_files() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/app/api/users/[userId]")).unwrap();
        fs::create_dir_all(temp.path().join("src/app/api/health")).unwrap();
        fs::create_dir_all(temp.path().join("pages/api/webhooks")).unwrap();
        fs::write(
            temp.path().join("package.json"),
            r#"{"dependencies":{"next":"14.0.0"}}"#,
        )
        .unwrap();
        fs::write(
            temp.path().join("src/app/api/users/[userId]/route.ts"),
            "export async function POST(request: Request) { return Response.json({ ok: true }); }\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("src/app/api/health/route.ts"),
            "export function HEAD() { return new Response(null); }\nexport const OPTIONS = () => Response.json({ ok: true });\n",
        )
        .unwrap();
        fs::write(
            temp.path().join("pages/api/webhooks/[...slug].ts"),
            "export default function handler(req, res) { res.json({ ok: true }); }\n",
        )
        .unwrap();

        let inventory = build_repository_inventory(temp.path()).unwrap();

        assert_framework(&inventory, "Next.js", "JavaScript");
        assert_route(&inventory, "POST", "/api/users/:userId", "Next.js");
        assert_route(&inventory, "HEAD", "/api/health", "Next.js");
        assert_route(&inventory, "OPTIONS", "/api/health", "Next.js");
        assert_route(&inventory, "ANY", "/api/webhooks/:slug", "Next.js");
    }

    #[test]
    fn repository_inventory_detects_nestjs_controller_routes() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src")).unwrap();
        fs::write(
            temp.path().join("package.json"),
            r#"{"dependencies":{"@nestjs/common":"^10.0.0"}}"#,
        )
        .unwrap();
        fs::write(
            temp.path().join("src/projects.controller.ts"),
            "import { Controller, Post } from '@nestjs/common';\n@Controller('teams')\nexport class ProjectsController {\n  @Post('/teams/projects')\n  createProject() { return {}; }\n}\n",
        )
        .unwrap();

        let inventory = build_repository_inventory(temp.path()).unwrap();

        assert_framework(&inventory, "NestJS", "TypeScript");
        assert_route(&inventory, "POST", "/teams/projects", "NestJS");
    }

    #[test]
    fn repository_inventory_detects_koa_router_routes() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src")).unwrap();
        fs::write(
            temp.path().join("package.json"),
            r#"{"dependencies":{"koa":"^2.15.0","@koa/router":"^12.0.0"}}"#,
        )
        .unwrap();
        fs::write(
            temp.path().join("src/server.ts"),
            "import Koa from 'koa';\nimport Router from '@koa/router';\nconst router = new Router();\nrouter.post('/teams/projects', createProject);\n",
        )
        .unwrap();

        let inventory = build_repository_inventory(temp.path()).unwrap();

        assert_framework(&inventory, "Koa", "JavaScript");
        assert_framework(&inventory, "Koa", "TypeScript");
        assert_route(&inventory, "POST", "/teams/projects", "Koa");
    }

    #[test]
    fn repository_inventory_detects_fastify_routes() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src")).unwrap();
        fs::write(
            temp.path().join("package.json"),
            r#"{"dependencies":{"fastify":"^4.26.0"}}"#,
        )
        .unwrap();
        fs::write(
            temp.path().join("src/server.ts"),
            "import fastify from 'fastify';\nconst app = fastify();\napp.post('/teams/projects', createProject);\n",
        )
        .unwrap();

        let inventory = build_repository_inventory(temp.path()).unwrap();

        assert_framework(&inventory, "Fastify", "JavaScript");
        assert_framework(&inventory, "Fastify", "TypeScript");
        assert_route(&inventory, "POST", "/teams/projects", "Fastify");
    }

    #[test]
    fn repository_inventory_detects_hono_routes() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src")).unwrap();
        fs::write(
            temp.path().join("package.json"),
            r#"{"dependencies":{"hono":"^4.3.0"}}"#,
        )
        .unwrap();
        fs::write(
            temp.path().join("src/server.ts"),
            "import { Hono } from 'hono';\nconst app = new Hono();\napp.post('/teams/projects', createProject);\n",
        )
        .unwrap();

        let inventory = build_repository_inventory(temp.path()).unwrap();

        assert_framework(&inventory, "Hono", "JavaScript");
        assert_framework(&inventory, "Hono", "TypeScript");
        assert_route(&inventory, "POST", "/teams/projects", "Hono");
    }

    #[test]
    fn repository_inventory_detects_elysia_routes() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src")).unwrap();
        fs::write(
            temp.path().join("package.json"),
            r#"{"dependencies":{"elysia":"^1.1.0"}}"#,
        )
        .unwrap();
        fs::write(
            temp.path().join("src/server.ts"),
            "import { Elysia } from 'elysia';\nconst app = new Elysia();\napp.post('/teams/projects', createProject);\n",
        )
        .unwrap();

        let inventory = build_repository_inventory(temp.path()).unwrap();

        assert_framework(&inventory, "Elysia", "JavaScript");
        assert_framework(&inventory, "Elysia", "TypeScript");
        assert_route(&inventory, "POST", "/teams/projects", "Elysia");
    }

    fn assert_language(inventory: &RepositoryInventory, name: &str, files: usize) {
        let language = inventory
            .languages
            .iter()
            .find(|language| language.name == name)
            .unwrap_or_else(|| panic!("missing language {name}: {:?}", inventory.languages));
        assert_eq!(language.files, files);
    }

    fn assert_has_file(files: &[InventoryFile], path: &str, kind: &str) {
        assert!(
            files
                .iter()
                .any(|file| file.path == path && file.kind == kind),
            "missing {path} {kind}: {files:?}"
        );
    }

    fn assert_framework(inventory: &RepositoryInventory, name: &str, language: &str) {
        assert!(
            inventory
                .frameworks
                .iter()
                .any(|framework| framework.name == name && framework.language == language),
            "missing framework {name}/{language}: {:?}",
            inventory.frameworks
        );
    }

    fn assert_route(inventory: &RepositoryInventory, method: &str, route: &str, framework: &str) {
        assert!(
            inventory.routes_controllers.iter().any(|item| {
                item.kind == "route"
                    && item.method.as_deref() == Some(method)
                    && item.route.as_deref() == Some(route)
                    && item.framework.as_deref() == Some(framework)
            }),
            "missing route {method} {route} {framework}: {:?}",
            inventory.routes_controllers
        );
    }

    fn assert_no_route(inventory: &RepositoryInventory, route: &str) {
        assert!(
            inventory
                .routes_controllers
                .iter()
                .all(|item| item.route.as_deref() != Some(route)),
            "unexpected route {route}: {:?}",
            inventory.routes_controllers
        );
    }
}
