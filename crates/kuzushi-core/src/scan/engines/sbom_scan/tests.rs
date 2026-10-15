use super::*;
use serde_json::json;
use std::fs;

#[cfg(unix)]
#[test]
fn parser_rejects_manifest_when_parent_is_replaced_after_inventory() {
    let target = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let nested = target.path().join("nested");
    fs::create_dir(&nested).unwrap();
    fs::write(
        nested.join("package.json"),
        r#"{"dependencies":{"safe":"1.0.0"}}"#,
    )
    .unwrap();
    fs::write(
        outside.path().join("package.json"),
        r#"{"dependencies":{"outside":"9.9.9"}}"#,
    )
    .unwrap();
    let inventory = collect_regular_files(
        target.path(),
        &ScanCancellation::default(),
        sbom_walk_options(),
    )
    .unwrap();
    fs::rename(&nested, target.path().join("original-nested")).unwrap();
    std::os::unix::fs::symlink(outside.path(), &nested).unwrap();

    let inputs = SbomInputs::new(target.path(), SbomScanOptions::default(), ScanCancellation::default()).unwrap();
    let error = manifest::manifest_components(&inputs, &inventory.files[0]).unwrap_err();

    let detail = format!("{error:#}");
    assert!(detail.contains("refusing to follow"), "{detail}");
    assert!(!detail.contains("outside\":\"9.9.9"));
}

#[test]
fn sbom_scan_extracts_package_cargo_and_python_dependencies() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("package.json"),
        r#"{"dependencies":{"express":"^4.18.0","left-pad":{"version":"1.3.0"}},"devDependencies":{"vitest":"latest"}}"#,
    )
    .unwrap();
    fs::write(
        temp.path().join("Cargo.toml"),
        "[package]\nname = \"demo\"\n[dependencies]\nserde = \"1\"\n",
    )
    .unwrap();
    fs::write(
        temp.path().join("pyproject.toml"),
        "[project]\ndependencies = [\"django>=5\"]\n",
    )
    .unwrap();
    fs::write(temp.path().join("Cargo.lock"), "# lock\n").unwrap();
    fs::write(
        temp.path().join("package-lock.json"),
        r#"{"packages":{"":{"dependencies":{"express":"^4.18.0"},"devDependencies":{"vitest":"latest"},"optionalDependencies":{"fsevents":"^2.3.3"},"peerDependencies":{"react":"^18.0.0"}},"node_modules/express":{"version":"4.18.0","dependencies":{"body-parser":"1.20.0"}}}}"#,
    )
    .unwrap();

    let report = scan_sbom(temp.path(), &ScanCancellation::default()).unwrap();
    let names = report
        .components
        .iter()
        .map(|component| component.name.as_str())
        .collect::<Vec<_>>();

    assert_eq!(report.manifests_scanned, 3);
    assert!(names.contains(&"express"));
    assert!(names.contains(&"left-pad"));
    assert!(names.contains(&"vitest"));
    assert!(names.contains(&"serde"));
    assert!(names.contains(&"django"));
    assert_eq!(report.by_ecosystem.get("npm"), Some(&4));
    assert_eq!(report.by_ecosystem.get("cargo"), Some(&1));
    assert_eq!(report.by_ecosystem.get("python"), Some(&1));
    assert_eq!(report.lockfiles.len(), 2);
    assert!(report
        .lockfiles
        .iter()
        .any(|lockfile| lockfile.path == "Cargo.lock" && lockfile.sha256.starts_with("sha256:")));
    assert!(report
        .dependencies
        .iter()
        .any(|edge| edge.from == "root" && edge.to == "express"));
    assert!(report
        .dependencies
        .iter()
        .any(|edge| edge.from == "root" && edge.to == "vitest"));
    assert!(report
        .dependencies
        .iter()
        .any(|edge| edge.from == "root" && edge.to == "fsevents"));
    assert!(report
        .dependencies
        .iter()
        .any(|edge| edge.from == "root" && edge.to == "react"));
    assert!(report
        .dependencies
        .iter()
        .any(|edge| edge.from == "express" && edge.to == "body-parser"));
    assert!(report
        .components
        .iter()
        .any(|component| component.name == "express"
            && component.package_url.as_deref() == Some("pkg:npm/express")));
    assert!(report
        .components
        .iter()
        .any(|component| component.name == "left-pad"
            && component.package_url.as_deref() == Some("pkg:npm/left-pad@1.3.0")));
    assert!(report
        .components
        .iter()
        .any(|component| component.name == "serde"
            && component.package_url.as_deref() == Some("pkg:cargo/serde@1")));
}

#[test]
fn sbom_scan_ignores_nested_agent_and_kuzushi_state() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("package.json"),
        r#"{"dependencies":{"product":"1.0.0"}}"#,
    )
    .unwrap();
    for state_dir in [".claude/worktrees/copy", ".kuzushi/worktrees/copy"] {
        let nested = temp.path().join(state_dir);
        fs::create_dir_all(&nested).unwrap();
        fs::write(
            nested.join("package.json"),
            r#"{"dependencies":{"duplicate":"9.9.9"}}"#,
        )
        .unwrap();
    }

    let report = scan_sbom(temp.path(), &ScanCancellation::default()).unwrap();

    assert_eq!(report.manifests_scanned, 1);
    assert_eq!(report.components.len(), 1);
    assert_eq!(report.components[0].name, "product");
    assert_eq!(report.components[0].manifest_path, "package.json");
}

#[test]
fn sbom_scan_extracts_package_json_root_edges_without_lockfile() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("package.json"),
        r#"{
  "dependencies": {
    "express": "^4.18.0"
  },
  "devDependencies": {
    "vitest": "latest"
  },
  "peerDependencies": {
    "react": "^18.0.0"
  },
  "optionalDependencies": {
    "fsevents": "^2.3.3"
  }
}"#,
    )
    .unwrap();

    let report = scan_sbom(temp.path(), &ScanCancellation::default()).unwrap();

    assert_eq!(report.manifests_scanned, 1);
    assert!(report.lockfiles.is_empty());
    assert!(report
        .dependencies
        .iter()
        .any(|edge| edge.from == "root" && edge.to == "express" && edge.source == "package.json"));
    assert!(report
        .dependencies
        .iter()
        .any(|edge| edge.from == "root" && edge.to == "vitest" && edge.source == "package.json"));
    assert!(report
        .dependencies
        .iter()
        .any(|edge| edge.from == "root" && edge.to == "react" && edge.source == "package.json"));
    assert!(report
        .dependencies
        .iter()
        .any(|edge| edge.from == "root" && edge.to == "fsevents" && edge.source == "package.json"));
}

#[test]
fn sbom_scan_extracts_bower_dependencies() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("bower.json"),
        r#"{
  "name": "legacy-ui",
  "dependencies": {
    "jquery": "3.7.1",
    "normalize-css": {
      "version": "8.0.1"
    }
  },
  "devDependencies": {
    "qunit": "^2.20.0"
  }
}"#,
    )
    .unwrap();

    let report = scan_sbom(temp.path(), &ScanCancellation::default()).unwrap();
    let scoped_names = report
        .components
        .iter()
        .map(|component| {
            (
                component.scope.as_str(),
                component.name.as_str(),
                component.package_url.as_deref(),
            )
        })
        .collect::<Vec<_>>();

    assert_eq!(report.manifests_scanned, 1);
    assert_eq!(report.by_ecosystem.get("bower"), Some(&3));
    assert!(scoped_names.contains(&("dependencies", "jquery", Some("pkg:generic/jquery@3.7.1"))));
    assert!(scoped_names.contains(
        &((
            "dependencies",
            "normalize-css",
            Some("pkg:generic/normalize-css@8.0.1")
        ))
    ));
    assert!(scoped_names.contains(&("devDependencies", "qunit", Some("pkg:generic/qunit"))));
    assert!(report
        .dependencies
        .iter()
        .any(|edge| edge.from == "root" && edge.to == "jquery" && edge.source == "bower.json"));
    assert!(report
        .dependencies
        .iter()
        .any(|edge| edge.from == "root" && edge.to == "qunit" && edge.source == "bower.json"));
}

#[test]
fn sbom_scan_extracts_haxelib_dependencies() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("haxelib.json"),
        r#"{
  "name": "demo",
  "version": "0.1.0",
  "dependencies": {
    "tink_core": "2.0.0",
    "utest": ""
  }
}"#,
    )
    .unwrap();

    let report = scan_sbom(temp.path(), &ScanCancellation::default()).unwrap();
    let scoped_names = report
        .components
        .iter()
        .map(|component| {
            (
                component.scope.as_str(),
                component.name.as_str(),
                component.package_url.as_deref(),
            )
        })
        .collect::<Vec<_>>();

    assert_eq!(report.manifests_scanned, 1);
    assert_eq!(report.by_ecosystem.get("haxelib"), Some(&2));
    assert!(scoped_names.contains(&(
        "dependencies",
        "tink_core",
        Some("pkg:generic/tink_core@2.0.0")
    )));
    assert!(scoped_names.contains(&("dependencies", "utest", Some("pkg:generic/utest"))));
    assert!(report.dependencies.iter().any(|edge| edge.from == "root"
        && edge.to == "tink_core"
        && edge.source == "haxelib.json"));
    assert!(report
        .dependencies
        .iter()
        .any(|edge| edge.from == "root" && edge.to == "utest" && edge.source == "haxelib.json"));
}

#[test]
fn sbom_scan_extracts_nimble_dependencies() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("demo.nimble"),
        r#"
version = "0.1.0"
author = "Example"
requires "nim >= 1.6.0", "jester", "chronicles >= 0.10.0"
"#,
    )
    .unwrap();

    let report = scan_sbom(temp.path(), &ScanCancellation::default()).unwrap();
    let scoped_names = report
        .components
        .iter()
        .map(|component| {
            (
                component.scope.as_str(),
                component.name.as_str(),
                component.package_url.as_deref(),
            )
        })
        .collect::<Vec<_>>();

    assert_eq!(report.manifests_scanned, 1);
    assert_eq!(report.by_ecosystem.get("nimble"), Some(&3));
    assert!(scoped_names.contains(&("requires", "nim", Some("pkg:generic/nim"))));
    assert!(scoped_names.contains(&("requires", "jester", Some("pkg:generic/jester"))));
    assert!(scoped_names.contains(&("requires", "chronicles", Some("pkg:generic/chronicles"))));
    assert!(report
        .dependencies
        .iter()
        .any(|edge| edge.from == "root" && edge.to == "jester" && edge.source == "demo.nimble"));
    assert!(report.dependencies.iter().any(|edge| edge.from == "root"
        && edge.to == "chronicles"
        && edge.source == "demo.nimble"));
}

#[test]
fn sbom_scan_extracts_gleam_toml_dependencies() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("gleam.toml"),
        r#"
name = "demo"
version = "0.1.0"

[dependencies]
gleam_stdlib = ">= 0.34.0 and < 2.0.0"
mist = "1.2.3"

[dev-dependencies]
gleeunit = ">= 1.0.0 and < 2.0.0"
"#,
    )
    .unwrap();

    let report = scan_sbom(temp.path(), &ScanCancellation::default()).unwrap();
    let scoped_names = report
        .components
        .iter()
        .map(|component| {
            (
                component.scope.as_str(),
                component.name.as_str(),
                component.package_url.as_deref(),
            )
        })
        .collect::<Vec<_>>();

    assert_eq!(report.manifests_scanned, 1);
    assert_eq!(report.by_ecosystem.get("hex"), Some(&3));
    assert!(scoped_names.contains(&("dependencies", "gleam_stdlib", Some("pkg:hex/gleam_stdlib"))));
    assert!(scoped_names.contains(&("dependencies", "mist", Some("pkg:hex/mist@1.2.3"))));
    assert!(scoped_names.contains(&("dev-dependencies", "gleeunit", Some("pkg:hex/gleeunit"))));
    assert!(report.dependencies.iter().any(|edge| edge.from == "root"
        && edge.to == "gleam_stdlib"
        && edge.source == "gleam.toml"));
    assert!(report
        .dependencies
        .iter()
        .any(|edge| edge.from == "root" && edge.to == "gleeunit" && edge.source == "gleam.toml"));
}

#[test]
fn sbom_scan_extracts_mix_dependencies() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("mix.exs"),
        r#"
defmodule Demo.MixProject do
  use Mix.Project

  defp deps do
    [
      {:phoenix, "~> 1.7.12"},
      {:jason, "~> 1.4", only: :test},
      {:plug_cowboy, "~> 2.7", optional: true}
    ]
  end
end
"#,
    )
    .unwrap();

    let report = scan_sbom(temp.path(), &ScanCancellation::default()).unwrap();
    let scoped_names = report
        .components
        .iter()
        .map(|component| {
            (
                component.scope.as_str(),
                component.name.as_str(),
                component.package_url.as_deref(),
            )
        })
        .collect::<Vec<_>>();

    assert_eq!(report.manifests_scanned, 1);
    assert_eq!(report.by_ecosystem.get("hex"), Some(&3));
    assert!(scoped_names.contains(&("deps", "phoenix", Some("pkg:hex/phoenix"))));
    assert!(scoped_names.contains(&("deps.test", "jason", Some("pkg:hex/jason"))));
    assert!(scoped_names.contains(&("deps", "plug_cowboy", Some("pkg:hex/plug_cowboy"))));
    assert!(report
        .dependencies
        .iter()
        .any(|edge| edge.from == "root" && edge.to == "phoenix" && edge.source == "mix.exs"));
    assert!(report
        .dependencies
        .iter()
        .any(|edge| edge.from == "root" && edge.to == "jason" && edge.source == "mix.exs"));
}

#[test]
fn sbom_scan_extracts_mix_lock_edges() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("mix.lock"),
        r#"%{
  "decimal": {:hex, :decimal, "2.1.1", "hash", [:mix], [], "hexpm", "hash"},
  "jason": {:hex, :jason, "1.4.4", "hash", [:mix], [{:decimal, "~> 2.0", [hex: :decimal, repo: "hexpm", optional: true]}], "hexpm", "hash"},
  "plug": {:hex, :plug, "1.15.3", "hash", [:mix], [{:mime, "~> 1.0 or ~> 2.0", [hex: :mime, repo: "hexpm", optional: false]}], "hexpm", "hash"}
}
"#,
    )
    .unwrap();

    let report = scan_sbom(temp.path(), &ScanCancellation::default()).unwrap();
    let components = report
        .components
        .iter()
        .map(|component| {
            (
                component.scope.as_str(),
                component.name.as_str(),
                component.package_url.as_deref(),
            )
        })
        .collect::<Vec<_>>();

    assert_eq!(report.by_ecosystem.get("hex"), Some(&3));
    assert_eq!(report.lockfiles.len(), 1);
    assert!(report
        .lockfiles
        .iter()
        .any(|lockfile| lockfile.path == "mix.lock" && lockfile.sha256.starts_with("sha256:")));
    assert!(components.contains(&("mix.lock", "decimal", Some("pkg:hex/decimal@2.1.1"))));
    assert!(components.contains(&("mix.lock", "jason", Some("pkg:hex/jason@1.4.4"))));
    assert!(components.contains(&("mix.lock", "plug", Some("pkg:hex/plug@1.15.3"))));
    assert!(report
        .dependencies
        .iter()
        .any(|edge| edge.from == "root" && edge.to == "jason" && edge.source == "mix.lock"));
    assert!(report
        .dependencies
        .iter()
        .any(|edge| edge.from == "jason" && edge.to == "decimal" && edge.source == "mix.lock"));
    assert!(report
        .dependencies
        .iter()
        .any(|edge| edge.from == "plug" && edge.to == "mime" && edge.source == "mix.lock"));
}

#[test]
fn sbom_scan_extracts_sbt_dependencies() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("build.sbt"),
        r#"
scalaVersion := "2.13.12"

libraryDependencies += "com.typesafe.akka" %% "akka-actor-typed" % "2.8.5"
libraryDependencies += "com.lihaoyi" % "os-lib_2.13" % "0.9.3"
libraryDependencies ++= Seq(
  "org.scalatest" %% "scalatest" % "3.2.18" % Test
)
"#,
    )
    .unwrap();

    let report = scan_sbom(temp.path(), &ScanCancellation::default()).unwrap();
    let scoped_names = report
        .components
        .iter()
        .map(|component| {
            (
                component.scope.as_str(),
                component.name.as_str(),
                component.package_url.as_deref(),
            )
        })
        .collect::<Vec<_>>();

    assert_eq!(report.manifests_scanned, 1);
    assert_eq!(report.by_ecosystem.get("maven"), Some(&3));
    assert!(scoped_names.contains(&(
        "libraryDependencies",
        "com.typesafe.akka/akka-actor-typed_2.13",
        Some("pkg:maven/com.typesafe.akka/akka-actor-typed_2.13@2.8.5")
    )));
    assert!(scoped_names.contains(&(
        "libraryDependencies",
        "com.lihaoyi/os-lib_2.13",
        Some("pkg:maven/com.lihaoyi/os-lib_2.13@0.9.3")
    )));
    assert!(scoped_names.contains(&(
        "libraryDependencies.test",
        "org.scalatest/scalatest_2.13",
        Some("pkg:maven/org.scalatest/scalatest_2.13@3.2.18")
    )));
    assert!(report.dependencies.iter().any(|edge| edge.from == "root"
        && edge.to == "com.typesafe.akka/akka-actor-typed_2.13"
        && edge.source == "build.sbt"));
    assert!(report.dependencies.iter().any(|edge| edge.from == "root"
        && edge.to == "org.scalatest/scalatest_2.13"
        && edge.source == "build.sbt"));
}

#[test]
fn sbom_scan_extracts_deno_import_dependencies() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("deno.json"),
        r#"{
  "imports": {
    "@std/path": "jsr:@std/path@1.0.0",
    "chalk": "npm:chalk@5.3.0",
    "lodash/": "npm:lodash/fp",
    "./local": "./mod.ts",
    "oak": "https://deno.land/x/oak/mod.ts"
  }
}"#,
    )
    .unwrap();

    let report = scan_sbom(temp.path(), &ScanCancellation::default()).unwrap();
    let scoped_names = report
        .components
        .iter()
        .map(|component| {
            (
                component.scope.as_str(),
                component.ecosystem.as_str(),
                component.name.as_str(),
                component.package_url.as_deref(),
            )
        })
        .collect::<Vec<_>>();

    assert_eq!(report.manifests_scanned, 1);
    assert_eq!(report.by_ecosystem.get("npm"), Some(&2));
    assert_eq!(report.by_ecosystem.get("jsr"), Some(&1));
    assert!(scoped_names.contains(&(
        "imports",
        "jsr",
        "@std/path",
        Some("pkg:generic/@std/path@1.0.0")
    )));
    assert!(scoped_names.contains(&("imports", "npm", "chalk", Some("pkg:npm/chalk@5.3.0"))));
    assert!(scoped_names.contains(&("imports", "npm", "lodash", Some("pkg:npm/lodash"))));
    assert!(report
        .dependencies
        .iter()
        .any(|edge| edge.from == "root" && edge.to == "@std/path" && edge.source == "deno.json"));
    assert!(report
        .dependencies
        .iter()
        .any(|edge| edge.from == "root" && edge.to == "chalk" && edge.source == "deno.json"));
    assert!(report
        .dependencies
        .iter()
        .any(|edge| edge.from == "root" && edge.to == "lodash" && edge.source == "deno.json"));
}

#[test]
fn sbom_scan_extracts_deno_import_map_scopes() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("import_map.json"),
        r#"{
  "imports": {
    "preact": "npm:preact@10.24.0"
  },
  "scopes": {
    "https://deno.land/x/example/": {
      "path": "jsr:@std/path@1.0.8",
      "kleur": "npm:kleur@4.1.5"
    }
  }
}"#,
    )
    .unwrap();

    let report = scan_sbom(temp.path(), &ScanCancellation::default()).unwrap();
    let scoped_names = report
        .components
        .iter()
        .map(|component| {
            (
                component.scope.as_str(),
                component.ecosystem.as_str(),
                component.name.as_str(),
                component.package_url.as_deref(),
            )
        })
        .collect::<Vec<_>>();

    assert_eq!(report.manifests_scanned, 1);
    assert_eq!(report.by_ecosystem.get("npm"), Some(&2));
    assert_eq!(report.by_ecosystem.get("jsr"), Some(&1));
    assert!(scoped_names.contains(&("imports", "npm", "preact", Some("pkg:npm/preact@10.24.0"))));
    assert!(scoped_names.contains(&(
        "scopes.https://deno.land/x/example/",
        "jsr",
        "@std/path",
        Some("pkg:generic/@std/path@1.0.8")
    )));
    assert!(scoped_names.contains(&(
        "scopes.https://deno.land/x/example/",
        "npm",
        "kleur",
        Some("pkg:npm/kleur@4.1.5")
    )));
    assert!(report.dependencies.iter().any(|edge| edge.from == "root"
        && edge.to == "@std/path"
        && edge.source == "import_map.json"));
    assert!(report
        .dependencies
        .iter()
        .any(|edge| edge.from == "root" && edge.to == "kleur" && edge.source == "import_map.json"));
}

#[test]
fn sbom_scan_extracts_referenced_deno_import_map() {
    let temp = tempfile::tempdir().unwrap();
    fs::create_dir_all(temp.path().join("config")).unwrap();
    fs::write(
        temp.path().join("deno.json"),
        r#"{
  "importMap": "./config/deps.json"
}"#,
    )
    .unwrap();
    fs::write(
        temp.path().join("config").join("deps.json"),
        r#"{
  "imports": {
    "postgres": "npm:postgres@3.4.5",
    "assert": "jsr:@std/assert@1.0.11"
  }
}"#,
    )
    .unwrap();

    let report = scan_sbom(temp.path(), &ScanCancellation::default()).unwrap();
    let scoped_names = report
        .components
        .iter()
        .map(|component| {
            (
                component.manifest_path.as_str(),
                component.scope.as_str(),
                component.ecosystem.as_str(),
                component.name.as_str(),
                component.package_url.as_deref(),
            )
        })
        .collect::<Vec<_>>();

    assert_eq!(report.manifests_scanned, 1);
    assert_eq!(report.by_ecosystem.get("npm"), Some(&1));
    assert_eq!(report.by_ecosystem.get("jsr"), Some(&1));
    assert!(scoped_names.contains(&(
        "config/deps.json",
        "imports",
        "npm",
        "postgres",
        Some("pkg:npm/postgres@3.4.5")
    )));
    assert!(scoped_names.contains(&(
        "config/deps.json",
        "imports",
        "jsr",
        "@std/assert",
        Some("pkg:generic/@std/assert@1.0.11")
    )));
    assert!(report.dependencies.iter().any(|edge| edge.from == "root"
        && edge.to == "postgres"
        && edge.source == "config/deps.json"));
    assert!(report.dependencies.iter().any(|edge| edge.from == "root"
        && edge.to == "@std/assert"
        && edge.source == "config/deps.json"));
}

#[test]
fn sbom_scan_ignores_deno_import_map_outside_target() {
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir_all(&target).unwrap();
    fs::write(
        target.join("deno.json"),
        r#"{
  "importMap": "../outside.json"
}"#,
    )
    .unwrap();
    fs::write(
        temp.path().join("outside.json"),
        r#"{
  "imports": {
    "outside": "npm:outside@1.0.0"
  }
}"#,
    )
    .unwrap();

    let report = scan_sbom(&target, &ScanCancellation::default()).unwrap();

    assert_eq!(report.manifests_scanned, 1);
    assert!(report.components.is_empty());
    assert!(report.dependencies.is_empty());
}

#[cfg(unix)]
#[test]
fn sbom_scan_ignores_symlinked_deno_import_map_outside_target() {
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    fs::create_dir_all(&target).unwrap();
    fs::write(
        target.join("deno.json"),
        r#"{
  "importMap": "./deps-link.json"
}"#,
    )
    .unwrap();
    fs::write(
        temp.path().join("outside.json"),
        r#"{
  "imports": {
    "outside": "npm:outside@1.0.0"
  }
}"#,
    )
    .unwrap();
    std::os::unix::fs::symlink(
        temp.path().join("outside.json"),
        target.join("deps-link.json"),
    )
    .unwrap();

    let report = scan_sbom(&target, &ScanCancellation::default()).unwrap();

    assert_eq!(report.manifests_scanned, 1);
    assert!(report.components.is_empty());
    assert!(report.dependencies.is_empty());
}

#[cfg(unix)]
#[test]
fn sbom_scan_does_not_descend_through_symlinked_directories() {
    let temp = tempfile::tempdir().unwrap();
    let target = temp.path().join("target");
    let outside = temp.path().join("outside");
    fs::create_dir_all(&target).unwrap();
    fs::create_dir_all(&outside).unwrap();
    fs::write(
        outside.join("package.json"),
        r#"{"dependencies":{"outside":"1.0.0"}}"#,
    )
    .unwrap();
    std::os::unix::fs::symlink(&outside, target.join("linked-dependencies")).unwrap();

    let report = scan_sbom(&target, &ScanCancellation::default()).unwrap();

    assert_eq!(report.manifests_scanned, 0);
    assert!(report.components.is_empty());
    assert!(report.dependencies.is_empty());
}

#[test]
fn sbom_scan_rejects_oversized_manifest_before_parsing() {
    let temp = tempfile::tempdir().unwrap();
    let manifest = temp.path().join("package.json");
    fs::write(&manifest, r#"{"dependencies":{}}"#).unwrap();
    fs::OpenOptions::new()
        .write(true)
        .open(&manifest)
        .unwrap()
        .set_len(64 * 1024 * 1024 + 1)
        .unwrap();

    let error = scan_sbom(temp.path(), &ScanCancellation::default()).unwrap_err();

    assert!(format!("{error:#}").contains("maximum supported size"));
}

#[test]
fn sbom_scan_extracts_deno_lock_edges() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("deno.lock"),
        r#"{
  "version": "4",
  "jsr": {
    "@std/path@1.0.0": {
      "integrity": "sha256-demo",
      "dependencies": [
        "jsr:@std/fs@1.0.0",
        "npm:chalk@5.3.0"
      ]
    },
    "@std/fs@1.0.0": {
      "integrity": "sha256-demo"
    }
  },
  "npm": {
    "chalk@5.3.0": {
      "integrity": "sha512-demo",
      "dependencies": [
        "ansi-styles"
      ]
    },
    "ansi-styles@6.2.1": {
      "integrity": "sha512-demo"
    }
  }
}"#,
    )
    .unwrap();

    let report = scan_sbom(temp.path(), &ScanCancellation::default()).unwrap();
    let components = report
        .components
        .iter()
        .map(|component| {
            (
                component.ecosystem.as_str(),
                component.scope.as_str(),
                component.name.as_str(),
                component.package_url.as_deref(),
            )
        })
        .collect::<Vec<_>>();

    assert_eq!(report.by_ecosystem.get("jsr"), Some(&2));
    assert_eq!(report.by_ecosystem.get("npm"), Some(&2));
    assert_eq!(report.lockfiles.len(), 1);
    assert!(report
        .lockfiles
        .iter()
        .any(|lockfile| lockfile.path == "deno.lock" && lockfile.sha256.starts_with("sha256:")));
    assert!(components.contains(&(
        "jsr",
        "deno.lock",
        "@std/path",
        Some("pkg:generic/@std/path@1.0.0"),
    )));
    assert!(components.contains(&(
        "jsr",
        "deno.lock",
        "@std/fs",
        Some("pkg:generic/@std/fs@1.0.0"),
    )));
    assert!(components.contains(&("npm", "deno.lock", "chalk", Some("pkg:npm/chalk@5.3.0"),)));
    assert!(components.contains(&(
        "npm",
        "deno.lock",
        "ansi-styles",
        Some("pkg:npm/ansi-styles@6.2.1"),
    )));
    assert!(report
        .dependencies
        .iter()
        .any(|edge| edge.from == "root" && edge.to == "@std/path" && edge.source == "deno.lock"));
    assert!(report
        .dependencies
        .iter()
        .any(|edge| edge.from == "@std/path"
            && edge.to == "@std/fs"
            && edge.source == "deno.lock"));
    assert!(report
        .dependencies
        .iter()
        .any(|edge| edge.from == "@std/path" && edge.to == "chalk" && edge.source == "deno.lock"));
    assert!(report.dependencies.iter().any(|edge| edge.from == "chalk"
        && edge.to == "ansi-styles"
        && edge.source == "deno.lock"));
}

#[test]
fn sbom_scan_records_bun_lockfile_digests() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("bun.lock"),
        r#"{
  // Bun text lockfiles are JSONC.
  "workspaces": {
    "": {
      "dependencies": {
        "react": "^18.2.0"
      },
      "devDependencies": {
        "vite": "^5.0.0"
      },
    },
  },
  "packages": {
    "react@18.2.0": [
      "react@18.2.0",
      "",
      {
        "dependencies": {
          "loose-envify": "^1.1.0"
        },
        "peerDependencies": {
          "scheduler": "^0.23.0"
        },
      },
      "sha512-demo"
    ],
  },
}"#,
    )
    .unwrap();
    fs::write(temp.path().join("bun.lockb"), b"BUN\x00LOCK").unwrap();

    let report = scan_sbom(temp.path(), &ScanCancellation::default()).unwrap();
    let components = report
        .components
        .iter()
        .map(|component| {
            (
                component.scope.as_str(),
                component.name.as_str(),
                component.package_url.as_deref(),
            )
        })
        .collect::<Vec<_>>();

    assert_eq!(report.by_ecosystem.get("npm"), Some(&1));
    assert_eq!(report.lockfiles.len(), 2);
    assert!(components.contains(&("bun.lock", "react", Some("pkg:npm/react@18.2.0"))));
    assert!(report
        .lockfiles
        .iter()
        .any(|lockfile| lockfile.path == "bun.lock" && lockfile.sha256.starts_with("sha256:")));
    assert!(report
        .lockfiles
        .iter()
        .any(|lockfile| lockfile.path == "bun.lockb" && lockfile.sha256.starts_with("sha256:")));
    assert!(report
        .dependencies
        .iter()
        .any(|edge| edge.from == "root" && edge.to == "react" && edge.source == "bun.lock"));
    assert!(report
        .dependencies
        .iter()
        .any(|edge| edge.from == "root" && edge.to == "vite" && edge.source == "bun.lock"));
    assert!(report.dependencies.iter().any(|edge| edge.from == "react"
        && edge.to == "loose-envify"
        && edge.source == "bun.lock"));
    assert!(report
        .dependencies
        .iter()
        .any(|edge| edge.from == "react" && edge.to == "scheduler" && edge.source == "bun.lock"));
}

#[test]
fn sbom_scan_extracts_cargo_lock_dependency_edges() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("Cargo.lock"),
        r#"version = 3

[[package]]
name = "demo"
version = "0.1.0"
dependencies = [
 "serde 1.0.197",
 "tokio",
]

[[package]]
name = "serde"
version = "1.0.197"
"#,
    )
    .unwrap();

    let report = scan_sbom(temp.path(), &ScanCancellation::default()).unwrap();
    let components = report
        .components
        .iter()
        .map(|component| {
            (
                component.scope.as_str(),
                component.name.as_str(),
                component.package_url.as_deref(),
            )
        })
        .collect::<Vec<_>>();

    assert_eq!(report.by_ecosystem.get("cargo"), Some(&2));
    assert!(components.contains(&("Cargo.lock", "demo", Some("pkg:cargo/demo@0.1.0"))));
    assert!(components.contains(&("Cargo.lock", "serde", Some("pkg:cargo/serde@1.0.197"))));
    assert!(report
        .dependencies
        .iter()
        .any(|edge| edge.from == "demo" && edge.to == "serde" && edge.source == "Cargo.lock"));
    assert!(report
        .dependencies
        .iter()
        .any(|edge| edge.from == "demo" && edge.to == "tokio" && edge.source == "Cargo.lock"));
}

#[test]
fn sbom_scan_extracts_cargo_workspace_dependencies() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("Cargo.toml"),
        r#"[workspace]
members = ["crates/app"]

[workspace.dependencies]
anyhow = "1"
serde = { version = "1.0" }
"#,
    )
    .unwrap();

    let report = scan_sbom(temp.path(), &ScanCancellation::default()).unwrap();
    let scoped_names = report
        .components
        .iter()
        .map(|component| {
            (
                component.scope.as_str(),
                component.name.as_str(),
                component.package_url.as_deref(),
            )
        })
        .collect::<Vec<_>>();

    assert_eq!(report.by_ecosystem.get("cargo"), Some(&2));
    assert!(scoped_names.contains(&(
        "workspace.dependencies",
        "anyhow",
        Some("pkg:cargo/anyhow@1")
    )));
    assert!(scoped_names.contains(&(
        "workspace.dependencies",
        "serde",
        Some("pkg:cargo/serde@1.0")
    )));
    assert!(report
        .dependencies
        .iter()
        .any(|edge| edge.from == "root" && edge.to == "anyhow" && edge.source == "Cargo.toml"));
    assert!(report
        .dependencies
        .iter()
        .any(|edge| edge.from == "root" && edge.to == "serde" && edge.source == "Cargo.toml"));
}

#[test]
fn sbom_scan_extracts_cargo_target_dependencies() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("Cargo.toml"),
        r#"[target.'cfg(unix)'.dependencies]
nix = "0.29"

[target.'cfg(windows)'.dev-dependencies]
winapi = { version = "0.3" }
"#,
    )
    .unwrap();

    let report = scan_sbom(temp.path(), &ScanCancellation::default()).unwrap();
    let scoped_names = report
        .components
        .iter()
        .map(|component| {
            (
                component.scope.as_str(),
                component.name.as_str(),
                component.package_url.as_deref(),
            )
        })
        .collect::<Vec<_>>();

    assert_eq!(report.by_ecosystem.get("cargo"), Some(&2));
    assert!(scoped_names.contains(&(
        "target.cfg(unix).dependencies",
        "nix",
        Some("pkg:cargo/nix@0.29")
    )));
    assert!(scoped_names.contains(&(
        "target.cfg(windows).dev-dependencies",
        "winapi",
        Some("pkg:cargo/winapi@0.3")
    )));
    assert!(report
        .dependencies
        .iter()
        .any(|edge| edge.from == "root" && edge.to == "nix" && edge.source == "Cargo.toml"));
    assert!(report
        .dependencies
        .iter()
        .any(|edge| edge.from == "root" && edge.to == "winapi" && edge.source == "Cargo.toml"));
}

#[test]
fn sbom_scan_extracts_composer_dependencies() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("composer.json"),
        r#"{
  "require": {
    "php": "^8.2",
    "symfony/http-foundation": "^7.0"
  },
  "require-dev": {
    "phpunit/phpunit": "^11.0"
  }
}"#,
    )
    .unwrap();

    let report = scan_sbom(temp.path(), &ScanCancellation::default()).unwrap();
    let scoped_names = report
        .components
        .iter()
        .map(|component| {
            (
                component.scope.as_str(),
                component.name.as_str(),
                component.package_url.as_deref(),
            )
        })
        .collect::<Vec<_>>();

    assert_eq!(report.manifests_scanned, 1);
    assert_eq!(report.by_ecosystem.get("composer"), Some(&2));
    assert!(scoped_names.contains(&(
        "require",
        "symfony/http-foundation",
        Some("pkg:composer/symfony/http-foundation")
    )));
    assert!(scoped_names.contains(&(
        "require-dev",
        "phpunit/phpunit",
        Some("pkg:composer/phpunit/phpunit")
    )));
    assert!(!scoped_names.iter().any(|(_, name, _)| *name == "php"));
    assert!(report.dependencies.iter().any(|edge| edge.from == "root"
        && edge.to == "symfony/http-foundation"
        && edge.source == "composer.json"));
    assert!(report.dependencies.iter().any(|edge| edge.from == "root"
        && edge.to == "phpunit/phpunit"
        && edge.source == "composer.json"));
    assert!(!report
        .dependencies
        .iter()
        .any(|edge| edge.from == "root" && edge.to == "php" && edge.source == "composer.json"));
}

#[test]
fn sbom_scan_extracts_composer_lock_package_edges() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("composer.lock"),
        r#"{
  "packages": [
    {
      "name": "symfony/http-foundation",
      "version": "v7.0.0",
      "require": {
        "php": ">=8.2",
        "symfony/polyfill-mbstring": "^1.0",
        "ext-json": "*"
      }
    },
    {"name": "symfony/polyfill-mbstring", "version": "v1.30.0"}
  ],
  "packages-dev": [
    {
      "name": "phpunit/phpunit",
      "version": "11.0.0",
      "require": {
        "sebastian/version": "^5.0",
        "composer-runtime-api": "^2.2"
      }
    },
    {"name": "sebastian/version", "version": "5.0.0"}
  ]
}"#,
    )
    .unwrap();

    let report = scan_sbom(temp.path(), &ScanCancellation::default()).unwrap();
    let components = report
        .components
        .iter()
        .map(|component| {
            (
                component.scope.as_str(),
                component.name.as_str(),
                component.package_url.as_deref(),
            )
        })
        .collect::<Vec<_>>();

    assert_eq!(report.lockfiles.len(), 1);
    assert_eq!(report.by_ecosystem.get("composer"), Some(&4));
    assert!(components.contains(&(
        "composer.lock.packages",
        "symfony/http-foundation",
        Some("pkg:composer/symfony/http-foundation@v7.0.0")
    )));
    assert!(components.contains(&(
        "composer.lock.packages-dev",
        "phpunit/phpunit",
        Some("pkg:composer/phpunit/phpunit@11.0.0")
    )));
    assert!(
        report
            .lockfiles
            .iter()
            .any(|lockfile| lockfile.path == "composer.lock"
                && lockfile.sha256.starts_with("sha256:"))
    );
    assert!(report.dependencies.iter().any(|edge| edge.from == "root"
        && edge.to == "symfony/http-foundation"
        && edge.source == "composer.lock"));
    assert!(report.dependencies.iter().any(|edge| edge.from == "root"
        && edge.to == "phpunit/phpunit"
        && edge.source == "composer.lock"));
    assert!(report
        .dependencies
        .iter()
        .any(|edge| edge.from == "symfony/http-foundation"
            && edge.to == "symfony/polyfill-mbstring"
            && edge.source == "composer.lock"));
    assert!(report
        .dependencies
        .iter()
        .any(|edge| edge.from == "phpunit/phpunit"
            && edge.to == "sebastian/version"
            && edge.source == "composer.lock"));
    assert!(!report
        .dependencies
        .iter()
        .any(|edge| edge.from == "symfony/http-foundation"
            && edge.to == "php"
            && edge.source == "composer.lock"));
    assert!(!report
        .dependencies
        .iter()
        .any(|edge| edge.from == "symfony/http-foundation"
            && edge.to == "ext-json"
            && edge.source == "composer.lock"));
    assert!(!report
        .dependencies
        .iter()
        .any(|edge| edge.from == "phpunit/phpunit"
            && edge.to == "composer-runtime-api"
            && edge.source == "composer.lock"));
}

#[test]
fn sbom_scan_extracts_gemfile_lock_dependency_edges() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("Gemfile.lock"),
        r#"GEM
  specs:
    rails (7.1.0)
      actionpack (= 7.1.0)
    actionpack (7.1.0)
      rack (~> 3.0)
    rack (3.0.8)
    rspec (3.12.0)
      rspec-core (~> 3.12.0)
    rspec-core (3.12.2)

DEPENDENCIES
  rails (~> 7.1)
  rspec!

BUNDLED WITH
   2.5.0
"#,
    )
    .unwrap();

    let report = scan_sbom(temp.path(), &ScanCancellation::default()).unwrap();
    let components = report
        .components
        .iter()
        .map(|component| {
            (
                component.scope.as_str(),
                component.name.as_str(),
                component.package_url.as_deref(),
            )
        })
        .collect::<Vec<_>>();

    assert_eq!(report.lockfiles.len(), 1);
    assert_eq!(report.by_ecosystem.get("gem"), Some(&5));
    assert!(components.contains(&("Gemfile.lock", "rails", Some("pkg:gem/rails@7.1.0"))));
    assert!(components.contains(&(
        "Gemfile.lock",
        "actionpack",
        Some("pkg:gem/actionpack@7.1.0")
    )));
    assert!(components.contains(&("Gemfile.lock", "rack", Some("pkg:gem/rack@3.0.8"))));
    assert!(report
        .lockfiles
        .iter()
        .any(|lockfile| lockfile.path == "Gemfile.lock" && lockfile.sha256.starts_with("sha256:")));
    assert!(report
        .dependencies
        .iter()
        .any(|edge| edge.from == "root" && edge.to == "rails" && edge.source == "Gemfile.lock"));
    assert!(report
        .dependencies
        .iter()
        .any(|edge| edge.from == "root" && edge.to == "rspec" && edge.source == "Gemfile.lock"));
    assert!(report.dependencies.iter().any(|edge| edge.from == "rails"
        && edge.to == "actionpack"
        && edge.source == "Gemfile.lock"));
    assert!(report
        .dependencies
        .iter()
        .any(|edge| edge.from == "actionpack"
            && edge.to == "rack"
            && edge.source == "Gemfile.lock"));
    assert!(report.dependencies.iter().any(|edge| edge.from == "rspec"
        && edge.to == "rspec-core"
        && edge.source == "Gemfile.lock"));
}

#[test]
fn sbom_scan_extracts_gemfile_dependencies() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("Gemfile"),
        r#"source "https://rubygems.org"

gem "rails", "~> 7.1"
gem 'rspec'
"#,
    )
    .unwrap();

    let report = scan_sbom(temp.path(), &ScanCancellation::default()).unwrap();
    let scoped_names = report
        .components
        .iter()
        .map(|component| {
            (
                component.scope.as_str(),
                component.name.as_str(),
                component.package_url.as_deref(),
            )
        })
        .collect::<Vec<_>>();

    assert_eq!(report.manifests_scanned, 1);
    assert_eq!(report.by_ecosystem.get("gem"), Some(&2));
    assert!(scoped_names.contains(&("gem", "rails", Some("pkg:gem/rails"))));
    assert!(scoped_names.contains(&("gem", "rspec", Some("pkg:gem/rspec"))));
    assert!(report
        .dependencies
        .iter()
        .any(|edge| edge.from == "root" && edge.to == "rails" && edge.source == "Gemfile"));
    assert!(report
        .dependencies
        .iter()
        .any(|edge| edge.from == "root" && edge.to == "rspec" && edge.source == "Gemfile"));
}

#[test]
fn sbom_scan_extracts_maven_pom_dependencies() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("pom.xml"),
        r#"
<project>
  <dependencies>
    <dependency>
      <groupId>org.slf4j</groupId>
      <artifactId>slf4j-api</artifactId>
      <version>1.7.36</version>
    </dependency>
    <dependency>
      <groupId>junit</groupId>
      <artifactId>junit</artifactId>
      <version>${junit.version}</version>
      <scope>test</scope>
    </dependency>
  </dependencies>
</project>
"#,
    )
    .unwrap();

    let report = scan_sbom(temp.path(), &ScanCancellation::default()).unwrap();
    let scoped_names = report
        .components
        .iter()
        .map(|component| {
            (
                component.scope.as_str(),
                component.name.as_str(),
                component.package_url.as_deref(),
            )
        })
        .collect::<Vec<_>>();

    assert_eq!(report.manifests_scanned, 1);
    assert_eq!(report.by_ecosystem.get("maven"), Some(&2));
    assert!(report.dependencies.iter().any(|edge| edge.from == "root"
        && edge.to == "org.slf4j/slf4j-api"
        && edge.source == "pom.xml"));
    assert!(report
        .dependencies
        .iter()
        .any(|edge| edge.from == "root" && edge.to == "junit/junit" && edge.source == "pom.xml"));
    assert!(scoped_names.contains(&(
        "dependencies",
        "org.slf4j/slf4j-api",
        Some("pkg:maven/org.slf4j/slf4j-api@1.7.36")
    )));
    assert!(scoped_names.contains(&(
        "dependencies.test",
        "junit/junit",
        Some("pkg:maven/junit/junit")
    )));
}

#[test]
fn sbom_scan_extracts_dotnet_project_dependencies() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("App.csproj"),
        r#"
<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="13.0.3" />
    <PackageReference Include="Serilog">
      <Version>3.1.1</Version>
    </PackageReference>
  </ItemGroup>
</Project>
"#,
    )
    .unwrap();

    let report = scan_sbom(temp.path(), &ScanCancellation::default()).unwrap();
    let scoped_names = report
        .components
        .iter()
        .map(|component| {
            (
                component.scope.as_str(),
                component.name.as_str(),
                component.package_url.as_deref(),
            )
        })
        .collect::<Vec<_>>();

    assert_eq!(report.manifests_scanned, 1);
    assert_eq!(report.by_ecosystem.get("nuget"), Some(&2));
    assert!(report.dependencies.iter().any(|edge| edge.from == "root"
        && edge.to == "Newtonsoft.Json"
        && edge.source == "App.csproj"));
    assert!(report
        .dependencies
        .iter()
        .any(|edge| edge.from == "root" && edge.to == "Serilog" && edge.source == "App.csproj"));
    assert!(scoped_names.contains(&(
        "PackageReference",
        "Newtonsoft.Json",
        Some("pkg:nuget/Newtonsoft.Json@13.0.3")
    )));
    assert!(scoped_names.contains(&(
        "PackageReference",
        "Serilog",
        Some("pkg:nuget/Serilog@3.1.1")
    )));
}

#[test]
fn sbom_scan_extracts_fsharp_project_dependencies() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("Library.fsproj"),
        r#"
<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="FSharp.Data" Version="6.4.0" />
  </ItemGroup>
</Project>
"#,
    )
    .unwrap();

    let report = scan_sbom(temp.path(), &ScanCancellation::default()).unwrap();

    assert_eq!(report.manifests_scanned, 1);
    assert_eq!(report.by_ecosystem.get("nuget"), Some(&1));
    assert!(report
        .components
        .iter()
        .any(|component| component.name == "FSharp.Data"
            && component.manifest_path == "Library.fsproj"
            && component.package_url.as_deref() == Some("pkg:nuget/FSharp.Data@6.4.0")));
    assert!(report.dependencies.iter().any(|edge| edge.from == "root"
        && edge.to == "FSharp.Data"
        && edge.source == "Library.fsproj"));
}

#[test]
fn sbom_scan_extracts_nuget_lock_dependency_edges() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("packages.lock.json"),
        r#"{
  "version": 1,
  "dependencies": {
    "net8.0": {
      "Newtonsoft.Json": {
        "type": "Direct",
        "requested": "[13.0.3, )",
        "resolved": "13.0.3",
        "contentHash": "sha512-demo",
        "dependencies": {
          "System.Runtime.CompilerServices.Unsafe": "6.0.0"
        }
      },
      "System.Runtime.CompilerServices.Unsafe": {
        "type": "Transitive",
        "resolved": "6.0.0",
        "contentHash": "sha512-demo"
      }
    }
  }
}"#,
    )
    .unwrap();

    let report = scan_sbom(temp.path(), &ScanCancellation::default()).unwrap();
    let components = report
        .components
        .iter()
        .map(|component| {
            (
                component.scope.as_str(),
                component.name.as_str(),
                component.package_url.as_deref(),
            )
        })
        .collect::<Vec<_>>();

    assert_eq!(report.lockfiles.len(), 1);
    assert_eq!(report.by_ecosystem.get("nuget"), Some(&2));
    assert!(components.contains(&(
        "packages.lock.json.net8.0",
        "Newtonsoft.Json",
        Some("pkg:nuget/Newtonsoft.Json@13.0.3")
    )));
    assert!(components.contains(&(
        "packages.lock.json.net8.0",
        "System.Runtime.CompilerServices.Unsafe",
        Some("pkg:nuget/System.Runtime.CompilerServices.Unsafe@6.0.0")
    )));
    assert!(report
        .lockfiles
        .iter()
        .any(|lockfile| lockfile.path == "packages.lock.json"
            && lockfile.sha256.starts_with("sha256:")));
    assert!(report.dependencies.iter().any(|edge| edge.from == "root"
        && edge.to == "Newtonsoft.Json"
        && edge.source == "packages.lock.json"));
    assert!(report
        .dependencies
        .iter()
        .any(|edge| edge.from == "Newtonsoft.Json"
            && edge.to == "System.Runtime.CompilerServices.Unsafe"
            && edge.source == "packages.lock.json"));
}

#[test]
fn sbom_scan_extracts_swift_package_resolved_edges() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("Package.resolved"),
        r#"{
  "pins": [
    {
      "identity": "alamofire",
      "kind": "remoteSourceControl",
      "location": "https://github.com/Alamofire/Alamofire.git",
      "state": {
        "revision": "abc123",
        "version": "5.8.1"
      }
    },
    {
      "package": "swift-argument-parser",
      "repositoryURL": "https://github.com/apple/swift-argument-parser.git",
      "state": {
        "branch": null,
        "revision": "def456",
        "version": "1.3.0"
      }
    }
  ],
  "version": 2
}"#,
    )
    .unwrap();

    let report = scan_sbom(temp.path(), &ScanCancellation::default()).unwrap();
    let components = report
        .components
        .iter()
        .map(|component| {
            (
                component.scope.as_str(),
                component.name.as_str(),
                component.package_url.as_deref(),
            )
        })
        .collect::<Vec<_>>();

    assert_eq!(report.by_ecosystem.get("swift"), Some(&2));
    assert_eq!(report.lockfiles.len(), 1);
    assert!(report
        .lockfiles
        .iter()
        .any(|lockfile| lockfile.path == "Package.resolved"
            && lockfile.sha256.starts_with("sha256:")));
    assert!(components.contains(&(
        "Package.resolved",
        "alamofire",
        Some("pkg:generic/alamofire@5.8.1"),
    )));
    assert!(components.contains(&(
        "Package.resolved",
        "swift-argument-parser",
        Some("pkg:generic/swift-argument-parser@1.3.0"),
    )));
    assert!(report.dependencies.iter().any(|edge| edge.from == "root"
        && edge.to == "alamofire"
        && edge.source == "Package.resolved"));
    assert!(report.dependencies.iter().any(|edge| edge.from == "root"
        && edge.to == "swift-argument-parser"
        && edge.source == "Package.resolved"));
}

#[test]
fn sbom_scan_extracts_gradle_lockfile_edges() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("gradle.lockfile"),
        r#"# This is a Gradle dependency lockfile.
org.slf4j:slf4j-api:1.7.36=compileClasspath,runtimeClasspath
junit:junit:4.13.2=testCompileClasspath,testRuntimeClasspath
empty=ignored
"#,
    )
    .unwrap();

    let report = scan_sbom(temp.path(), &ScanCancellation::default()).unwrap();
    let components = report
        .components
        .iter()
        .map(|component| {
            (
                component.scope.as_str(),
                component.name.as_str(),
                component.package_url.as_deref(),
            )
        })
        .collect::<Vec<_>>();

    assert_eq!(report.by_ecosystem.get("maven"), Some(&2));
    assert_eq!(report.lockfiles.len(), 1);
    assert!(report.lockfiles.iter().any(
        |lockfile| lockfile.path == "gradle.lockfile" && lockfile.sha256.starts_with("sha256:")
    ));
    assert!(components.contains(&(
        "gradle.lockfile",
        "org.slf4j/slf4j-api",
        Some("pkg:maven/org.slf4j/slf4j-api@1.7.36"),
    )));
    assert!(components.contains(&(
        "gradle.lockfile",
        "junit/junit",
        Some("pkg:maven/junit/junit@4.13.2"),
    )));
    assert!(report.dependencies.iter().any(|edge| edge.from == "root"
        && edge.to == "org.slf4j/slf4j-api"
        && edge.source == "gradle.lockfile"));
    assert!(report.dependencies.iter().any(|edge| edge.from == "root"
        && edge.to == "junit/junit"
        && edge.source == "gradle.lockfile"));
    assert!(!report.dependencies.iter().any(|edge| edge.to == "empty"));
}

#[test]
fn sbom_scan_extracts_gradle_build_dependencies() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("build.gradle.kts"),
        r#"
plugins {
    java
}

dependencies {
    implementation("org.springframework.boot:spring-boot-starter-web:3.2.1")
    testImplementation("org.junit.jupiter:junit-jupiter:5.10.1")
    runtimeOnly("org.postgresql:postgresql")
    constraints {
        implementation("com.fasterxml.jackson.core:jackson-databind:2.16.1")
    }
}
"#,
    )
    .unwrap();

    let report = scan_sbom(temp.path(), &ScanCancellation::default()).unwrap();
    let components = report
        .components
        .iter()
        .map(|component| {
            (
                component.scope.as_str(),
                component.name.as_str(),
                component.package_url.as_deref(),
            )
        })
        .collect::<Vec<_>>();

    assert_eq!(report.manifests_scanned, 1);
    assert_eq!(report.by_ecosystem.get("maven"), Some(&4));
    assert!(components.contains(&(
        "implementation",
        "org.springframework.boot/spring-boot-starter-web",
        Some("pkg:maven/org.springframework.boot/spring-boot-starter-web@3.2.1")
    )));
    assert!(components.contains(&(
        "testImplementation",
        "org.junit.jupiter/junit-jupiter",
        Some("pkg:maven/org.junit.jupiter/junit-jupiter@5.10.1")
    )));
    assert!(components.contains(&(
        "runtimeOnly",
        "org.postgresql/postgresql",
        Some("pkg:maven/org.postgresql/postgresql")
    )));
    assert!(report.dependencies.iter().any(|edge| edge.from == "root"
        && edge.to == "org.springframework.boot/spring-boot-starter-web"
        && edge.source == "build.gradle.kts"));
    assert!(report.dependencies.iter().any(|edge| edge.from == "root"
        && edge.to == "com.fasterxml.jackson.core/jackson-databind"
        && edge.source == "build.gradle.kts"));
}

#[test]
fn sbom_scan_extracts_gradle_groovy_map_dependencies() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("build.gradle"),
        r#"
dependencies {
    implementation 'org.slf4j:slf4j-api:2.0.12'
    api group: 'com.google.guava', name: 'guava', version: '33.0.0-jre'
    compileOnly group: 'jakarta.servlet', name: 'jakarta.servlet-api'
    apiElements("ignored:configuration:1.0.0")
}
"#,
    )
    .unwrap();

    let report = scan_sbom(temp.path(), &ScanCancellation::default()).unwrap();

    assert_eq!(report.manifests_scanned, 1);
    assert_eq!(report.by_ecosystem.get("maven"), Some(&3));
    assert!(report
        .components
        .iter()
        .any(|component| component.scope == "api"
            && component.name == "com.google.guava/guava"
            && component.package_url.as_deref()
                == Some("pkg:maven/com.google.guava/guava@33.0.0-jre")));
    assert!(report
        .components
        .iter()
        .any(|component| component.scope == "compileOnly"
            && component.name == "jakarta.servlet/jakarta.servlet-api"
            && component.package_url.as_deref()
                == Some("pkg:maven/jakarta.servlet/jakarta.servlet-api")));
    assert!(report.dependencies.iter().any(|edge| edge.from == "root"
        && edge.to == "org.slf4j/slf4j-api"
        && edge.source == "build.gradle"));
    assert!(!report
        .dependencies
        .iter()
        .any(|edge| edge.to == "ignored/configuration"));
}

#[test]
fn sbom_scan_extracts_renv_lock_package_edges() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("renv.lock"),
        r#"{
  "R": {
    "Version": "4.3.2",
    "Repositories": [
      {
        "Name": "CRAN",
        "URL": "https://cloud.r-project.org"
      }
    ]
  },
  "Packages": {
    "dplyr": {
      "Package": "dplyr",
      "Version": "1.1.4",
      "Depends": "R (>= 3.5.0)",
      "Imports": "rlang (>= 1.1.0), tibble",
      "Suggests": "testthat"
    },
    "rlang": {
      "Package": "rlang",
      "Version": "1.1.3"
    },
    "tibble": {
      "Package": "tibble",
      "Version": "3.2.1"
    },
    "testthat": {
      "Package": "testthat",
      "Version": "3.2.1"
    }
  }
}"#,
    )
    .unwrap();

    let report = scan_sbom(temp.path(), &ScanCancellation::default()).unwrap();
    let components = report
        .components
        .iter()
        .map(|component| {
            (
                component.scope.as_str(),
                component.name.as_str(),
                component.package_url.as_deref(),
            )
        })
        .collect::<Vec<_>>();

    assert_eq!(report.by_ecosystem.get("r"), Some(&4));
    assert_eq!(report.lockfiles.len(), 1);
    assert!(report
        .lockfiles
        .iter()
        .any(|lockfile| lockfile.path == "renv.lock" && lockfile.sha256.starts_with("sha256:")));
    assert!(components.contains(&("renv.lock", "dplyr", Some("pkg:cran/dplyr@1.1.4"))));
    assert!(components.contains(&("renv.lock", "rlang", Some("pkg:cran/rlang@1.1.3"))));
    assert!(components.contains(&("renv.lock", "tibble", Some("pkg:cran/tibble@3.2.1"))));
    assert!(components.contains(&("renv.lock", "testthat", Some("pkg:cran/testthat@3.2.1"),)));
    assert!(report
        .dependencies
        .iter()
        .any(|edge| edge.from == "root" && edge.to == "dplyr" && edge.source == "renv.lock"));
    assert!(report
        .dependencies
        .iter()
        .any(|edge| edge.from == "root" && edge.to == "rlang" && edge.source == "renv.lock"));
    assert!(report
        .dependencies
        .iter()
        .any(|edge| edge.from == "dplyr" && edge.to == "rlang" && edge.source == "renv.lock"));
    assert!(report
        .dependencies
        .iter()
        .any(|edge| edge.from == "dplyr" && edge.to == "tibble" && edge.source == "renv.lock"));
    assert!(report
        .dependencies
        .iter()
        .any(|edge| edge.from == "dplyr" && edge.to == "testthat" && edge.source == "renv.lock"));
    assert!(!report
        .dependencies
        .iter()
        .any(|edge| edge.from == "dplyr" && edge.to == "R" && edge.source == "renv.lock"));
}

#[test]
fn sbom_scan_extracts_podfile_lock_dependency_edges() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("Podfile.lock"),
        r#"PODS:
  - Alamofire (5.8.1)
  - Firebase/Auth (10.22.0):
    - Firebase/CoreOnly
    - GoogleUtilities/AppDelegateSwizzler (~> 7.11)
  - Firebase/CoreOnly (10.22.0)
  - GoogleUtilities/AppDelegateSwizzler (7.13.0)

DEPENDENCIES:
  - Alamofire (~> 5.8)
  - Firebase/Auth

SPEC CHECKSUMS:
  Alamofire: abc123
"#,
    )
    .unwrap();

    let report = scan_sbom(temp.path(), &ScanCancellation::default()).unwrap();
    let components = report
        .components
        .iter()
        .map(|component| {
            (
                component.scope.as_str(),
                component.name.as_str(),
                component.package_url.as_deref(),
            )
        })
        .collect::<Vec<_>>();

    assert_eq!(report.by_ecosystem.get("cocoapods"), Some(&4));
    assert_eq!(report.lockfiles.len(), 1);
    assert!(report
        .lockfiles
        .iter()
        .any(|lockfile| lockfile.path == "Podfile.lock" && lockfile.sha256.starts_with("sha256:")));
    assert!(components.contains(&(
        "Podfile.lock",
        "Alamofire",
        Some("pkg:generic/Alamofire@5.8.1"),
    )));
    assert!(components.contains(&(
        "Podfile.lock",
        "Firebase/Auth",
        Some("pkg:generic/Firebase/Auth@10.22.0"),
    )));
    assert!(components.contains(&(
        "Podfile.lock",
        "Firebase/CoreOnly",
        Some("pkg:generic/Firebase/CoreOnly@10.22.0"),
    )));
    assert!(components.contains(&(
        "Podfile.lock",
        "GoogleUtilities/AppDelegateSwizzler",
        Some("pkg:generic/GoogleUtilities/AppDelegateSwizzler@7.13.0"),
    )));
    assert!(report.dependencies.iter().any(|edge| edge.from == "root"
        && edge.to == "Alamofire"
        && edge.source == "Podfile.lock"));
    assert!(report.dependencies.iter().any(|edge| edge.from == "root"
        && edge.to == "Firebase/Auth"
        && edge.source == "Podfile.lock"));
    assert!(report
        .dependencies
        .iter()
        .any(|edge| edge.from == "Firebase/Auth"
            && edge.to == "Firebase/CoreOnly"
            && edge.source == "Podfile.lock"));
    assert!(report
        .dependencies
        .iter()
        .any(|edge| edge.from == "Firebase/Auth"
            && edge.to == "GoogleUtilities/AppDelegateSwizzler"
            && edge.source == "Podfile.lock"));
    assert!(!report.dependencies.iter().any(|edge| edge.from == "root"
        && edge.to == "Firebase/CoreOnly"
        && edge.source == "Podfile.lock"));
}

#[test]
fn sbom_scan_extracts_cartfile_resolved_edges() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("Cartfile.resolved"),
        r#"github "Alamofire/Alamofire" "5.8.1"
git "https://github.com/ReactiveX/RxSwift.git" "6.6.0"
binary "https://example.com/Foo.json" "1.0.0"
"#,
    )
    .unwrap();

    let report = scan_sbom(temp.path(), &ScanCancellation::default()).unwrap();
    let components = report
        .components
        .iter()
        .map(|component| {
            (
                component.scope.as_str(),
                component.name.as_str(),
                component.package_url.as_deref(),
            )
        })
        .collect::<Vec<_>>();

    assert_eq!(report.by_ecosystem.get("carthage"), Some(&3));
    assert_eq!(report.lockfiles.len(), 1);
    assert!(report
        .lockfiles
        .iter()
        .any(|lockfile| lockfile.path == "Cartfile.resolved"
            && lockfile.sha256.starts_with("sha256:")));
    assert!(components.contains(&(
        "Cartfile.resolved",
        "Alamofire/Alamofire",
        Some("pkg:generic/Alamofire/Alamofire@5.8.1"),
    )));
    assert!(components.contains(&(
        "Cartfile.resolved",
        "https://github.com/ReactiveX/RxSwift.git",
        Some("pkg:generic/https://github.com/ReactiveX/RxSwift.git@6.6.0"),
    )));
    assert!(components.contains(&(
        "Cartfile.resolved",
        "https://example.com/Foo.json",
        Some("pkg:generic/https://example.com/Foo.json@1.0.0"),
    )));
    assert!(report.dependencies.iter().any(|edge| edge.from == "root"
        && edge.to == "Alamofire/Alamofire"
        && edge.source == "Cartfile.resolved"));
    assert!(report.dependencies.iter().any(|edge| edge.from == "root"
        && edge.to == "https://github.com/ReactiveX/RxSwift.git"
        && edge.source == "Cartfile.resolved"));
    assert!(report.dependencies.iter().any(|edge| edge.from == "root"
        && edge.to == "https://example.com/Foo.json"
        && edge.source == "Cartfile.resolved"));
}

#[test]
fn sbom_scan_extracts_helm_chart_lock_edges() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("Chart.lock"),
        r#"dependencies:
  - name: postgresql
    repository: https://charts.bitnami.com/bitnami
    version: 13.2.24
  - name: redis
    repository: https://charts.bitnami.com/bitnami
    version: 18.6.1
digest: sha256:demo
generated: "2024-01-01T00:00:00.000000-00:00"
"#,
    )
    .unwrap();

    let report = scan_sbom(temp.path(), &ScanCancellation::default()).unwrap();
    let components = report
        .components
        .iter()
        .map(|component| {
            (
                component.scope.as_str(),
                component.name.as_str(),
                component.package_url.as_deref(),
            )
        })
        .collect::<Vec<_>>();

    assert_eq!(report.by_ecosystem.get("helm"), Some(&2));
    assert_eq!(report.lockfiles.len(), 1);
    assert!(report
        .lockfiles
        .iter()
        .any(|lockfile| lockfile.path == "Chart.lock" && lockfile.sha256.starts_with("sha256:")));
    assert!(components.contains(&(
        "Chart.lock",
        "postgresql",
        Some("pkg:helm/postgresql@13.2.24"),
    )));
    assert!(components.contains(&("Chart.lock", "redis", Some("pkg:helm/redis@18.6.1"),)));
    assert!(report
        .dependencies
        .iter()
        .any(|edge| edge.from == "root" && edge.to == "postgresql" && edge.source == "Chart.lock"));
    assert!(report
        .dependencies
        .iter()
        .any(|edge| edge.from == "root" && edge.to == "redis" && edge.source == "Chart.lock"));
}

#[test]
fn sbom_scan_extracts_helm_chart_dependencies() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("Chart.yaml"),
        r#"apiVersion: v2
name: app
version: 0.1.0
dependencies:
  - name: postgresql
    version: 13.2.24
    repository: https://charts.bitnami.com/bitnami
  - name: redis
    version: ">=18.0.0"
    repository: https://charts.bitnami.com/bitnami
"#,
    )
    .unwrap();

    let report = scan_sbom(temp.path(), &ScanCancellation::default()).unwrap();
    let scoped_names = report
        .components
        .iter()
        .map(|component| {
            (
                component.scope.as_str(),
                component.name.as_str(),
                component.package_url.as_deref(),
            )
        })
        .collect::<Vec<_>>();

    assert_eq!(report.manifests_scanned, 1);
    assert_eq!(report.by_ecosystem.get("helm"), Some(&2));
    assert!(scoped_names.contains(&(
        "dependencies",
        "postgresql",
        Some("pkg:helm/postgresql@13.2.24")
    )));
    assert!(scoped_names.contains(&("dependencies", "redis", Some("pkg:helm/redis"))));
    assert!(report
        .dependencies
        .iter()
        .any(|edge| edge.from == "root" && edge.to == "postgresql" && edge.source == "Chart.yaml"));
    assert!(report
        .dependencies
        .iter()
        .any(|edge| edge.from == "root" && edge.to == "redis" && edge.source == "Chart.yaml"));
}

#[test]
fn sbom_scan_extracts_elm_json_dependencies() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("elm.json"),
        r#"{
  "type": "application",
  "source-directories": ["src"],
  "elm-version": "0.19.1",
  "dependencies": {
    "direct": {
      "elm/core": "1.0.5",
      "elm/http": "2.0.0"
    },
    "indirect": {
      "elm/json": "1.1.3"
    }
  },
  "test-dependencies": {
    "direct": {
      "elm-explorations/test": "2.0.1"
    },
    "indirect": {}
  }
}"#,
    )
    .unwrap();

    let report = scan_sbom(temp.path(), &ScanCancellation::default()).unwrap();
    let scoped_names = report
        .components
        .iter()
        .map(|component| {
            (
                component.scope.as_str(),
                component.name.as_str(),
                component.package_url.as_deref(),
            )
        })
        .collect::<Vec<_>>();

    assert_eq!(report.manifests_scanned, 1);
    assert_eq!(report.by_ecosystem.get("elm"), Some(&4));
    assert!(scoped_names.contains(&(
        "dependencies.direct",
        "elm/core",
        Some("pkg:elm/elm/core@1.0.5")
    )));
    assert!(scoped_names.contains(&(
        "dependencies.indirect",
        "elm/json",
        Some("pkg:elm/elm/json@1.1.3")
    )));
    assert!(scoped_names.contains(&(
        "test-dependencies.direct",
        "elm-explorations/test",
        Some("pkg:elm/elm-explorations/test@2.0.1")
    )));
    assert!(report
        .dependencies
        .iter()
        .any(|edge| edge.from == "root" && edge.to == "elm/core" && edge.source == "elm.json"));
    assert!(!report
        .dependencies
        .iter()
        .any(|edge| edge.from == "root" && edge.to == "elm/json"));
}

#[test]
fn sbom_scan_extracts_elm_package_json_dependencies() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("elm.json"),
        r#"{
  "type": "package",
  "name": "example/demo",
  "summary": "demo",
  "license": "BSD-3-Clause",
  "version": "1.0.0",
  "exposed-modules": [],
  "elm-version": "0.19.0 <= v < 0.20.0",
  "dependencies": {
    "elm/core": "1.0.0 <= v < 2.0.0"
  },
  "test-dependencies": {}
}"#,
    )
    .unwrap();

    let report = scan_sbom(temp.path(), &ScanCancellation::default()).unwrap();

    assert_eq!(report.manifests_scanned, 1);
    assert_eq!(report.by_ecosystem.get("elm"), Some(&1));
    assert!(report
        .components
        .iter()
        .any(|component| component.name == "elm/core"
            && component.scope == "dependencies"
            && component.package_url.as_deref() == Some("pkg:elm/elm/core")));
    assert!(report
        .dependencies
        .iter()
        .any(|edge| edge.from == "root" && edge.to == "elm/core" && edge.source == "elm.json"));
}

#[test]
fn sbom_scan_extracts_julia_project_dependencies() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("Project.toml"),
        r#"
name = "Demo"
uuid = "11111111-1111-1111-1111-111111111111"
version = "0.1.0"

[deps]
DataFrames = "a93c6f00-e57d-5684-b7b6-d8193f3e46c0"
JSON = "682c06a0-de6a-54ab-a142-c8b1cf79cde6"
"#,
    )
    .unwrap();

    let report = scan_sbom(temp.path(), &ScanCancellation::default()).unwrap();
    let scoped_names = report
        .components
        .iter()
        .map(|component| {
            (
                component.scope.as_str(),
                component.name.as_str(),
                component.package_url.as_deref(),
            )
        })
        .collect::<Vec<_>>();

    assert_eq!(report.manifests_scanned, 1);
    assert_eq!(report.by_ecosystem.get("julia"), Some(&2));
    assert!(scoped_names.contains(&("deps", "DataFrames", Some("pkg:julia/DataFrames"))));
    assert!(scoped_names.contains(&("deps", "JSON", Some("pkg:julia/JSON"))));
    assert!(report.dependencies.iter().any(|edge| edge.from == "root"
        && edge.to == "DataFrames"
        && edge.source == "Project.toml"));
    assert!(report
        .dependencies
        .iter()
        .any(|edge| edge.from == "root" && edge.to == "JSON" && edge.source == "Project.toml"));
}

#[test]
fn sbom_scan_extracts_conanfile_dependencies() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("conanfile.txt"),
        r#"
[requires]
fmt/10.2.1
zlib/1.3.1@conan/stable
openssl/3.2.1#recipe-revision

[generators]
CMakeDeps
"#,
    )
    .unwrap();

    let report = scan_sbom(temp.path(), &ScanCancellation::default()).unwrap();
    let scoped_names = report
        .components
        .iter()
        .map(|component| {
            (
                component.scope.as_str(),
                component.name.as_str(),
                component.version.as_deref(),
                component.package_url.as_deref(),
            )
        })
        .collect::<Vec<_>>();

    assert_eq!(report.manifests_scanned, 1);
    assert_eq!(report.by_ecosystem.get("conan"), Some(&3));
    assert!(scoped_names.contains(&(
        "requires",
        "fmt",
        Some("10.2.1"),
        Some("pkg:conan/fmt@10.2.1")
    )));
    assert!(scoped_names.contains(&(
        "requires",
        "zlib",
        Some("1.3.1"),
        Some("pkg:conan/zlib@1.3.1")
    )));
    assert!(scoped_names.contains(&(
        "requires",
        "openssl",
        Some("3.2.1"),
        Some("pkg:conan/openssl@3.2.1")
    )));
    assert!(report
        .dependencies
        .iter()
        .any(|edge| edge.from == "root" && edge.to == "fmt" && edge.source == "conanfile.txt"));
    assert!(report
        .dependencies
        .iter()
        .any(|edge| edge.from == "root" && edge.to == "openssl" && edge.source == "conanfile.txt"));
}

#[test]
fn sbom_scan_extracts_vcpkg_manifest_dependencies() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("vcpkg.json"),
        r#"{
  "name": "demo",
  "version-string": "0.1.0",
  "dependencies": [
    "fmt",
    {
      "name": "zlib",
      "features": ["tools"],
      "platform": "linux"
    }
  ]
}"#,
    )
    .unwrap();

    let report = scan_sbom(temp.path(), &ScanCancellation::default()).unwrap();
    let scoped_names = report
        .components
        .iter()
        .map(|component| {
            (
                component.scope.as_str(),
                component.name.as_str(),
                component.package_url.as_deref(),
            )
        })
        .collect::<Vec<_>>();

    assert_eq!(report.manifests_scanned, 1);
    assert_eq!(report.by_ecosystem.get("vcpkg"), Some(&2));
    assert!(scoped_names.contains(&("dependencies", "fmt", Some("pkg:generic/fmt"))));
    assert!(scoped_names.contains(&("dependencies", "zlib", Some("pkg:generic/zlib"))));
    assert!(report
        .dependencies
        .iter()
        .any(|edge| edge.from == "root" && edge.to == "fmt" && edge.source == "vcpkg.json"));
    assert!(report
        .dependencies
        .iter()
        .any(|edge| edge.from == "root" && edge.to == "zlib" && edge.source == "vcpkg.json"));
}

#[test]
fn sbom_scan_extracts_cpanfile_dependencies() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("cpanfile"),
        r#"
requires 'Mojolicious', '9.36';
requires "DBI";
test_requires 'Test::More', '1.302199';
recommends 'Optional::Module', '0.1';
"#,
    )
    .unwrap();

    let report = scan_sbom(temp.path(), &ScanCancellation::default()).unwrap();
    let scoped_names = report
        .components
        .iter()
        .map(|component| {
            (
                component.scope.as_str(),
                component.name.as_str(),
                component.version.as_deref(),
                component.package_url.as_deref(),
            )
        })
        .collect::<Vec<_>>();

    assert_eq!(report.manifests_scanned, 1);
    assert_eq!(report.by_ecosystem.get("cpan"), Some(&3));
    assert!(scoped_names.contains(&(
        "requires",
        "Mojolicious",
        Some("9.36"),
        Some("pkg:cpan/Mojolicious@9.36")
    )));
    assert!(scoped_names.contains(&(("requires", "DBI", None, Some("pkg:cpan/DBI")))));
    assert!(scoped_names.contains(&(
        "test_requires",
        "Test::More",
        Some("1.302199"),
        Some("pkg:cpan/Test::More@1.302199")
    )));
    assert!(report
        .dependencies
        .iter()
        .any(|edge| edge.from == "root" && edge.to == "Mojolicious" && edge.source == "cpanfile"));
    assert!(report
        .dependencies
        .iter()
        .any(|edge| edge.from == "root" && edge.to == "DBI" && edge.source == "cpanfile"));
}

#[test]
fn sbom_scan_extracts_opam_dependencies() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("demo.opam"),
        r#"
opam-version: "2.0"
name: "demo"
depends: [
  "ocaml" {>= "4.14"}
  "dune" {>= "3.0"}
  "yojson"
]
"#,
    )
    .unwrap();

    let report = scan_sbom(temp.path(), &ScanCancellation::default()).unwrap();
    let scoped_names = report
        .components
        .iter()
        .map(|component| {
            (
                component.scope.as_str(),
                component.name.as_str(),
                component.package_url.as_deref(),
            )
        })
        .collect::<Vec<_>>();

    assert_eq!(report.manifests_scanned, 1);
    assert_eq!(report.by_ecosystem.get("opam"), Some(&3));
    assert!(scoped_names.contains(&("depends", "ocaml", Some("pkg:generic/ocaml"))));
    assert!(scoped_names.contains(&("depends", "dune", Some("pkg:generic/dune"))));
    assert!(scoped_names.contains(&("depends", "yojson", Some("pkg:generic/yojson"))));
    assert!(report
        .dependencies
        .iter()
        .any(|edge| edge.from == "root" && edge.to == "ocaml" && edge.source == "demo.opam"));
    assert!(report
        .dependencies
        .iter()
        .any(|edge| edge.from == "root" && edge.to == "yojson" && edge.source == "demo.opam"));
}

#[test]
fn sbom_scan_extracts_cabal_dependencies() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("demo.cabal"),
        r#"
cabal-version: 3.0
name: demo

library
  exposed-modules: Demo
  build-depends:
      base >=4.14 && <5
    , text ^>=2.0
    , aeson >=2.1
  default-language: Haskell2010
"#,
    )
    .unwrap();

    let report = scan_sbom(temp.path(), &ScanCancellation::default()).unwrap();
    let scoped_names = report
        .components
        .iter()
        .map(|component| {
            (
                component.scope.as_str(),
                component.name.as_str(),
                component.package_url.as_deref(),
            )
        })
        .collect::<Vec<_>>();

    assert_eq!(report.manifests_scanned, 1);
    assert_eq!(report.by_ecosystem.get("hackage"), Some(&3));
    assert!(scoped_names.contains(&("build-depends", "base", Some("pkg:hackage/base"))));
    assert!(scoped_names.contains(&("build-depends", "text", Some("pkg:hackage/text"))));
    assert!(scoped_names.contains(&("build-depends", "aeson", Some("pkg:hackage/aeson"))));
    assert!(report
        .dependencies
        .iter()
        .any(|edge| edge.from == "root" && edge.to == "base" && edge.source == "demo.cabal"));
    assert!(report
        .dependencies
        .iter()
        .any(|edge| edge.from == "root" && edge.to == "aeson" && edge.source == "demo.cabal"));
}

#[test]
fn sbom_scan_extracts_shard_yml_dependencies() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("shard.yml"),
        r#"
name: demo
version: 0.1.0
dependencies:
  kemal:
    github: kemalcr/kemal
  pg:
    github: will/crystal-pg
development_dependencies:
  ameba:
    github: crystal-ameba/ameba
"#,
    )
    .unwrap();

    let report = scan_sbom(temp.path(), &ScanCancellation::default()).unwrap();
    let scoped_names = report
        .components
        .iter()
        .map(|component| {
            (
                component.scope.as_str(),
                component.name.as_str(),
                component.package_url.as_deref(),
            )
        })
        .collect::<Vec<_>>();

    assert_eq!(report.manifests_scanned, 1);
    assert_eq!(report.by_ecosystem.get("crystal"), Some(&3));
    assert!(scoped_names.contains(&("dependencies", "kemal", Some("pkg:generic/kemal"))));
    assert!(scoped_names.contains(&("dependencies", "pg", Some("pkg:generic/pg"))));
    assert!(scoped_names.contains(&(
        "development_dependencies",
        "ameba",
        Some("pkg:generic/ameba")
    )));
    assert!(report
        .dependencies
        .iter()
        .any(|edge| edge.from == "root" && edge.to == "kemal" && edge.source == "shard.yml"));
    assert!(report
        .dependencies
        .iter()
        .any(|edge| edge.from == "root" && edge.to == "ameba" && edge.source == "shard.yml"));
}

#[test]
fn sbom_scan_extracts_r_description_dependencies() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("DESCRIPTION"),
        r#"Package: demo
Version: 0.1.0
Depends: R (>= 4.2),
    dplyr (>= 1.1.4)
Imports: rlang,
    cli
Suggests: testthat
"#,
    )
    .unwrap();

    let report = scan_sbom(temp.path(), &ScanCancellation::default()).unwrap();
    let scoped_names = report
        .components
        .iter()
        .map(|component| {
            (
                component.scope.as_str(),
                component.name.as_str(),
                component.package_url.as_deref(),
            )
        })
        .collect::<Vec<_>>();

    assert_eq!(report.manifests_scanned, 1);
    assert_eq!(report.by_ecosystem.get("r"), Some(&4));
    assert!(scoped_names.contains(&("Depends", "dplyr", Some("pkg:cran/dplyr"))));
    assert!(scoped_names.contains(&("Imports", "rlang", Some("pkg:cran/rlang"))));
    assert!(scoped_names.contains(&("Imports", "cli", Some("pkg:cran/cli"))));
    assert!(scoped_names.contains(&("Suggests", "testthat", Some("pkg:cran/testthat"))));
    assert!(report
        .dependencies
        .iter()
        .any(|edge| edge.from == "root" && edge.to == "dplyr" && edge.source == "DESCRIPTION"));
    assert!(!report
        .components
        .iter()
        .any(|component| component.name == "R"));
}

#[test]
fn sbom_scan_extracts_pubspec_lock_direct_edges() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("pubspec.lock"),
        r#"packages:
  http:
    dependency: "direct main"
    description:
      name: http
      url: "https://pub.dev"
    source: hosted
    version: "1.2.2"
  test:
    dependency: "direct dev"
    description:
      name: test
      url: "https://pub.dev"
    source: hosted
    version: "1.25.8"
  async:
    dependency: transitive
    description:
      name: async
      url: "https://pub.dev"
    source: hosted
    version: "2.11.0"
"#,
    )
    .unwrap();

    let report = scan_sbom(temp.path(), &ScanCancellation::default()).unwrap();
    let components = report
        .components
        .iter()
        .map(|component| {
            (
                component.scope.as_str(),
                component.name.as_str(),
                component.package_url.as_deref(),
            )
        })
        .collect::<Vec<_>>();

    assert_eq!(report.by_ecosystem.get("dart"), Some(&3));
    assert_eq!(report.lockfiles.len(), 1);
    assert!(report
        .lockfiles
        .iter()
        .any(|lockfile| lockfile.path == "pubspec.lock" && lockfile.sha256.starts_with("sha256:")));
    assert!(components.contains(&("pubspec.lock", "http", Some("pkg:pub/http@1.2.2"))));
    assert!(components.contains(&("pubspec.lock", "test", Some("pkg:pub/test@1.25.8"))));
    assert!(components.contains(&("pubspec.lock", "async", Some("pkg:pub/async@2.11.0"))));
    assert!(report
        .dependencies
        .iter()
        .any(|edge| edge.from == "root" && edge.to == "http" && edge.source == "pubspec.lock"));
    assert!(report
        .dependencies
        .iter()
        .any(|edge| edge.from == "root" && edge.to == "test" && edge.source == "pubspec.lock"));
    assert!(!report
        .dependencies
        .iter()
        .any(|edge| edge.from == "root" && edge.to == "async"));
}

#[test]
fn sbom_scan_extracts_pubspec_yaml_dependencies() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("pubspec.yaml"),
        r#"name: app
dependencies:
  http: ^1.2.2
  path:
    version: 1.9.0
  flutter:
    sdk: flutter
dev_dependencies:
  test: 1.25.8
"#,
    )
    .unwrap();

    let report = scan_sbom(temp.path(), &ScanCancellation::default()).unwrap();
    let scoped_names = report
        .components
        .iter()
        .map(|component| {
            (
                component.scope.as_str(),
                component.name.as_str(),
                component.package_url.as_deref(),
            )
        })
        .collect::<Vec<_>>();

    assert_eq!(report.manifests_scanned, 1);
    assert_eq!(report.by_ecosystem.get("dart"), Some(&3));
    assert!(scoped_names.contains(&("dependencies", "http", Some("pkg:pub/http"))));
    assert!(scoped_names.contains(&("dependencies", "path", Some("pkg:pub/path@1.9.0"))));
    assert!(scoped_names.contains(&("dev_dependencies", "test", Some("pkg:pub/test@1.25.8"))));
    assert!(report
        .dependencies
        .iter()
        .any(|edge| edge.from == "root" && edge.to == "http" && edge.source == "pubspec.yaml"));
    assert!(report
        .dependencies
        .iter()
        .any(|edge| edge.from == "root" && edge.to == "path" && edge.source == "pubspec.yaml"));
    assert!(report
        .dependencies
        .iter()
        .any(|edge| edge.from == "root" && edge.to == "test" && edge.source == "pubspec.yaml"));
    assert!(!report
        .components
        .iter()
        .any(|component| component.name == "flutter"));
    assert!(!report.dependencies.iter().any(|edge| {
        edge.from == "root" && edge.to == "flutter" && edge.source == "pubspec.yaml"
    }));
}

#[test]
fn sbom_scan_extracts_conda_environment_dependencies() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("environment.yml"),
        r#"name: demo
channels:
  - conda-forge
dependencies:
  - python=3.11
  - numpy=1.26.4=py311h64a7726_0
  - openssl
  - pip:
      - requests[socks]==2.32.3
      - flask >= 3
"#,
    )
    .unwrap();

    let report = scan_sbom(temp.path(), &ScanCancellation::default()).unwrap();
    let scoped_names = report
        .components
        .iter()
        .map(|component| {
            (
                component.ecosystem.as_str(),
                component.scope.as_str(),
                component.name.as_str(),
                component.package_url.as_deref(),
            )
        })
        .collect::<Vec<_>>();

    assert_eq!(report.manifests_scanned, 1);
    assert_eq!(report.by_ecosystem.get("conda"), Some(&3));
    assert_eq!(report.by_ecosystem.get("python"), Some(&2));
    assert!(report
        .dependencies
        .iter()
        .any(|edge| edge.from == "root" && edge.to == "numpy" && edge.source == "environment.yml"));
    assert!(report.dependencies.iter().any(|edge| edge.from == "root"
        && edge.to == "requests"
        && edge.source == "environment.yml"));
    assert!(scoped_names.contains(&(
        "conda",
        "dependencies",
        "python",
        Some("pkg:conda/python@3.11")
    )));
    assert!(scoped_names.contains(&(
        "conda",
        "dependencies",
        "numpy",
        Some("pkg:conda/numpy@1.26.4")
    )));
    assert!(scoped_names.contains(&(
        "conda",
        "dependencies",
        "openssl",
        Some("pkg:conda/openssl")
    )));
    assert!(scoped_names.contains(&(
        "python",
        "dependencies.pip",
        "requests",
        Some("pkg:pypi/requests")
    )));
    assert!(scoped_names.contains(&(
        "python",
        "dependencies.pip",
        "flask",
        Some("pkg:pypi/flask")
    )));
}

#[test]
fn sbom_scan_extracts_go_sum_module_edges() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("go.sum"),
        "github.com/gin-gonic/gin v1.9.1 h1:abc\ngolang.org/x/crypto v0.17.0/go.mod h1:def\n",
    )
    .unwrap();

    let report = scan_sbom(temp.path(), &ScanCancellation::default()).unwrap();
    let components = report
        .components
        .iter()
        .map(|component| {
            (
                component.scope.as_str(),
                component.name.as_str(),
                component.package_url.as_deref(),
            )
        })
        .collect::<Vec<_>>();

    assert_eq!(report.by_ecosystem.get("go"), Some(&2));
    assert!(components.contains(&(
        "go.sum",
        "github.com/gin-gonic/gin",
        Some("pkg:golang/github.com/gin-gonic/gin@v1.9.1"),
    )));
    assert!(components.contains(&(
        "go.sum",
        "golang.org/x/crypto",
        Some("pkg:golang/golang.org/x/crypto@v0.17.0"),
    )));
    assert!(report.dependencies.iter().any(|edge| edge.from == "root"
        && edge.to == "github.com/gin-gonic/gin"
        && edge.source == "go.sum"));
    assert!(report.dependencies.iter().any(|edge| edge.from == "root"
        && edge.to == "golang.org/x/crypto"
        && edge.source == "go.sum"));
}

#[test]
fn sbom_scan_extracts_poetry_lock_dependency_edges() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("poetry.lock"),
        r#"[[package]]
name = "fastapi"
version = "0.111.0"

[package.dependencies]
pydantic = ">=1.7"
starlette = ">=0.37"

[[package]]
name = "starlette"
version = "0.37.2"
"#,
    )
    .unwrap();

    let report = scan_sbom(temp.path(), &ScanCancellation::default()).unwrap();
    let components = report
        .components
        .iter()
        .map(|component| {
            (
                component.scope.as_str(),
                component.name.as_str(),
                component.package_url.as_deref(),
            )
        })
        .collect::<Vec<_>>();

    assert_eq!(report.by_ecosystem.get("python"), Some(&2));
    assert!(components.contains(&("poetry.lock", "fastapi", Some("pkg:pypi/fastapi@0.111.0"))));
    assert!(components.contains(&(
        "poetry.lock",
        "starlette",
        Some("pkg:pypi/starlette@0.37.2")
    )));
    assert!(report.dependencies.iter().any(|edge| edge.from == "fastapi"
        && edge.to == "pydantic"
        && edge.source == "poetry.lock"));
    assert!(report.dependencies.iter().any(|edge| edge.from == "fastapi"
        && edge.to == "starlette"
        && edge.source == "poetry.lock"));
}

#[test]
fn sbom_scan_extracts_pipfile_manifest_dependencies() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("Pipfile"),
        r#"[packages]
requests = "==2.32.3"
flask = {version = ">=3"}

[dev-packages]
pytest = "*"
"#,
    )
    .unwrap();

    let report = scan_sbom(temp.path(), &ScanCancellation::default()).unwrap();
    let scoped_names = report
        .components
        .iter()
        .map(|component| {
            (
                component.scope.as_str(),
                component.name.as_str(),
                component.package_url.as_deref(),
            )
        })
        .collect::<Vec<_>>();

    assert_eq!(report.manifests_scanned, 1);
    assert_eq!(report.by_ecosystem.get("python"), Some(&3));
    assert!(scoped_names.contains(&("packages", "requests", Some("pkg:pypi/requests"))));
    assert!(scoped_names.contains(&("packages", "flask", Some("pkg:pypi/flask"))));
    assert!(scoped_names.contains(&("dev-packages", "pytest", Some("pkg:pypi/pytest"))));
    assert!(report
        .dependencies
        .iter()
        .any(|edge| edge.from == "root" && edge.to == "requests" && edge.source == "Pipfile"));
    assert!(report
        .dependencies
        .iter()
        .any(|edge| edge.from == "root" && edge.to == "pytest" && edge.source == "Pipfile"));
}

#[test]
fn sbom_scan_extracts_pipfile_lock_dependency_edges() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("Pipfile.lock"),
        r#"{
  "default": {
    "requests": {
      "version": "==2.32.0"
    }
  },
  "develop": {
    "pytest": {
      "version": "==8.3.0"
    }
  }
}"#,
    )
    .unwrap();

    let report = scan_sbom(temp.path(), &ScanCancellation::default()).unwrap();
    let components = report
        .components
        .iter()
        .map(|component| {
            (
                component.scope.as_str(),
                component.name.as_str(),
                component.package_url.as_deref(),
            )
        })
        .collect::<Vec<_>>();

    assert_eq!(report.by_ecosystem.get("python"), Some(&2));
    assert!(components.contains(&(
        "Pipfile.lock.default",
        "requests",
        Some("pkg:pypi/requests@2.32.0")
    )));
    assert!(components.contains(&(
        "Pipfile.lock.develop",
        "pytest",
        Some("pkg:pypi/pytest@8.3.0")
    )));
    assert!(report
        .dependencies
        .iter()
        .any(|edge| edge.from == "root" && edge.to == "requests" && edge.source == "Pipfile.lock"));
    assert!(report
        .dependencies
        .iter()
        .any(|edge| edge.from == "root" && edge.to == "pytest" && edge.source == "Pipfile.lock"));
}

#[test]
fn sbom_scan_extracts_uv_lock_package_edges() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("uv.lock"),
        r#"version = 1

[[package]]
name = "fastapi"
version = "0.111.0"
dependencies = [
  { name = "pydantic" },
  { name = "starlette" },
]

[[package]]
name = "starlette"
version = "0.37.2"

[[package]]
name = "pydantic"
version = "2.7.4"
"#,
    )
    .unwrap();

    let report = scan_sbom(temp.path(), &ScanCancellation::default()).unwrap();
    let components = report
        .components
        .iter()
        .map(|component| {
            (
                component.scope.as_str(),
                component.name.as_str(),
                component.package_url.as_deref(),
            )
        })
        .collect::<Vec<_>>();

    assert_eq!(report.by_ecosystem.get("python"), Some(&3));
    assert!(components.contains(&("uv.lock", "fastapi", Some("pkg:pypi/fastapi@0.111.0"))));
    assert!(components.contains(&("uv.lock", "starlette", Some("pkg:pypi/starlette@0.37.2"))));
    assert!(components.contains(&("uv.lock", "pydantic", Some("pkg:pypi/pydantic@2.7.4"))));
    assert!(report
        .dependencies
        .iter()
        .any(|edge| edge.from == "root" && edge.to == "fastapi" && edge.source == "uv.lock"));
    assert!(report
        .dependencies
        .iter()
        .any(|edge| edge.from == "root" && edge.to == "starlette" && edge.source == "uv.lock"));
    assert!(report
        .dependencies
        .iter()
        .any(|edge| edge.from == "fastapi" && edge.to == "pydantic" && edge.source == "uv.lock"));
    assert!(report
        .dependencies
        .iter()
        .any(|edge| edge.from == "fastapi" && edge.to == "starlette" && edge.source == "uv.lock"));
}

#[test]
fn sbom_scan_extracts_yarn_lock_dependency_edges() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("yarn.lock"),
        r#""express@^4.18.0":
  version "4.18.2"
  dependencies:
    body-parser "1.20.1"
    qs "6.11.0"
  optionalDependencies:
    supports-color "^8.1.1"

"@scope/pkg@^1.0.0":
  version "1.0.0"
  dependencies:
    left-pad "^1.3.0"
"#,
    )
    .unwrap();

    let report = scan_sbom(temp.path(), &ScanCancellation::default()).unwrap();
    let components = report
        .components
        .iter()
        .map(|component| {
            (
                component.scope.as_str(),
                component.name.as_str(),
                component.package_url.as_deref(),
            )
        })
        .collect::<Vec<_>>();

    assert_eq!(report.by_ecosystem.get("npm"), Some(&2));
    assert!(components.contains(&("yarn.lock", "express", Some("pkg:npm/express@4.18.2"))));
    assert!(components.contains(&(
        "yarn.lock",
        "@scope/pkg",
        Some("pkg:npm/%40scope/pkg@1.0.0"),
    )));
    assert!(report.dependencies.iter().any(|edge| edge.from == "express"
        && edge.to == "body-parser"
        && edge.source == "yarn.lock"));
    assert!(report
        .dependencies
        .iter()
        .any(|edge| edge.from == "express" && edge.to == "qs" && edge.source == "yarn.lock"));
    assert!(report.dependencies.iter().any(|edge| edge.from == "express"
        && edge.to == "supports-color"
        && edge.source == "yarn.lock"));
    assert!(report
        .dependencies
        .iter()
        .any(|edge| edge.from == "@scope/pkg"
            && edge.to == "left-pad"
            && edge.source == "yarn.lock"));
}

#[test]
fn sbom_scan_extracts_pnpm_lock_importer_edges() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("pnpm-lock.yaml"),
        r#"lockfileVersion: '9.0'

importers:
  .:
    dependencies:
      express:
        specifier: ^4.18.0
        version: 4.18.2
    devDependencies:
      '@scope/pkg':
        specifier: ^1.0.0
        version: 1.0.0

packages:
  express@4.18.2:
    resolution: {integrity: sha512-demo}
    dependencies:
      debug: 2.6.9
    optionalDependencies:
      supports-color: 8.1.1
    peerDependencies:
      accepts: ^1.3.8
"#,
    )
    .unwrap();

    let report = scan_sbom(temp.path(), &ScanCancellation::default()).unwrap();
    let components = report
        .components
        .iter()
        .map(|component| {
            (
                component.scope.as_str(),
                component.name.as_str(),
                component.package_url.as_deref(),
            )
        })
        .collect::<Vec<_>>();

    assert_eq!(report.by_ecosystem.get("npm"), Some(&4));
    assert!(components.contains(&("pnpm-lock.yaml", "express", Some("pkg:npm/express@4.18.2"),)));
    assert!(components.contains(&(
        "pnpm-lock.yaml",
        "@scope/pkg",
        Some("pkg:npm/%40scope/pkg@1.0.0"),
    )));
    assert!(components.contains(&("pnpm-lock.yaml", "debug", Some("pkg:npm/debug@2.6.9"),)));
    assert!(components.contains(&(
        "pnpm-lock.yaml",
        "supports-color",
        Some("pkg:npm/supports-color@8.1.1"),
    )));
    assert!(report.dependencies.iter().any(|edge| edge.from == "root"
        && edge.to == "express"
        && edge.source == "pnpm-lock.yaml"));
    assert!(report.dependencies.iter().any(|edge| edge.from == "root"
        && edge.to == "@scope/pkg"
        && edge.source == "pnpm-lock.yaml"));
    assert!(report.dependencies.iter().any(|edge| edge.from == "express"
        && edge.to == "debug"
        && edge.source == "pnpm-lock.yaml"));
    assert!(report.dependencies.iter().any(|edge| edge.from == "express"
        && edge.to == "supports-color"
        && edge.source == "pnpm-lock.yaml"));
    assert!(report.dependencies.iter().any(|edge| edge.from == "express"
        && edge.to == "accepts"
        && edge.source == "pnpm-lock.yaml"));
    assert!(!report
        .dependencies
        .iter()
        .any(|edge| edge.from == "root" && edge.to == "debug" && edge.source == "pnpm-lock.yaml"));
}

#[test]
fn sbom_scan_extracts_package_lock_v1_dependency_edges() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("package-lock.json"),
        r#"{
  "lockfileVersion": 1,
  "dependencies": {
    "express": {
      "version": "4.18.2",
      "dependencies": {
        "body-parser": {"version": "1.20.1"}
      }
    },
    "@scope/pkg": {"version": "1.0.0"}
  }
}"#,
    )
    .unwrap();

    let report = scan_sbom(temp.path(), &ScanCancellation::default()).unwrap();
    let components = report
        .components
        .iter()
        .map(|component| {
            (
                component.scope.as_str(),
                component.name.as_str(),
                component.package_url.as_deref(),
            )
        })
        .collect::<Vec<_>>();

    assert_eq!(report.by_ecosystem.get("npm"), Some(&3));
    assert!(components.contains(&(
        "package-lock.json",
        "express",
        Some("pkg:npm/express@4.18.2")
    )));
    assert!(components.contains(&(
        "package-lock.json",
        "body-parser",
        Some("pkg:npm/body-parser@1.20.1")
    )));
    assert!(components.contains(&(
        "package-lock.json",
        "@scope/pkg",
        Some("pkg:npm/%40scope/pkg@1.0.0")
    )));
    assert!(report
        .dependencies
        .iter()
        .any(|edge| edge.from == "root" && edge.to == "express"));
    assert!(report
        .dependencies
        .iter()
        .any(|edge| edge.from == "express" && edge.to == "body-parser"));
    assert!(report
        .dependencies
        .iter()
        .any(|edge| edge.from == "root" && edge.to == "@scope/pkg"));
}

#[test]
fn sbom_scan_extracts_package_lock_v3_scoped_dependency_edges() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("package-lock.json"),
        r#"{
  "lockfileVersion": 3,
  "packages": {
    "": {
      "dependencies": {
        "@scope/pkg": "^1.0.0"
      }
    },
    "node_modules/@scope/pkg": {
      "version": "1.0.0",
      "dependencies": {
        "left-pad": "1.3.0"
      },
      "peerDependencies": {
        "react": "^18.0.0"
      }
    }
  }
}"#,
    )
    .unwrap();

    let report = scan_sbom(temp.path(), &ScanCancellation::default()).unwrap();
    let components = report
        .components
        .iter()
        .map(|component| {
            (
                component.scope.as_str(),
                component.name.as_str(),
                component.package_url.as_deref(),
            )
        })
        .collect::<Vec<_>>();

    assert_eq!(report.by_ecosystem.get("npm"), Some(&1));
    assert!(components.contains(&(
        "package-lock.json",
        "@scope/pkg",
        Some("pkg:npm/%40scope/pkg@1.0.0")
    )));
    assert!(report
        .dependencies
        .iter()
        .any(|edge| edge.from == "root" && edge.to == "@scope/pkg"));
    assert!(report
        .dependencies
        .iter()
        .any(|edge| edge.from == "@scope/pkg" && edge.to == "left-pad"));
    assert!(report
        .dependencies
        .iter()
        .any(|edge| edge.from == "@scope/pkg" && edge.to == "react"));
}

#[test]
fn sbom_scan_extracts_python_optional_dependency_groups() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("pyproject.toml"),
        "[project]\ndependencies = [\"django>=5\"]\n[project.optional-dependencies]\ndev = [\"pytest>=8\"]\ndocs = [\"mkdocs~=1.6\"]\n[dependency-groups]\nlint = [\"ruff==0.6.0\"]\n",
    )
    .unwrap();

    let report = scan_sbom(temp.path(), &ScanCancellation::default()).unwrap();
    let scoped_names = report
        .components
        .iter()
        .map(|component| (component.scope.as_str(), component.name.as_str()))
        .collect::<Vec<_>>();

    assert_eq!(report.by_ecosystem.get("python"), Some(&4));
    assert!(scoped_names.contains(&("project.dependencies", "django")));
    assert!(scoped_names.contains(&("project.optional-dependencies.dev", "pytest")));
    assert!(scoped_names.contains(&("project.optional-dependencies.docs", "mkdocs")));
    assert!(scoped_names.contains(&("dependency-groups.lint", "ruff")));
    assert!(report
        .dependencies
        .iter()
        .any(|edge| edge.from == "root" && edge.to == "django" && edge.source == "pyproject.toml"));
    assert!(report
        .dependencies
        .iter()
        .any(|edge| edge.from == "root" && edge.to == "pytest" && edge.source == "pyproject.toml"));
    assert!(report
        .dependencies
        .iter()
        .any(|edge| edge.from == "root" && edge.to == "mkdocs" && edge.source == "pyproject.toml"));
    assert!(report
        .dependencies
        .iter()
        .any(|edge| edge.from == "root" && edge.to == "ruff" && edge.source == "pyproject.toml"));
}

#[test]
fn sbom_scan_extracts_poetry_pyproject_dependencies() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("pyproject.toml"),
        r#"[tool.poetry.dependencies]
python = "^3.11"
fastapi = "^0.111.0"
pydantic = { version = ">=2.7" }

[tool.poetry.dev-dependencies]
pytest = "^8.3"

[tool.poetry.group.docs.dependencies]
mkdocs = "^1.6"
"#,
    )
    .unwrap();

    let report = scan_sbom(temp.path(), &ScanCancellation::default()).unwrap();
    let scoped_names = report
        .components
        .iter()
        .map(|component| (component.scope.as_str(), component.name.as_str()))
        .collect::<Vec<_>>();

    assert_eq!(report.by_ecosystem.get("python"), Some(&4));
    assert!(scoped_names.contains(&("tool.poetry.dependencies", "fastapi")));
    assert!(scoped_names.contains(&("tool.poetry.dependencies", "pydantic")));
    assert!(scoped_names.contains(&("tool.poetry.dev-dependencies", "pytest")));
    assert!(scoped_names.contains(&("tool.poetry.group.docs.dependencies", "mkdocs")));
    assert!(!scoped_names.contains(&("tool.poetry.dependencies", "python")));
    assert!(report.dependencies.iter().any(|edge| edge.from == "root"
        && edge.to == "fastapi"
        && edge.source == "pyproject.toml"));
    assert!(report.dependencies.iter().any(|edge| edge.from == "root"
        && edge.to == "pydantic"
        && edge.source == "pyproject.toml"));
    assert!(report
        .dependencies
        .iter()
        .any(|edge| edge.from == "root" && edge.to == "pytest" && edge.source == "pyproject.toml"));
    assert!(report
        .dependencies
        .iter()
        .any(|edge| edge.from == "root" && edge.to == "mkdocs" && edge.source == "pyproject.toml"));
    assert!(!report
        .dependencies
        .iter()
        .any(|edge| edge.from == "root" && edge.to == "python" && edge.source == "pyproject.toml"));
}

#[test]
fn sbom_scan_extracts_python_requirements_components() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("requirements.txt"),
        "requests[socks]==2.32.0 ; python_version >= '3.11'\n# comment\n-r dev-requirements.txt\n./local-package\nflask >= 3\n",
    )
    .unwrap();
    fs::write(temp.path().join("dev-requirements.txt"), "pytest~=8.3\n").unwrap();

    let report = scan_sbom(temp.path(), &ScanCancellation::default()).unwrap();
    let scoped_names = report
        .components
        .iter()
        .map(|component| {
            (
                component.scope.as_str(),
                component.name.as_str(),
                component.package_url.as_deref(),
            )
        })
        .collect::<Vec<_>>();

    assert_eq!(report.manifests_scanned, 2);
    assert_eq!(report.by_ecosystem.get("python"), Some(&3));
    assert!(scoped_names.contains(&("requirements.txt", "requests", Some("pkg:pypi/requests"))));
    assert!(scoped_names.contains(&("requirements.txt", "flask", Some("pkg:pypi/flask"))));
    assert!(scoped_names.contains(&("dev-requirements.txt", "pytest", Some("pkg:pypi/pytest"))));
    assert!(report.dependencies.iter().any(|edge| edge.from == "root"
        && edge.to == "requests"
        && edge.source == "requirements.txt"));
    assert!(report.dependencies.iter().any(|edge| edge.from == "root"
        && edge.to == "flask"
        && edge.source == "requirements.txt"));
    assert!(report.dependencies.iter().any(|edge| edge.from == "root"
        && edge.to == "pytest"
        && edge.source == "dev-requirements.txt"));
}

#[test]
fn sbom_scan_extracts_go_mod_dependencies() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("go.mod"),
        r#"module example.com/app

go 1.22

require github.com/gin-gonic/gin v1.9.1

require (
    golang.org/x/crypto v0.17.0 // indirect
)
"#,
    )
    .unwrap();

    let report = scan_sbom(temp.path(), &ScanCancellation::default()).unwrap();
    let scoped_names = report
        .components
        .iter()
        .map(|component| {
            (
                component.scope.as_str(),
                component.name.as_str(),
                component.package_url.as_deref(),
            )
        })
        .collect::<Vec<_>>();

    assert_eq!(report.manifests_scanned, 1);
    assert_eq!(report.by_ecosystem.get("go"), Some(&2));
    assert!(scoped_names.contains(&(
        "require",
        "github.com/gin-gonic/gin",
        Some("pkg:golang/github.com/gin-gonic/gin@v1.9.1")
    )));
    assert!(scoped_names.contains(&(
        "require",
        "golang.org/x/crypto",
        Some("pkg:golang/golang.org/x/crypto@v0.17.0")
    )));
    assert!(report.dependencies.iter().any(|edge| edge.from == "root"
        && edge.to == "github.com/gin-gonic/gin"
        && edge.source == "go.mod"));
    assert!(report.dependencies.iter().any(|edge| edge.from == "root"
        && edge.to == "golang.org/x/crypto"
        && edge.source == "go.mod"));
}

#[test]
fn sbom_scan_outputs_completed_tool_envelope() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("package.json"),
        r#"{"dependencies":{"lodash":"4.17.21","express":"4.18.2"}}"#,
    )
    .unwrap();

    let report = scan_sbom(temp.path(), &ScanCancellation::default()).unwrap();
    let output = report.to_tool_json();

    assert_eq!(output["status"], json!("completed"));
    assert_eq!(output["data"]["componentCount"], json!(2));
    assert_eq!(output["data"]["lockfileCount"], json!(0));
    assert_eq!(output["data"]["dependencyCount"], json!(2));
    assert!(output["data"]["components"]
        .as_array()
        .unwrap()
        .iter()
        .any(|component| component["name"] == json!("lodash")
            && component["packageUrl"] == json!("pkg:npm/lodash@4.17.21")));
    assert_eq!(output["data"]["cycloneDx"]["bomFormat"], json!("CycloneDX"));
    assert!(output["data"]["cycloneDx"]["components"]
        .as_array()
        .unwrap()
        .iter()
        .any(|component| component["purl"] == json!("pkg:npm/lodash@4.17.21")));
    assert_eq!(
        output["data"]["cycloneDx"]["metadata"]["component"]["bom-ref"],
        json!("kuzushi:root")
    );
    assert_eq!(
        output["data"]["cycloneDx"]["dependencies"][0]["ref"],
        json!("kuzushi:root")
    );
    assert_eq!(
        output["data"]["cycloneDx"]["dependencies"][0]["dependsOn"],
        json!(["pkg:npm/express@4.18.2", "pkg:npm/lodash@4.17.21"])
    );
    assert_eq!(output["data"]["spdx"]["spdxVersion"], json!("SPDX-2.3"));
    assert!(output["data"]["spdx"]["packages"]
        .as_array()
        .unwrap()
        .iter()
        .any(|package| package["externalRefs"][0]["referenceLocator"]
            == json!("pkg:npm/lodash@4.17.21")));
    assert!(output["data"]["spdx"]["relationships"]
        .as_array()
        .unwrap()
        .iter()
        .any(
            |relationship| relationship["spdxElementId"] == json!("SPDXRef-DOCUMENT")
                && relationship["relatedSpdxElement"] == json!("SPDXRef-Package-npm-lodash")
        ));
}

#[test]
fn sbom_scan_exports_lockfile_components_to_standard_sboms() {
    let temp = tempfile::tempdir().unwrap();
    fs::write(
        temp.path().join("Cargo.lock"),
        r#"version = 3

[[package]]
name = "demo"
version = "0.1.0"
dependencies = [
 "serde 1.0.197",
]

[[package]]
name = "serde"
version = "1.0.197"
"#,
    )
    .unwrap();

    let report = scan_sbom(temp.path(), &ScanCancellation::default()).unwrap();
    let output = report.to_tool_json();

    assert_eq!(output["data"]["lockfileCount"], json!(1));
    assert!(output["data"]["cycloneDx"]["components"]
        .as_array()
        .unwrap()
        .iter()
        .any(
            |component| component["purl"] == json!("pkg:cargo/serde@1.0.197")
                && component["properties"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|property| property["name"] == json!("kuzushi:manifestPath")
                        && property["value"] == json!("Cargo.lock"))
        ));
    assert!(output["data"]["cycloneDx"]["dependencies"]
        .as_array()
        .unwrap()
        .iter()
        .any(
            |dependency| dependency["ref"] == json!("pkg:cargo/demo@0.1.0")
                && dependency["dependsOn"] == json!(["pkg:cargo/serde@1.0.197"])
        ));
    assert!(output["data"]["spdx"]["packages"]
        .as_array()
        .unwrap()
        .iter()
        .any(|package| package["externalRefs"][0]["referenceLocator"]
            == json!("pkg:cargo/serde@1.0.197")
            && package["annotations"]
                .as_array()
                .unwrap()
                .iter()
                .any(|annotation| annotation["comment"] == json!("manifestPath=Cargo.lock"))));
    assert!(output["data"]["spdx"]["relationships"]
        .as_array()
        .unwrap()
        .iter()
        .any(
            |relationship| relationship["spdxElementId"] == json!("SPDXRef-Package-cargo-demo")
                && relationship["relatedSpdxElement"] == json!("SPDXRef-Package-cargo-serde")
        ));
}
