#[cfg(test)]
mod tests {
    use super::super::id::severity_from_cvss;
    use super::super::*;

    const PACKAGE_JSON: &str =
        include_str!("../../../../../../tests/fixtures/dep-hygiene/node/package.json");
    const PYPROJECT_TOML: &str =
        include_str!("../../../../../../tests/fixtures/dep-hygiene/python/pyproject.toml");
    const CARGO_TOML: &str =
        include_str!("../../../../../../tests/fixtures/dep-hygiene/rust/Cargo.toml");
    const GO_MOD: &str = include_str!("../../../../../../tests/fixtures/dep-hygiene/go/go.mod");
    const REQUIREMENTS_TXT: &str = "flask\nrequests>=2.0\nsafe-lib>=1,<2\n-r dev.txt\n";
    const PIPFILE: &str = r#"[packages]
flask = "*"
requests = ">=2.0"
safe-lib = ">=1,<2"

[dev-packages]
pytest = { version = "latest" }
"#;
    const COMPOSER_JSON: &str = r#"{
      "require": {
        "php": ">=8.2",
        "ext-json": "*",
        "symfony/http-foundation": "*",
        "guzzlehttp/guzzle": ">=7.0",
        "safe/package": "^1.2"
      },
      "require-dev": {
        "phpunit/phpunit": "dev-main"
      }
    }"#;
    const DOTNET_PROJECT: &str = r#"<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="*" />
    <PackageReference Include="Dapper" Version="[2.0,)" />
    <PackageReference Include="Serilog" Version="3.1.0" />
    <PackageReference Include="NUnit">
      <Version>latest</Version>
    </PackageReference>
  </ItemGroup>
</Project>
"#;
    const MAVEN_POM: &str = r#"<project>
  <dependencies>
    <dependency>
      <groupId>org.slf4j</groupId>
      <artifactId>slf4j-api</artifactId>
      <version>LATEST</version>
    </dependency>
    <dependency>
      <groupId>com.fasterxml.jackson.core</groupId>
      <artifactId>jackson-databind</artifactId>
      <version>[2.15,)</version>
    </dependency>
    <dependency>
      <groupId>junit</groupId>
      <artifactId>junit</artifactId>
      <version>4.13.2</version>
    </dependency>
    <dependency>
      <groupId>org.example</groupId>
      <artifactId>managed</artifactId>
      <version>${managed.version}</version>
    </dependency>
  </dependencies>
</project>
"#;
    const GRADLE_BUILD: &str = r#"dependencies {
    implementation "org.slf4j:slf4j-api:+"
    testImplementation("junit:junit:4.13.2")
    runtimeOnly group: "com.fasterxml.jackson.core", name: "jackson-databind", version: "[2.15,)"
    api("org.example:managed:${managedVersion}")
    compileOnly("org.example:floating:latest.release")
}"#;
    const GEMFILE: &str = r#"source "https://rubygems.org"
gem "rails"
gem "rack", ">= 2.0"
gem "puma", "~> 6.4"
gem "safe_gem", ">= 1.0", "< 2.0"
gem "debug", "latest"
"#;
    const BOWER_JSON: &str = r#"{
      "dependencies": {
        "jquery": "*",
        "angular": ">=1.6",
        "safe-lib": "1.2.3"
      },
      "devDependencies": {
        "qunit": { "version": "latest" }
      }
    }"#;
    const CONANFILE_TXT: &str = r#"[requires]
zlib/*
openssl/[>=1.1]
fmt/10.1.1
boost/[>=1.80 <2.0]

[tool_requires]
cmake/latest
"#;
    const PUBSPEC_YAML: &str = r#"dependencies:
  http: any
  collection: ">=1.18.0"
  path: ^1.9.0
  hosted_package:
    version: latest
  flutter:
    sdk: flutter
dev_dependencies:
  test: "*"
"#;
    const HAXELIB_JSON: &str = r#"{
      "dependencies": {
        "tink_core": "*",
        "hxnodejs": ">=12.0",
        "utest": "1.13.2",
        "devlib": "dev"
      }
    }"#;
    const CPANFILE: &str = r#"requires 'Moo';
requires 'DBI', '>= 1.643';
requires 'Path::Tiny', '0.144';
test_requires 'Test::More', 'latest';
recommends 'Safe::Bounded', '>= 1.0, < 2.0';
"#;
    const R_DESCRIPTION: &str = r#"Package: demo
Version: 0.1.0
Depends: R (>= 4.1), dplyr (>= 1.1), ggplot2
Imports:
  httr (>= 1.4, < 2.0),
  jsonlite (latest)
LinkingTo: Rcpp (>= 1.0)
"#;
    const CONDA_ENVIRONMENT: &str = r#"name: demo
dependencies:
  - python=3.11
  - numpy>=1.26
  - pandas
  - scipy=1.11
  - pip:
      - flask
      - requests>=2.0
      - safe-lib>=1,<2
"#;
    const GLEAM_TOML: &str = r#"[dependencies]
gleam_stdlib = ">= 0.34.0"
mist = "*"
safe_hex = "~> 1.0"

[dev-dependencies]
gleeunit = "latest"
"#;
    const SHARD_YML: &str = r#"dependencies:
  kemal:
    github: kemalcr/kemal
  pg:
    version: ">= 0.26.0"
  safe_shard:
    version: "~> 1.2"
development_dependencies:
  ameba:
    version: latest
"#;
    const OPAM_FILE: &str = r#"opam-version: "2.0"
depends: [
  "ocaml" {>= "4.14"}
  "dune" {>= "3.0" & < "4.0"}
  "alcotest" {with-test}
  "base64" {= "3.5.1"}
]
"#;
    const ELM_JSON: &str = r#"{
      "type": "application",
      "dependencies": {
        "direct": {
          "elm/core": ">= 1.0.0",
          "elm/html": "1.0.0",
          "elm/json": "*"
        },
        "indirect": {
          "elm/virtual-dom": "latest"
        }
      },
      "test-dependencies": {
        "direct": {
          "elm-explorations/test": ">= 2.0.0"
        }
      }
    }"#;
    const MIX_EXS: &str = r#"defp deps do
  [
    {:phoenix, "~> 1.7"},
    {:jason, ">= 1.4"},
    {:plug, ">= 1.0 and < 2.0"},
    {:devlib, "latest", only: :dev},
    {:telemetry, "1.2.1"}
  ]
end
"#;
    const NIMBLE_FILE: &str = r#"requires "nim >= 2.0"
requires "jester", "chronicles >= 0.10.0", "safe_pkg >= 1.0.0 & < 2.0.0"
requires "latestlib latest"
requires "pinned == 1.2.3"
"#;
    const CABAL_FILE: &str = r#"cabal-version: 3.0
name: demo
library
  build-depends:
      base >=4.14 && <5
    , text >= 2.0
    , aeson
    , bytestring ==0.11
  exposed-modules: Demo
"#;
    const SBT_BUILD: &str = r#"scalaVersion := "2.13.12"
libraryDependencies ++= Seq(
  "ch.qos.logback" % "logback-classic" % "+",
  "org.typelevel" %% "cats-effect" % ">=3.5",
  "com.typesafe" % "config" % "1.4.3",
  "org.scalatest" %% "scalatest" % "latest.release" % Test
)
"#;
    const JULIA_PROJECT_TOML: &str = r#"[deps]
HTTP = "cd3eb016-35fb-5094-929b-558a96fad6f3"
JSON3 = "0f8b85d8-7281-11e9-16c2-8bfb4c7a9433"
SafePkg = "00000000-0000-0000-0000-000000000001"
MissingCompat = "00000000-0000-0000-0000-000000000002"

[compat]
HTTP = ">= 1.0"
JSON3 = "*"
SafePkg = "1, < 2"
"#;
    const DENO_IMPORT_MAP: &str = r#"{
      "imports": {
        "lodash": "npm:lodash@latest",
        "leftpad": "npm:left-pad",
        "safe": "npm:safe-lib@1.2.3"
      },
      "scopes": {
        "https://deno.land/x/demo/": {
          "oak": "jsr:@oak/oak@>=1.0",
          "wild": "jsr:@demo/wild@*"
        }
      }
    }"#;

    #[test]
    fn analyzes_package_json_like_typescript_module() {
        let findings = analyze_manifest(
            ManifestKind::PackageJson,
            Path::new("/repo/package.json"),
            PACKAGE_JSON,
        );
        let by_package = finding_map(&findings);

        assert_eq!(by_package["lodash"].severity, DepHygieneSeverity::High);
        assert_eq!(by_package["express"].severity, DepHygieneSeverity::High);
        assert_eq!(by_package["axios"].severity, DepHygieneSeverity::Medium);
        assert_eq!(by_package["left-pad"].severity, DepHygieneSeverity::Low);
        assert_eq!(by_package["vitest"].severity, DepHygieneSeverity::High);
        assert!(!by_package.contains_key("good-lib"));
        assert!(!by_package.contains_key("react"));
    }

    #[test]
    fn ignores_unparseable_package_json() {
        let findings = analyze_manifest(
            ManifestKind::PackageJson,
            Path::new("/repo/package.json"),
            "{ this is not json",
        );
        assert!(findings.is_empty());
    }

    #[test]
    fn analyzes_pyproject_toml_like_typescript_module() {
        let findings = analyze_manifest(
            ManifestKind::PyprojectToml,
            Path::new("/repo/pyproject.toml"),
            PYPROJECT_TOML,
        );
        let by_package = finding_map(&findings);

        assert_eq!(by_package["requests"].severity, DepHygieneSeverity::Medium);
        assert_eq!(by_package["flask"].severity, DepHygieneSeverity::High);
        assert_eq!(by_package["loguru"].severity, DepHygieneSeverity::High);
        assert_eq!(by_package["httpx"].severity, DepHygieneSeverity::Medium);
        assert!(!by_package.contains_key("django"));
        assert!(!by_package.contains_key("pydantic"));
        assert!(!by_package.contains_key("sqlalchemy"));
        assert!(!by_package.contains_key("python"));
    }

    #[test]
    fn analyzes_requirements_txt_pep508_specifiers() {
        let findings = analyze_manifest(
            ManifestKind::RequirementsTxt,
            Path::new("/repo/requirements.txt"),
            REQUIREMENTS_TXT,
        );
        let by_package = finding_map(&findings);

        assert_eq!(by_package["flask"].severity, DepHygieneSeverity::High);
        assert_eq!(by_package["requests"].severity, DepHygieneSeverity::Medium);
        assert!(!by_package.contains_key("safe-lib"));
        assert!(!by_package.contains_key("-r"));
        assert!(findings
            .iter()
            .all(|finding| finding.manifest == "requirements.txt"));
    }

    #[test]
    fn analyzes_pipfile_version_constraints() {
        let findings = analyze_manifest(ManifestKind::Pipfile, Path::new("/repo/Pipfile"), PIPFILE);
        let by_package = finding_map(&findings);

        assert_eq!(by_package["flask"].severity, DepHygieneSeverity::High);
        assert_eq!(by_package["requests"].severity, DepHygieneSeverity::Medium);
        assert_eq!(by_package["pytest"].severity, DepHygieneSeverity::High);
        assert!(!by_package.contains_key("safe-lib"));
        assert!(findings.iter().all(|finding| finding.manifest == "Pipfile"));
    }

    #[test]
    fn analyzes_composer_json_version_constraints() {
        let findings = analyze_manifest(
            ManifestKind::ComposerJson,
            Path::new("/repo/composer.json"),
            COMPOSER_JSON,
        );
        let by_package = finding_map(&findings);

        assert_eq!(
            by_package["symfony/http-foundation"].severity,
            DepHygieneSeverity::High
        );
        assert_eq!(
            by_package["guzzlehttp/guzzle"].severity,
            DepHygieneSeverity::Medium
        );
        assert_eq!(
            by_package["phpunit/phpunit"].severity,
            DepHygieneSeverity::High
        );
        assert!(!by_package.contains_key("php"));
        assert!(!by_package.contains_key("ext-json"));
        assert!(!by_package.contains_key("safe/package"));
        assert!(findings
            .iter()
            .all(|finding| finding.manifest == "composer.json"));
    }

    #[test]
    fn analyzes_dotnet_project_package_references() {
        let findings = analyze_manifest(
            ManifestKind::DotnetProject,
            Path::new("/repo/Demo.csproj"),
            DOTNET_PROJECT,
        );
        let by_package = finding_map(&findings);

        assert_eq!(
            by_package["Newtonsoft.Json"].severity,
            DepHygieneSeverity::High
        );
        assert_eq!(by_package["Dapper"].severity, DepHygieneSeverity::Medium);
        assert_eq!(by_package["NUnit"].severity, DepHygieneSeverity::High);
        assert!(!by_package.contains_key("Serilog"));
        assert!(findings
            .iter()
            .all(|finding| finding.manifest == "dotnet-project"));
    }

    #[test]
    fn analyzes_maven_pom_dependency_versions() {
        let findings = analyze_manifest(
            ManifestKind::MavenPom,
            Path::new("/repo/pom.xml"),
            MAVEN_POM,
        );
        let by_package = finding_map(&findings);

        assert_eq!(
            by_package["org.slf4j/slf4j-api"].severity,
            DepHygieneSeverity::High
        );
        assert_eq!(
            by_package["com.fasterxml.jackson.core/jackson-databind"].severity,
            DepHygieneSeverity::Medium
        );
        assert!(!by_package.contains_key("junit/junit"));
        assert!(!by_package.contains_key("org.example/managed"));
        assert!(findings.iter().all(|finding| finding.manifest == "pom.xml"));
    }

    #[test]
    fn analyzes_gradle_build_dependency_versions() {
        let findings = analyze_manifest(
            ManifestKind::GradleBuild,
            Path::new("/repo/build.gradle"),
            GRADLE_BUILD,
        );
        let by_package = finding_map(&findings);

        assert_eq!(
            by_package["org.slf4j/slf4j-api"].severity,
            DepHygieneSeverity::High
        );
        assert_eq!(
            by_package["com.fasterxml.jackson.core/jackson-databind"].severity,
            DepHygieneSeverity::Medium
        );
        assert_eq!(
            by_package["org.example/floating"].severity,
            DepHygieneSeverity::High
        );
        assert!(!by_package.contains_key("junit/junit"));
        assert!(!by_package.contains_key("org.example/managed"));
        assert!(findings
            .iter()
            .all(|finding| finding.manifest == "gradle-build"));
    }

    #[test]
    fn analyzes_gemfile_dependency_versions() {
        let findings = analyze_manifest(ManifestKind::Gemfile, Path::new("/repo/Gemfile"), GEMFILE);
        let by_package = finding_map(&findings);

        assert_eq!(by_package["rails"].severity, DepHygieneSeverity::High);
        assert_eq!(by_package["rack"].severity, DepHygieneSeverity::Medium);
        assert_eq!(by_package["debug"].severity, DepHygieneSeverity::High);
        assert!(!by_package.contains_key("puma"));
        assert!(!by_package.contains_key("safe_gem"));
        assert!(findings.iter().all(|finding| finding.manifest == "Gemfile"));
    }

    #[test]
    fn analyzes_bower_json_version_constraints() {
        let findings = analyze_manifest(
            ManifestKind::BowerJson,
            Path::new("/repo/bower.json"),
            BOWER_JSON,
        );
        let by_package = finding_map(&findings);

        assert_eq!(by_package["jquery"].severity, DepHygieneSeverity::High);
        assert_eq!(by_package["angular"].severity, DepHygieneSeverity::Medium);
        assert_eq!(by_package["qunit"].severity, DepHygieneSeverity::High);
        assert!(!by_package.contains_key("safe-lib"));
        assert!(findings
            .iter()
            .all(|finding| finding.manifest == "bower.json"));
    }

    #[test]
    fn analyzes_conanfile_txt_requires_versions() {
        let findings = analyze_manifest(
            ManifestKind::ConanfileTxt,
            Path::new("/repo/conanfile.txt"),
            CONANFILE_TXT,
        );
        let by_package = finding_map(&findings);

        assert_eq!(by_package["zlib"].severity, DepHygieneSeverity::High);
        assert_eq!(by_package["openssl"].severity, DepHygieneSeverity::Medium);
        assert!(!by_package.contains_key("fmt"));
        assert!(!by_package.contains_key("boost"));
        assert!(!by_package.contains_key("cmake"));
        assert!(findings
            .iter()
            .all(|finding| finding.manifest == "conanfile.txt"));
    }

    #[test]
    fn analyzes_pubspec_yaml_dependency_versions() {
        let findings = analyze_manifest(
            ManifestKind::PubspecYaml,
            Path::new("/repo/pubspec.yaml"),
            PUBSPEC_YAML,
        );
        let by_package = finding_map(&findings);

        assert_eq!(by_package["http"].severity, DepHygieneSeverity::High);
        assert_eq!(
            by_package["collection"].severity,
            DepHygieneSeverity::Medium
        );
        assert_eq!(
            by_package["hosted_package"].severity,
            DepHygieneSeverity::High
        );
        assert_eq!(by_package["test"].severity, DepHygieneSeverity::High);
        assert!(!by_package.contains_key("path"));
        assert!(!by_package.contains_key("flutter"));
        assert!(findings
            .iter()
            .all(|finding| finding.manifest == "pubspec.yaml"));
    }

    #[test]
    fn analyzes_haxelib_json_dependency_versions() {
        let findings = analyze_manifest(
            ManifestKind::HaxelibJson,
            Path::new("/repo/haxelib.json"),
            HAXELIB_JSON,
        );
        let by_package = finding_map(&findings);

        assert_eq!(by_package["tink_core"].severity, DepHygieneSeverity::High);
        assert_eq!(by_package["hxnodejs"].severity, DepHygieneSeverity::Medium);
        assert_eq!(by_package["devlib"].severity, DepHygieneSeverity::High);
        assert!(!by_package.contains_key("utest"));
        assert!(findings
            .iter()
            .all(|finding| finding.manifest == "haxelib.json"));
    }

    #[test]
    fn analyzes_cpanfile_requirement_versions() {
        let findings = analyze_manifest(
            ManifestKind::Cpanfile,
            Path::new("/repo/cpanfile"),
            CPANFILE,
        );
        let by_package = finding_map(&findings);

        assert_eq!(by_package["Moo"].severity, DepHygieneSeverity::High);
        assert_eq!(by_package["DBI"].severity, DepHygieneSeverity::Medium);
        assert_eq!(by_package["Test::More"].severity, DepHygieneSeverity::High);
        assert!(!by_package.contains_key("Path::Tiny"));
        assert!(!by_package.contains_key("Safe::Bounded"));
        assert!(findings
            .iter()
            .all(|finding| finding.manifest == "cpanfile"));
    }

    #[test]
    fn analyzes_r_description_dependency_versions() {
        let findings = analyze_manifest(
            ManifestKind::RDescription,
            Path::new("/repo/DESCRIPTION"),
            R_DESCRIPTION,
        );
        let by_package = finding_map(&findings);

        assert_eq!(by_package["dplyr"].severity, DepHygieneSeverity::Medium);
        assert_eq!(by_package["ggplot2"].severity, DepHygieneSeverity::High);
        assert_eq!(by_package["jsonlite"].severity, DepHygieneSeverity::High);
        assert_eq!(by_package["Rcpp"].severity, DepHygieneSeverity::Medium);
        assert!(!by_package.contains_key("R"));
        assert!(!by_package.contains_key("httr"));
        assert!(findings
            .iter()
            .all(|finding| finding.manifest == "DESCRIPTION"));
    }

    #[test]
    fn analyzes_conda_environment_dependency_versions() {
        let findings = analyze_manifest(
            ManifestKind::CondaEnvironmentYml,
            Path::new("/repo/environment.yml"),
            CONDA_ENVIRONMENT,
        );
        let by_package = finding_map(&findings);

        assert_eq!(by_package["numpy"].severity, DepHygieneSeverity::Medium);
        assert_eq!(by_package["pandas"].severity, DepHygieneSeverity::High);
        assert_eq!(by_package["flask"].severity, DepHygieneSeverity::High);
        assert_eq!(by_package["requests"].severity, DepHygieneSeverity::Medium);
        assert!(!by_package.contains_key("python"));
        assert!(!by_package.contains_key("scipy"));
        assert!(!by_package.contains_key("safe-lib"));
        assert!(findings
            .iter()
            .all(|finding| finding.manifest == "environment.yml"));
    }

    #[test]
    fn analyzes_gleam_toml_dependency_versions() {
        let findings = analyze_manifest(
            ManifestKind::GleamToml,
            Path::new("/repo/gleam.toml"),
            GLEAM_TOML,
        );
        let by_package = finding_map(&findings);

        assert_eq!(
            by_package["gleam_stdlib"].severity,
            DepHygieneSeverity::Medium
        );
        assert_eq!(by_package["mist"].severity, DepHygieneSeverity::High);
        assert_eq!(by_package["gleeunit"].severity, DepHygieneSeverity::High);
        assert!(!by_package.contains_key("safe_hex"));
        assert!(findings
            .iter()
            .all(|finding| finding.manifest == "gleam.toml"));
    }

    #[test]
    fn analyzes_shard_yml_dependency_versions() {
        let findings = analyze_manifest(
            ManifestKind::ShardYml,
            Path::new("/repo/shard.yml"),
            SHARD_YML,
        );
        let by_package = finding_map(&findings);

        assert_eq!(by_package["kemal"].severity, DepHygieneSeverity::High);
        assert_eq!(by_package["pg"].severity, DepHygieneSeverity::Medium);
        assert_eq!(by_package["ameba"].severity, DepHygieneSeverity::High);
        assert!(!by_package.contains_key("safe_shard"));
        assert!(findings
            .iter()
            .all(|finding| finding.manifest == "shard.yml"));
    }

    #[test]
    fn analyzes_opam_dependency_versions() {
        let findings = analyze_manifest(
            ManifestKind::OpamFile,
            Path::new("/repo/demo.opam"),
            OPAM_FILE,
        );
        let by_package = finding_map(&findings);

        assert_eq!(by_package["ocaml"].severity, DepHygieneSeverity::Medium);
        assert_eq!(by_package["alcotest"].severity, DepHygieneSeverity::High);
        assert!(!by_package.contains_key("dune"));
        assert!(!by_package.contains_key("base64"));
        assert!(findings.iter().all(|finding| finding.manifest == "opam"));
    }

    #[test]
    fn analyzes_elm_json_dependency_versions() {
        let findings =
            analyze_manifest(ManifestKind::ElmJson, Path::new("/repo/elm.json"), ELM_JSON);
        let by_package = finding_map(&findings);

        assert_eq!(by_package["elm/core"].severity, DepHygieneSeverity::Medium);
        assert_eq!(by_package["elm/json"].severity, DepHygieneSeverity::High);
        assert_eq!(
            by_package["elm/virtual-dom"].severity,
            DepHygieneSeverity::High
        );
        assert_eq!(
            by_package["elm-explorations/test"].severity,
            DepHygieneSeverity::Medium
        );
        assert!(!by_package.contains_key("elm/html"));
        assert!(findings
            .iter()
            .all(|finding| finding.manifest == "elm.json"));
    }

    #[test]
    fn analyzes_mix_exs_dependency_versions() {
        let findings = analyze_manifest(ManifestKind::MixExs, Path::new("/repo/mix.exs"), MIX_EXS);
        let by_package = finding_map(&findings);

        assert_eq!(by_package["jason"].severity, DepHygieneSeverity::Medium);
        assert_eq!(by_package["devlib"].severity, DepHygieneSeverity::High);
        assert!(!by_package.contains_key("phoenix"));
        assert!(!by_package.contains_key("plug"));
        assert!(!by_package.contains_key("telemetry"));
        assert!(findings.iter().all(|finding| finding.manifest == "mix.exs"));
    }

    #[test]
    fn analyzes_nimble_dependency_versions() {
        let findings = analyze_manifest(
            ManifestKind::NimbleFile,
            Path::new("/repo/demo.nimble"),
            NIMBLE_FILE,
        );
        let by_package = finding_map(&findings);

        assert_eq!(by_package["nim"].severity, DepHygieneSeverity::Medium);
        assert_eq!(by_package["jester"].severity, DepHygieneSeverity::High);
        assert_eq!(
            by_package["chronicles"].severity,
            DepHygieneSeverity::Medium
        );
        assert_eq!(by_package["latestlib"].severity, DepHygieneSeverity::High);
        assert!(!by_package.contains_key("safe_pkg"));
        assert!(!by_package.contains_key("pinned"));
        assert!(findings.iter().all(|finding| finding.manifest == "nimble"));
    }

    #[test]
    fn analyzes_cabal_dependency_versions() {
        let findings = analyze_manifest(
            ManifestKind::CabalFile,
            Path::new("/repo/demo.cabal"),
            CABAL_FILE,
        );
        let by_package = finding_map(&findings);

        assert_eq!(by_package["text"].severity, DepHygieneSeverity::Medium);
        assert_eq!(by_package["aeson"].severity, DepHygieneSeverity::High);
        assert!(!by_package.contains_key("base"));
        assert!(!by_package.contains_key("bytestring"));
        assert!(findings.iter().all(|finding| finding.manifest == "cabal"));
    }

    #[test]
    fn analyzes_sbt_build_dependency_versions() {
        let findings = analyze_manifest(
            ManifestKind::SbtBuild,
            Path::new("/repo/build.sbt"),
            SBT_BUILD,
        );
        let by_package = finding_map(&findings);

        assert_eq!(
            by_package["ch.qos.logback/logback-classic"].severity,
            DepHygieneSeverity::High
        );
        assert_eq!(
            by_package["org.typelevel/cats-effect"].severity,
            DepHygieneSeverity::Medium
        );
        assert_eq!(
            by_package["org.scalatest/scalatest"].severity,
            DepHygieneSeverity::High
        );
        assert!(!by_package.contains_key("com.typesafe/config"));
        assert!(findings
            .iter()
            .all(|finding| finding.manifest == "build.sbt"));
    }

    #[test]
    fn analyzes_julia_project_dependency_compat() {
        let findings = analyze_manifest(
            ManifestKind::JuliaProjectToml,
            Path::new("/repo/Project.toml"),
            JULIA_PROJECT_TOML,
        );
        let by_package = finding_map(&findings);

        assert_eq!(by_package["HTTP"].severity, DepHygieneSeverity::Medium);
        assert_eq!(by_package["JSON3"].severity, DepHygieneSeverity::High);
        assert_eq!(
            by_package["MissingCompat"].severity,
            DepHygieneSeverity::High
        );
        assert!(!by_package.contains_key("SafePkg"));
        assert!(findings
            .iter()
            .all(|finding| finding.manifest == "Project.toml"));
    }

    #[test]
    fn analyzes_deno_import_map_versions() {
        let findings = analyze_manifest(
            ManifestKind::DenoJson,
            Path::new("/repo/deno.json"),
            DENO_IMPORT_MAP,
        );
        let by_package = finding_map(&findings);

        assert_eq!(by_package["lodash"].severity, DepHygieneSeverity::High);
        assert_eq!(by_package["left-pad"].severity, DepHygieneSeverity::High);
        assert_eq!(by_package["@oak/oak"].severity, DepHygieneSeverity::Medium);
        assert_eq!(by_package["@demo/wild"].severity, DepHygieneSeverity::High);
        assert!(!by_package.contains_key("safe-lib"));
        assert!(findings
            .iter()
            .all(|finding| finding.manifest == "deno.json"));
    }

    #[test]
    fn analyzes_cargo_toml_like_typescript_module() {
        let findings = analyze_manifest(
            ManifestKind::CargoToml,
            Path::new("/repo/Cargo.toml"),
            CARGO_TOML,
        );
        let by_package = finding_map(&findings);

        assert_eq!(by_package["serde"].severity, DepHygieneSeverity::High);
        assert_eq!(by_package["tokio"].severity, DepHygieneSeverity::Medium);
        assert!(!by_package.contains_key("anyhow"));
        assert!(!by_package.contains_key("proptest"));
    }

    #[test]
    fn analyzes_go_mod_like_typescript_module() {
        let findings = analyze_manifest(ManifestKind::GoMod, Path::new("/repo/go.mod"), GO_MOD);
        let by_package = finding_map(&findings);

        assert!(!by_package.contains_key("github.com/example/safe"));
        assert_eq!(
            by_package["github.com/example/commit-pin"].severity,
            DepHygieneSeverity::Medium
        );
        assert_eq!(
            by_package["github.com/example/floating"].severity,
            DepHygieneSeverity::High
        );
        assert_eq!(
            by_package["github.com/example/zero"].severity,
            DepHygieneSeverity::High
        );
    }

    #[test]
    fn check_dependency_hygiene_reads_root_manifests() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(tmp.path().join("package.json"), PACKAGE_JSON).unwrap();
        fs::write(tmp.path().join("pyproject.toml"), PYPROJECT_TOML).unwrap();
        fs::write(tmp.path().join("requirements.txt"), REQUIREMENTS_TXT).unwrap();
        fs::write(tmp.path().join("Pipfile"), PIPFILE).unwrap();
        fs::write(tmp.path().join("composer.json"), COMPOSER_JSON).unwrap();
        fs::write(tmp.path().join("Demo.csproj"), DOTNET_PROJECT).unwrap();
        fs::write(tmp.path().join("pom.xml"), MAVEN_POM).unwrap();
        fs::write(tmp.path().join("build.gradle"), GRADLE_BUILD).unwrap();
        fs::write(tmp.path().join("Gemfile"), GEMFILE).unwrap();
        fs::write(tmp.path().join("bower.json"), BOWER_JSON).unwrap();
        fs::write(tmp.path().join("conanfile.txt"), CONANFILE_TXT).unwrap();
        fs::write(tmp.path().join("pubspec.yaml"), PUBSPEC_YAML).unwrap();
        fs::write(tmp.path().join("haxelib.json"), HAXELIB_JSON).unwrap();
        fs::write(tmp.path().join("cpanfile"), CPANFILE).unwrap();
        fs::write(tmp.path().join("DESCRIPTION"), R_DESCRIPTION).unwrap();
        fs::write(tmp.path().join("environment.yml"), CONDA_ENVIRONMENT).unwrap();
        fs::write(tmp.path().join("gleam.toml"), GLEAM_TOML).unwrap();
        fs::write(tmp.path().join("shard.yml"), SHARD_YML).unwrap();
        fs::write(tmp.path().join("demo.opam"), OPAM_FILE).unwrap();
        fs::write(tmp.path().join("elm.json"), ELM_JSON).unwrap();
        fs::write(tmp.path().join("mix.exs"), MIX_EXS).unwrap();
        fs::write(tmp.path().join("demo.nimble"), NIMBLE_FILE).unwrap();
        fs::write(tmp.path().join("demo.cabal"), CABAL_FILE).unwrap();
        fs::write(tmp.path().join("build.sbt"), SBT_BUILD).unwrap();
        fs::write(tmp.path().join("Project.toml"), JULIA_PROJECT_TOML).unwrap();
        fs::write(tmp.path().join("deno.json"), DENO_IMPORT_MAP).unwrap();
        fs::write(tmp.path().join("Cargo.toml"), CARGO_TOML).unwrap();
        fs::write(tmp.path().join("go.mod"), GO_MOD).unwrap();

        let report = check_dependency_hygiene(tmp.path()).unwrap();

        assert_eq!(report.count, 86);
        assert!(report.output().contains("dep-hygiene: 86 risky specifiers"));
    }

    #[cfg(unix)]
    #[test]
    fn dependency_hygiene_rejects_symlinked_manifest_outside_target() {
        const OUTSIDE_TOKEN: &str = "OUTSIDE-DEPENDENCY-TOKEN";
        let target = tempfile::tempdir().unwrap();
        let outside = tempfile::NamedTempFile::new().unwrap();
        fs::write(outside.path(), OUTSIDE_TOKEN).unwrap();
        std::os::unix::fs::symlink(outside.path(), target.path().join("requirements.txt")).unwrap();

        let error = check_dependency_hygiene(target.path()).unwrap_err();

        assert!(!format!("{error:#}").contains(OUTSIDE_TOKEN));
    }

    #[test]
    fn dependency_hygiene_rejects_oversized_manifest_before_reading() {
        let target = tempfile::tempdir().unwrap();
        let path = target.path().join("requirements.txt");
        fs::write(&path, "safe==1\n").unwrap();
        fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(16 * 1024 * 1024 + 1)
            .unwrap();

        let error = check_dependency_hygiene(target.path()).unwrap_err();

        assert!(format!("{error:#}").contains("maximum supported size"));
    }

    #[test]
    fn scanner_converts_report_to_core_findings() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(
            tmp.path().join("package.json"),
            r#"{"dependencies":{"lodash":"latest"}}"#,
        )
        .unwrap();
        let scanner = DepHygieneScanner;
        let findings = scanner
            .scan(tmp.path(), &ScanCancellation::default())
            .unwrap();

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].tool, "dep-hygiene");
        assert_eq!(findings[0].severity, Severity::High);
        assert_eq!(findings[0].file_path, "package.json");
        assert_eq!(
            findings[0].static_proof_state,
            Some(StaticProofState::SignalOnly)
        );
        assert!(findings[0].message.contains("lodash@latest"));
    }

    #[test]
    fn distinct_packages_in_one_manifest_keep_distinct_finding_identities() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(
            tmp.path().join("package.json"),
            r#"{"dependencies":{"clarinet":"^0.12.6","z85":"^0.0.2"}}"#,
        )
        .unwrap();
        let findings = DepHygieneScanner
            .scan(tmp.path(), &ScanCancellation::default())
            .unwrap();

        assert_eq!(findings.len(), 2);
        assert_ne!(findings[0].fingerprint, findings[1].fingerprint);
        let locators = findings
            .iter()
            .map(|finding| finding.symbol_locator.clone().unwrap())
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(
            locators,
            ["package.json#clarinet", "package.json#z85"]
                .map(String::from)
                .into()
        );
    }

    #[test]
    fn rescanning_the_same_dependency_reproduces_its_fingerprint() {
        let tmp = tempfile::tempdir().unwrap();
        fs::write(
            tmp.path().join("package.json"),
            r#"{"dependencies":{"clarinet":"^0.12.6"}}"#,
        )
        .unwrap();
        let scan = || {
            DepHygieneScanner
                .scan(tmp.path(), &ScanCancellation::default())
                .unwrap()
        };

        assert_eq!(scan()[0].fingerprint, scan()[0].fingerprint);
    }

    #[test]
    fn missing_target_error_is_actionable() {
        let tmp = tempfile::tempdir().unwrap();
        let err = check_dependency_hygiene(&tmp.path().join("missing"))
            .unwrap_err()
            .to_string();

        assert!(err.contains("dep-hygiene: target does not exist"));
    }

    fn finding_map(
        findings: &[DepHygieneFinding],
    ) -> std::collections::BTreeMap<String, DepHygieneFinding> {
        findings
            .iter()
            .map(|finding| (finding.package_name.clone(), finding.clone()))
            .collect()
    }

    /// Captured shape of a real `cargo audit --json` document, narrowed to
    /// the fields the parser reads. Two advisories with different CVSS
    /// inputs to exercise score parsing and the textual fallback.
    const CARGO_AUDIT_FIXTURE: &str = r#"{
      "database": { "advisory_count": 0 },
      "lockfile": { "dependency_count": 1 },
      "settings": {},
      "vulnerabilities": {
        "found": true,
        "count": 2,
        "list": [
          {
            "advisory": {
              "id": "RUSTSEC-2020-0071",
              "package": "time",
              "title": "Potential segfault in localtime_r invocations",
              "cvss": "6.2"
            },
            "versions": { "patched": [">=0.2.23"], "unaffected": [] },
            "affected": null,
            "package": {
              "name": "time",
              "version": "0.1.40",
              "source": "registry+https://github.com/rust-lang/crates.io-index"
            }
          },
          {
            "advisory": {
              "id": "RUSTSEC-2099-0001",
              "package": "fakecrate",
              "title": "Hypothetical critical RCE",
              "cvss": "CRITICAL/AV:N/AC:L/PR:N"
            },
            "package": {
              "name": "fakecrate",
              "version": "1.0.0",
              "source": "registry+https://github.com/rust-lang/crates.io-index"
            }
          }
        ]
      },
      "warnings": {}
    }"#;

    #[test]
    fn parse_cargo_audit_emits_finding_per_advisory() {
        let findings = parse_cargo_audit_output(CARGO_AUDIT_FIXTURE).unwrap();
        assert_eq!(findings.len(), 2);
        let by_rule: std::collections::BTreeMap<_, _> = findings
            .iter()
            .map(|f| (f.rule_id.clone(), f.clone()))
            .collect();

        let time_finding = &by_rule["RUSTSEC-2020-0071"];
        assert_eq!(time_finding.tool, "cargo-audit");
        assert_eq!(time_finding.severity, Severity::Medium);
        assert_eq!(
            time_finding.static_proof_state,
            Some(StaticProofState::SignalOnly)
        );
        assert_eq!(time_finding.file_path, "Cargo.lock");
        assert!(time_finding.message.contains("time@0.1.40"));
        assert!(time_finding.message.contains("Potential segfault"));

        let fake_finding = &by_rule["RUSTSEC-2099-0001"];
        assert_eq!(fake_finding.severity, Severity::Critical);
        assert!(fake_finding.message.contains("fakecrate@1.0.0"));
    }

    #[test]
    fn cargo_audit_advisory_on_two_locked_versions_keeps_two_findings() {
        let fixture = CARGO_AUDIT_FIXTURE.replace(
            r#""id": "RUSTSEC-2099-0001""#,
            r#""id": "RUSTSEC-2020-0071""#,
        );
        let findings = parse_cargo_audit_output(&fixture).unwrap();

        assert_eq!(findings[0].rule_id, findings[1].rule_id);
        assert_ne!(findings[0].fingerprint, findings[1].fingerprint);
        assert_eq!(
            findings[1].symbol_locator.as_deref(),
            Some("Cargo.lock#fakecrate@1.0.0")
        );
    }

    #[test]
    fn parse_cargo_audit_returns_empty_for_invalid_json() {
        assert!(parse_cargo_audit_output("{ this is not json").is_err());
    }

    #[test]
    fn parse_cargo_audit_returns_empty_when_no_vulnerabilities_key() {
        assert!(
            parse_cargo_audit_output(r#"{"vulnerabilities":{"found":false}}"#)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn parse_cargo_audit_rejects_a_partially_invalid_advisory_list() {
        let output = r#"{
          "vulnerabilities": {
            "found": true,
            "list": [
              {"advisory":{"id":"RUSTSEC-1","title":"valid"},"package":{"name":"x","version":"1"}},
              {}
            ]
          }
        }"#;

        assert!(parse_cargo_audit_output(output).is_err());
    }

    #[test]
    fn cargo_audit_severity_buckets_match_cvss_score() {
        assert_eq!(severity_from_cvss(Some("9.8")), Severity::Critical);
        assert_eq!(severity_from_cvss(Some("7.5")), Severity::High);
        assert_eq!(severity_from_cvss(Some("5.0")), Severity::Medium);
        assert_eq!(severity_from_cvss(Some("2.1")), Severity::Low);
        assert_eq!(severity_from_cvss(Some("0.0")), Severity::Unknown);
        assert_eq!(severity_from_cvss(None), Severity::Medium);
        // Vector-style CVSS strings fall back to keyword detection.
        assert_eq!(
            severity_from_cvss(Some("CVSS:3.1/AV:N/AC:L/PR:N/C:H/I:H/A:H")),
            Severity::High
        );
        assert_eq!(severity_from_cvss(Some("medium")), Severity::Medium);
        assert_eq!(
            severity_from_cvss(Some("CVSS:3.1/AV:N/AC:L/C:L")),
            Severity::Low
        );
        assert_eq!(
            severity_from_cvss(Some("unscored vector")),
            Severity::Medium
        );
    }

    #[test]
    fn cargo_audit_scanner_no_lockfile_returns_empty() {
        let tmp = tempfile::tempdir().unwrap();
        // No Cargo.lock written. The scanner must short-circuit cleanly,
        // even when cargo-audit is missing from PATH (binary_available
        // is never reached because the lockfile gate fires first).
        let scanner = CargoAuditScanner;
        let findings = scanner
            .scan(tmp.path(), &ScanCancellation::default())
            .unwrap();
        assert!(findings.is_empty());
    }
}
