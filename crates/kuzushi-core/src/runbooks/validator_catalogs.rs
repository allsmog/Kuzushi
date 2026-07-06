use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidatorCatalogKind {
    Common,
    KernelC,
    GoWeb,
    TypeScriptNode,
    PythonWeb,
    JavaSpring,
}

pub fn validator_catalog(kind: ValidatorCatalogKind) -> &'static str {
    match kind {
        ValidatorCatalogKind::Common => COMMON_VALIDATORS,
        ValidatorCatalogKind::KernelC => KERNEL_C_VALIDATORS,
        ValidatorCatalogKind::GoWeb => GO_WEB_VALIDATORS,
        ValidatorCatalogKind::TypeScriptNode => TYPESCRIPT_NODE_VALIDATORS,
        ValidatorCatalogKind::PythonWeb => PYTHON_WEB_VALIDATORS,
        ValidatorCatalogKind::JavaSpring => JAVA_SPRING_VALIDATORS,
    }
}

pub const COMMON_VALIDATORS: &str = r#"Common validator/guard classes to check:
- route-level authn/authz middleware;
- schema validators and deserializers that reject invalid fields;
- parser-level bounds checks before per-handler dispatch;
- framework auto-escaping and context-sensitive encoders;
- content-type and file-type validators;
- allowlists and canonicalization order;
- privilege gates such as admin/superuser/role checks;
- feature flags and deployment constraints that make a path unreachable."#;

pub const KERNEL_C_VALIDATORS: &str = r#"C/C++ and kernel validator examples:
- dispatcher-level protocol validators before per-handler dispatch;
- length fields with u8/u16/u32 bit-width constraints;
- allocation-time guards such as checked struct-size calculations;
- parser functions that compute data-area length before copies;
- netlink, ioctl, packet, filesystem, or driver dispatch validators;
- object lifetime and reference-count ownership checks."#;

pub const GO_WEB_VALIDATORS: &str = r#"Go validator examples:
- chi/gin/echo/net/http middleware chains for auth, CSRF, request size, and content type;
- request binding and validation tags before handler use;
- database/sql placeholder semantics vs fmt.Sprintf/query concatenation;
- html/template contextual escaping vs text/template/raw HTML;
- context-based tenant/role checks propagated through service layers;
- path.Clean/filepath.Clean plus prefix checks after canonicalization."#;

pub const TYPESCRIPT_NODE_VALIDATORS: &str = r#"TypeScript/Node validator examples:
- Express/Fastify/Nest middleware and guards;
- zod/joi/class-validator schemas applied before controller/service calls;
- ORM parameterization vs raw query fragments;
- React/Next escaping vs dangerouslySetInnerHTML, raw template rendering, DOM sinks;
- multer/busboy upload filters plus storage path canonicalization;
- child_process exec vs execFile/spawn argument arrays."#;

pub const PYTHON_WEB_VALIDATORS: &str = r#"Python validator examples:
- Django/Flask/FastAPI route dependencies and decorators;
- pydantic/marshmallow/form validators before use;
- ORM parameterization vs raw SQL/text fragments;
- Jinja/Django auto-escape vs mark_safe/raw filters;
- pathlib/os.path canonicalization and prefix checks;
- subprocess shell=True vs argument-array execution."#;

pub const JAVA_SPRING_VALIDATORS: &str = r#"Java/Spring validator examples:
- Spring Security filters, method annotations, and role gates;
- Bean Validation annotations and controller binding;
- PreparedStatement/JPA parameters vs string-built JPQL/SQL;
- Thymeleaf/JSP escaping vs unescaped output;
- Path normalization and Zip Slip extraction guards;
- ProcessBuilder argument separation vs shell invocation."#;
