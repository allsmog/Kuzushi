use super::*;

#[test]
fn flask_and_fastapi_receivers_keep_their_own_framework_in_a_mixed_file() {
    let bindings = PythonRouteFrameworks::from_source("from flask import Flask, Blueprint\nfrom fastapi import FastAPI, APIRouter\nweb = Flask(__name__)\nbp = Blueprint('notes', __name__)\napi = FastAPI()\nrouter = APIRouter()\n");
    assert_eq!(bindings.framework("web"), Some("Flask"));
    assert_eq!(bindings.framework("bp"), Some("Flask"));
    assert_eq!(bindings.framework("api"), Some("FastAPI"));
    assert_eq!(bindings.framework("router"), Some("FastAPI"));
}

#[test]
fn imported_constructor_and_module_aliases_resolve_without_dependency_guesses() {
    let bindings = PythonRouteFrameworks::from_source("from flask import Flask as Factory\nimport fastapi as api_lib\nweb: object = Factory(__name__)\napi = api_lib.FastAPI()\n");
    assert_eq!(bindings.framework("web"), Some("Flask"));
    assert_eq!(bindings.framework("api"), Some("FastAPI"));
    assert_eq!(bindings.framework("unknown"), None);
}

#[test]
fn ambiguous_rebinding_unknown_factories_and_shadowed_imports_stay_unclassified() {
    let bindings = PythonRouteFrameworks::from_source("from flask import Flask\nfrom fastapi import FastAPI\napp = Flask(__name__)\napp = FastAPI()\nother = create_app()\nFlask = custom_factory\nshadowed = Flask()\n");
    assert_eq!(bindings.framework("app"), None);
    assert_eq!(bindings.framework("other"), None);
    assert_eq!(bindings.framework("shadowed"), None);
}

#[test]
fn comments_and_route_syntax_alone_never_identify_a_framework() {
    let bindings = PythonRouteFrameworks::from_source(
        "# from fastapi import FastAPI\n@app.get('/health')\ndef health(): pass\n",
    );
    assert_eq!(bindings.framework("app"), None);
}

#[test]
fn locally_defined_constructor_names_do_not_inherit_the_imported_framework() {
    let bindings = PythonRouteFrameworks::from_source(
        "from fastapi import FastAPI\ndef FastAPI(): pass\napp = FastAPI()\n",
    );
    assert_eq!(bindings.framework("app"), None);
}
