//! Builds the Rhai [`Engine`] the plugin runs scripts on, wiring in every
//! capability a sync plugin has: canister calls, the sync inputs, filesystem
//! access over WASI, and Candid/principal/encoding helpers.

use candid::Principal;
use candid_parser::parse_idl_args;
use rhai::packages::Package;
use rhai::{Blob, Dynamic, Engine, EvalAltResult, Map, Scope};
use rhai_fs::FilesystemPackage;
use sha2::{Digest, Sha256};

use crate::icp::sync_plugin::types::CallType;
use crate::principal::{self, RhaiPrincipal};
use crate::{CanisterCallRequest, SyncExecInput, canister_call};

/// Run the entry script found in `input.files` with all capabilities wired in.
/// Returns the plugin's `exec` result: `Ok(())` on a clean run, or a
/// human-readable error string on any failure.
pub fn run(input: SyncExecInput) -> Result<(), String> {
    // By contract the first declared file input is the Rhai entry script; the
    // remaining files stay available to the script via the `files` constant.
    let script = input
        .files
        .first()
        .ok_or("no script provided: the first file input must be the Rhai script")?;
    let script_name = script.name.clone();
    let script_src = script.content.clone();

    let engine = build_engine();
    let mut scope = build_scope(&input)?;

    engine
        .run_with_scope(&mut scope, &script_src)
        .map_err(|e| format!("{script_name}: {e}"))
}

/// Construct the engine and register every host-provided capability.
fn build_engine() -> Engine {
    let mut engine = Engine::new();

    // Script `print` is transient progress (stdout); `debug` and the explicit
    // `eprint` helper are persistent messages the user still sees after the step
    // completes (stderr). This mirrors the plugin stdio contract in the WIT docs.
    engine.on_print(|text| println!("{text}"));
    engine.on_debug(|text, _source, pos| {
        if pos.is_none() {
            eprintln!("{text}");
        } else {
            eprintln!("{text} (at {pos:?})");
        }
    });
    engine.register_fn("eprint", |text: &str| eprintln!("{text}"));

    // OS filesystem access (open_file/read_string/etc.), scoped by WASI to the
    // directories the host preopened from the manifest's `dirs`.
    FilesystemPackage::new().register_into_engine(&mut engine);

    principal::register(&mut engine);
    register_canister_calls(&mut engine);
    register_candid(&mut engine);
    register_encoding(&mut engine);

    engine
}

/// Register `canister_call` and its `call_update` / `call_query` shorthands.
fn register_canister_calls(engine: &mut Engine) {
    // The general form: `canister_call(#{ method, arg, query, direct, cycles })`.
    // Only `method` is required; the rest default to an empty-arg update call
    // routed through the proxy (if configured) with no cycles.
    engine.register_fn(
        "canister_call",
        |opts: Map| -> Result<Blob, Box<EvalAltResult>> {
            let method = opts
                .get("method")
                .ok_or_else(|| "canister_call: missing required `method`".to_string())?
                .clone()
                .into_string()
                .map_err(|t| format!("canister_call: `method` must be a string, got {t}"))?;

            let arg = match opts.get("arg") {
                Some(v) => v.clone().into_blob().map_err(|t| {
                    format!(
                        "canister_call: `arg` must be a blob (e.g. from candid_encode), got {t}"
                    )
                })?,
                None => Vec::new(),
            };

            let call_type = if map_bool(&opts, "query")? {
                CallType::Query
            } else {
                CallType::Update
            };
            let direct = map_bool(&opts, "direct")?;
            let cycles = map_cycles(&opts)?;

            host_call(method, arg, call_type, direct, cycles)
        },
    );

    engine.register_fn("call_update", |method: &str, arg: Blob| {
        host_call(method.to_string(), arg, CallType::Update, false, 0)
    });
    engine.register_fn("call_query", |method: &str, arg: Blob| {
        host_call(method.to_string(), arg, CallType::Query, false, 0)
    });
}

/// Register Candid textual encode/decode helpers.
fn register_candid(engine: &mut Engine) {
    // Encode a Candid value in text format (e.g. `"(42 : nat64, \"hi\")"`) to
    // argument bytes. Number literals default to `int`/`nat`; annotate them
    // (`42 : nat64`) when the method signature needs a specific width.
    engine.register_fn(
        "candid_encode",
        |text: &str| -> Result<Blob, Box<EvalAltResult>> {
            let args = parse_idl_args(text).map_err(|e| format!("candid_encode failed: {e}"))?;
            args.to_bytes()
                .map_err(|e| format!("candid_encode failed: {e}").into())
        },
    );

    // Decode Candid argument bytes back to their text representation. Without a
    // type it reconstructs a best-effort structural view, which is enough for
    // inspecting responses in a script.
    engine.register_fn(
        "candid_decode",
        |bytes: Blob| -> Result<String, Box<EvalAltResult>> {
            candid::IDLArgs::from_bytes(&bytes)
                .map(|args| args.to_string())
                .map_err(|e| format!("candid_decode failed: {e}").into())
        },
    );
}

/// Register general encoding helpers a canister script is likely to reach for.
fn register_encoding(engine: &mut Engine) {
    engine.register_fn("to_hex", |bytes: Blob| hex::encode(bytes));
    engine.register_fn(
        "from_hex",
        |text: &str| -> Result<Blob, Box<EvalAltResult>> {
            hex::decode(text).map_err(|e| format!("from_hex failed: {e}").into())
        },
    );
    engine.register_fn("sha256", |bytes: Blob| Sha256::digest(&bytes).to_vec());

    engine.register_fn(
        "json_decode",
        |text: &str| -> Result<Dynamic, Box<EvalAltResult>> {
            let value: serde_json::Value =
                serde_json::from_str(text).map_err(|e| format!("json_decode failed: {e}"))?;
            rhai::serde::to_dynamic(value)
        },
    );
    engine.register_fn(
        "json_encode",
        |value: Dynamic| -> Result<String, Box<EvalAltResult>> {
            serde_json::to_string(&value).map_err(|e| format!("json_encode failed: {e}").into())
        },
    );
}

/// Build the scope holding the sync inputs as script-visible constants.
fn build_scope(input: &SyncExecInput) -> Result<Scope<'static>, String> {
    let canister = Principal::from_text(&input.canister_id).map_err(|e| {
        format!(
            "host passed an invalid canister id '{}': {e}",
            input.canister_id
        )
    })?;
    let identity = Principal::from_text(&input.identity_principal).map_err(|e| {
        format!(
            "host passed an invalid identity principal '{}': {e}",
            input.identity_principal
        )
    })?;

    let files: Map = input
        .files
        .iter()
        .map(|f| (f.name.clone().into(), Dynamic::from(f.content.clone())))
        .collect();
    let dirs: rhai::Array = input
        .dirs
        .iter()
        .map(|d| Dynamic::from(d.clone()))
        .collect();

    let proxy: Dynamic = match &input.proxy_canister_id {
        Some(text) => {
            let p = Principal::from_text(text)
                .map_err(|e| format!("host passed an invalid proxy principal '{text}': {e}"))?;
            Dynamic::from(RhaiPrincipal(p))
        }
        None => Dynamic::UNIT,
    };

    let mut scope = Scope::new();
    scope
        .push_constant("canister_id", input.canister_id.clone())
        .push_constant("canister", RhaiPrincipal(canister))
        .push_constant("environment", input.environment.clone())
        .push_constant("identity_id", input.identity_principal.clone())
        .push_constant("identity", RhaiPrincipal(identity))
        .push_constant("proxy", proxy)
        .push_constant("dirs", dirs)
        .push_constant("files", files);
    Ok(scope)
}

/// Invoke the host `canister-call` import, mapping its error string into a Rhai
/// runtime error so scripts can `try`/`catch` or let it abort the run.
fn host_call(
    method: String,
    arg: Vec<u8>,
    call_type: CallType,
    direct: bool,
    cycles: u64,
) -> Result<Blob, Box<EvalAltResult>> {
    let req = CanisterCallRequest {
        method,
        arg,
        call_type,
        direct,
        cycles,
    };
    canister_call(&req).map_err(|e| format!("canister_call failed: {e}").into())
}

/// Read an optional boolean field from an options map, defaulting to `false`.
fn map_bool(opts: &Map, key: &str) -> Result<bool, Box<EvalAltResult>> {
    match opts.get(key) {
        Some(v) => v
            .as_bool()
            .map_err(|t| format!("canister_call: `{key}` must be a bool, got {t}").into()),
        None => Ok(false),
    }
}

/// Read the optional `cycles` field (a non-negative integer) from a map.
fn map_cycles(opts: &Map) -> Result<u64, Box<EvalAltResult>> {
    match opts.get("cycles") {
        Some(v) => {
            let n = v
                .as_int()
                .map_err(|t| format!("canister_call: `cycles` must be an integer, got {t}"))?;
            u64::try_from(n).map_err(|_| {
                "canister_call: `cycles` must be non-negative"
                    .to_string()
                    .into()
            })
        }
        None => Ok(0),
    }
}
