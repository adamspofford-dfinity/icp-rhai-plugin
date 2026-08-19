//! A Rhai-facing wrapper around [`candid::Principal`].
//!
//! Registered under the script-visible name `Principal`. Scripts obtain one via
//! the `principal("aaaaa-aa")` / `principal_from_blob(blob)` constructors or the
//! injected `canister` / `identity` / `proxy` constants, and convert back with
//! `.to_text()` / `.to_blob()`.

use candid::Principal;
use rhai::{Blob, Engine, EvalAltResult};

/// Newtype so we can implement Rhai trait bindings on a foreign type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RhaiPrincipal(pub Principal);

impl From<Principal> for RhaiPrincipal {
    fn from(p: Principal) -> Self {
        Self(p)
    }
}

/// Register the `Principal` type and its constructors/methods on `engine`.
pub fn register(engine: &mut Engine) {
    engine.register_type_with_name::<RhaiPrincipal>("Principal");

    // Constructors.
    engine.register_fn(
        "principal",
        |text: &str| -> Result<RhaiPrincipal, Box<EvalAltResult>> {
            Principal::from_text(text)
                .map(RhaiPrincipal)
                .map_err(|e| format!("invalid principal '{text}': {e}").into())
        },
    );
    engine.register_fn(
        "principal_from_blob",
        |bytes: Blob| -> Result<RhaiPrincipal, Box<EvalAltResult>> {
            Principal::try_from_slice(&bytes)
                .map(RhaiPrincipal)
                .map_err(|e| format!("invalid principal bytes: {e}").into())
        },
    );

    // Accessors.
    engine.register_fn("to_text", |p: &mut RhaiPrincipal| p.0.to_text());
    engine.register_fn("to_blob", |p: &mut RhaiPrincipal| p.0.as_slice().to_vec());

    // Printing / comparison.
    engine.register_fn("to_string", |p: &mut RhaiPrincipal| p.0.to_text());
    engine.register_fn("to_debug", |p: &mut RhaiPrincipal| {
        format!("Principal({})", p.0.to_text())
    });
    engine.register_fn("==", |a: RhaiPrincipal, b: RhaiPrincipal| a == b);
    engine.register_fn("!=", |a: RhaiPrincipal, b: RhaiPrincipal| a != b);
}
