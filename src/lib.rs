//! An icp-cli sync plugin that runs a Rhai script against the canister being
//! synced.
//!
//! The plugin exposes to the script the same capabilities a native sync plugin
//! has — calling the target canister, the sync inputs, and read-only filesystem
//! access to the manifest's `dirs` — plus Candid, principal, and encoding
//! helpers convenient for canister work. See [`engine`] for the wiring.

wit_bindgen::generate!({
    world: "sync-plugin",
    path: "sync-plugin.wit",
});

mod engine;
mod principal;

struct RhaiPlugin;

impl Guest for RhaiPlugin {
    fn exec(input: SyncExecInput) -> Result<(), String> {
        engine::run(input)
    }
}

export!(RhaiPlugin);
