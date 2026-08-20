# icp-rhai-plugin

An [icp-cli](https://github.com/dfinity/icp-cli) **sync plugin** that runs a
[Rhai](https://rhai.rs) script against the canister being synced. It implements
the `icp:sync-plugin` WIT world (see [`sync-plugin.wit`](sync-plugin.wit)) and
exposes to the script roughly the same capabilities a native sync plugin has —
calling the target canister, the sync inputs, and read-only filesystem access —
plus Candid, principal, and encoding helpers convenient for canister work.

## Building

The plugin is a WebAssembly component targeting `wasm32-wasip2`:

```sh
rustup target add wasm32-wasip2
cargo build --target wasm32-wasip2 --release
```

The component is emitted at
`target/wasm32-wasip2/release/icp_rhai_plugin.wasm`.

## The script

The entry script comes from one of two places, and declaring both is an error:

- A **`script` field**, whose value is the Rhai source inline.
- A file declared under the **`script` key**, whose contents are the Rhai source.

```yaml
sync:
  steps:
    - plugin: ./icp_rhai_plugin.wasm
      files:
        script: sync.rhai
        seed: [seed/users.json, seed/roles.json]
      dirs:
        assets: assets
```

Every declared file — the entry script included — is read by the host and handed
to the script via the `files` map, keyed by path. Directories declared in `dirs`
are preopened read-only and reachable with the filesystem functions below.
Declaring `files:`/`dirs:` as a map instead of a plain list tags each entry with
its key, which the script reads back through `file_keys` / `dir_keys`.

A script runs to completion for a clean sync; throwing (or a runtime error)
fails the step with the thrown message.

## Scripting API

### Sync inputs (constants)

| Name            | Type                    | Description                                             |
| --------------- | ----------------------- | ------------------------------------------------------- |
| `canister_id`   | `String`                | Textual principal of the target canister.               |
| `canister`      | `Principal`             | The target canister as a `Principal`.                   |
| `environment`   | `String`                | Environment being synced (e.g. `"production"`).         |
| `identity_id`   | `String`                | Textual principal of the signing identity.              |
| `identity`      | `Principal`             | The signing identity as a `Principal`.                  |
| `proxy`         | `Principal` \| `()`     | Proxy canister if `--proxy` was set, else unit.         |
| `dirs`          | `Array` of `String`     | Declared directory paths (preopened read-only).         |
| `dir_keys`      | `Map` (key → `Array`)   | Manifest key → the directory paths declared under it.   |
| `files`         | `Map` (path → `String`) | Contents of every declared file, by path.               |
| `file_keys`     | `Map` (key → `Array`)   | Manifest key → the file paths declared under it.        |
| `fields`        | `Map` (name → `String`) | Key-value fields declared in the step's `fields`.       |
| `canister_ids`  | `Map` (name → `String`) | Every project canister's name → textual principal.      |

`dir_keys` and `file_keys` cover only the entries declared under a map key; a
plain-list `dirs:`/`files:` has none, and appears only in `dirs`/`files`. One key
may name several paths, so each maps to an array:

```js
// Contents of every file declared under the `seed` key.
let seeds = file_keys.seed.map(|path| files[path]);
```

`canister_ids` is informational: it maps each named canister in the project
(both `subproject:local` keys and bare local names for same-subproject siblings)
to its textual principal for the environment being synced. Being listed does not
grant permission to call a canister — that still requires declaring it in the
step's `canisters:` list. Wrap a value in `principal(..)` for a `Principal`, or
pass it straight to a call's `target`.

### Canister calls

By default a call targets the canister being synced (`canister_id`). A call may
instead target any canister declared as a dependency in the sync step's
`canisters:` list, via the `target` field (see below). Each call returns the raw
Candid-encoded response bytes as a `Blob`, or throws with the host's error
message.

```js
// Shorthands: empty-arg style is just candid_encode("()").
// These always target the canister being synced.
let resp = call_query("get_count", candid_encode("()"));
let resp = call_update("set_count", candid_encode("(7 : nat64)"));

// General form. Only `method` is required.
let resp = canister_call(#{
    method: "transfer",
    arg: candid_encode("(record { to = principal \"aaaaa-aa\"; amount = 10 : nat })"),
    query: false,   // default false → update; true → query
    direct: false,  // default false → route update through the proxy if configured
    cycles: 0,      // attached to a proxied update call only
    // target: omitted → the canister being synced. A string that parses as a
    // principal (or a Principal value) targets by id; any other string targets
    // by canister name. The target must be declared in `canisters:`.
    target: "ledger",
});
```

### Candid

```js
let bytes = candid_encode("(42 : nat64, \"hi\")"); // text value → Blob
let text  = candid_decode(bytes);                  // Blob → text (best-effort)
```

Number literals default to `int`/`nat`; annotate them (`42 : nat64`) when the
method signature needs a specific width. `candid_decode` reconstructs a
structural view without type information, so record fields appear as their
numeric hashes — it is meant for inspection, not round-tripping.

### Principals

```js
let p = principal("ryjl3-tyaaa-aaaaa-aaaba-cai"); // text → Principal (throws if invalid)
let q = principal_from_blob(p.to_blob());          // bytes → Principal
p.to_text();                                       // → String
p.to_blob();                                       // → Blob (raw bytes)
p == q;                                            // equality
```

### Encoding helpers

```js
to_hex(blob);        // Blob → hex String
from_hex("deadbeef"); // hex String → Blob
sha256(blob);         // Blob → 32-byte Blob

json_decode(`{"a":1}`); // JSON String → Dynamic (map/array/scalar)
json_encode(value);      // Dynamic → JSON String
```

### Filesystem

Read-only access to the preopened `dirs` is provided by
[`rhai-fs`](https://crates.io/crates/rhai-fs) (`open_file`, `read_string`,
`read_blob`, seeking, etc.):

```js
let f = open_file("assets/data.json", "r");
let text = f.read_string();
```

Writes fail because the host preopens directories read-only.

### Output

`print(..)` writes to stdout, shown as transient progress and discarded when
the step ends. `debug(..)` and `eprint(..)` write to stderr, which is also
printed persistently after the step completes — use them for warnings and
summaries the user should still see.

## Example

```js
// Bump a counter and report the new value.
let before = candid_decode(call_query("get", candid_encode("()")));
eprint("count before sync: " + before);

call_update("increment", candid_encode("()"));

let after = candid_decode(call_query("get", candid_encode("()")));
eprint("count after sync: " + after);
```
