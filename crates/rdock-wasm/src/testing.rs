//! Signing helpers for tests (feature `testing`): a deterministic Ed25519 key that writes
//! public keys and `.minisig` files in minisign's format.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use blake2::{Blake2b512, Digest as _};
use ring::signature::{Ed25519KeyPair, KeyPair as _};

/// A test signing key derived from one seed byte.
pub struct TestKey {
    id: [u8; 8],
    pair: Option<Ed25519KeyPair>,
}

impl std::fmt::Debug for TestKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TestKey")
            .field("id", &self.id_hex())
            .finish_non_exhaustive()
    }
}

impl TestKey {
    /// The key for `seed`; the same seed gives the same key and key ID.
    #[must_use]
    pub fn new(seed: u8) -> Self {
        Self {
            id: [seed, 0x52, 0x44, 0x4f, 0x43, 0x4b, 0x00, seed],
            pair: Ed25519KeyPair::from_seed_unchecked(&[seed; 32]).ok(),
        }
    }

    /// The key ID as minisign prints it.
    #[must_use]
    pub fn id_hex(&self) -> String {
        use std::fmt::Write as _;
        self.id.iter().rev().fold(String::new(), |mut out, b| {
            let _ = write!(out, "{b:02X}");
            out
        })
    }

    /// The public key line (`RWQ…`), as `trusted_keys` takes it.
    #[must_use]
    pub fn public(&self) -> String {
        let mut bytes = b"Ed".to_vec();
        bytes.extend_from_slice(&self.id);
        if let Some(pair) = &self.pair {
            bytes.extend_from_slice(pair.public_key().as_ref());
        }
        STANDARD.encode(bytes)
    }

    fn raw_sign(&self, message: &[u8]) -> Vec<u8> {
        self.pair
            .as_ref()
            .map(|p| p.sign(message).as_ref().to_vec())
            .unwrap_or_default()
    }

    /// A `.minisig` file for `data`: prehashed (`ED`, minisign's default) or legacy (`Ed`).
    #[must_use]
    pub fn sign(&self, data: &[u8], prehashed: bool) -> String {
        let signature = if prehashed {
            self.raw_sign(&Blake2b512::digest(data))
        } else {
            self.raw_sign(data)
        };
        let trusted_comment = "timestamp:1762905600\tfile:plugin.wasm";
        let mut first = if prehashed {
            b"ED".to_vec()
        } else {
            b"Ed".to_vec()
        };
        first.extend_from_slice(&self.id);
        first.extend_from_slice(&signature);
        let mut global = signature;
        global.extend_from_slice(trusted_comment.as_bytes());
        let global = self.raw_sign(&global);
        format!(
            "untrusted comment: signature from rdock test key\n{}\ntrusted comment: {trusted_comment}\n{}\n",
            STANDARD.encode(first),
            STANDARD.encode(global)
        )
    }
}

/// What a test component does: WAT bodies of its core functions, and optional imports.
///
/// `on_request` is the body of `(func (param $args i32) (result i32) (local $p i32))`: `$args`
/// points at the lowered `(facts, request)` (the request's path pointer is at offset 48, its
/// length at 52) and the function returns a pointer to a `request-action`. `on_response` is
/// the body of a function with the 13 flattened `(facts, response)` parameters that returns a
/// pointer to a `(ptr, len)` list of `response-edit`s.
#[derive(Debug, Clone, Default)]
pub struct Guest<'a> {
    /// Component-level imports, `canon lower`s and the core instance `$env` they form.
    pub imports: &'a str,
    /// Core module imports (from `env`).
    pub core_imports: &'a str,
    /// The body of the core `on-request`.
    pub on_request: &'a str,
    /// The body of the core `on-response`.
    pub on_response: &'a str,
}

/// `on-request` that continues with `set-header x-wasm: yes`, or answers `403` with a text
/// body for the path `/blocked`.
pub const HEADER_ON_REQUEST: &str = r"
    (if (i32.and
          (i32.eq (i32.load offset=52 (local.get $args)) (i32.const 8))
          (i64.eq (i64.load (i32.load offset=48 (local.get $args))) (i64.const 0x64656b636f6c622f)))
      (then
        (i32.store8 (i32.const 512) (i32.const 1))
        (i32.store16 (i32.const 516) (i32.const 403))
        (i32.store (i32.const 520) (i32.const 600))
        (i32.store (i32.const 524) (i32.const 1))
        (i32.store (i32.const 600) (i32.const 160))
        (i32.store (i32.const 604) (i32.const 12))
        (i32.store (i32.const 608) (i32.const 144))
        (i32.store (i32.const 612) (i32.const 10))
        (i32.store (i32.const 528) (i32.const 112))
        (i32.store (i32.const 532) (i32.const 15))
        (return (i32.const 512))))
    (i32.store8 (i32.const 512) (i32.const 0))
    (i32.store (i32.const 516) (i32.const 640))
    (i32.store (i32.const 520) (i32.const 1))
    (i32.store8 (i32.const 640) (i32.const 0))
    (i32.store (i32.const 644) (i32.const 16))
    (i32.store (i32.const 648) (i32.const 6))
    (i32.store (i32.const 652) (i32.const 32))
    (i32.store (i32.const 656) (i32.const 3))
    (i32.const 512)
";

/// `on-response` that sets `x-wasm-response: yes`.
pub const HEADER_ON_RESPONSE: &str = r"
    (i32.store (i32.const 700) (i32.const 720))
    (i32.store (i32.const 704) (i32.const 1))
    (i32.store8 (i32.const 720) (i32.const 0))
    (i32.store (i32.const 724) (i32.const 48))
    (i32.store (i32.const 728) (i32.const 15))
    (i32.store (i32.const 732) (i32.const 32))
    (i32.store (i32.const 736) (i32.const 3))
    (i32.const 700)
";

/// `on-request` that continues without edits.
pub const CONTINUE: &str = r"
    (i32.store8 (i32.const 512) (i32.const 0))
    (i32.store (i32.const 516) (i32.const 0))
    (i32.store (i32.const 520) (i32.const 0))
    (i32.const 512)
";

/// `on-response` without edits.
pub const NO_EDITS: &str = r"
    (i32.store (i32.const 700) (i32.const 0))
    (i32.store (i32.const 704) (i32.const 0))
    (i32.const 700)
";

/// A body that never returns.
pub const LOOP: &str = "(loop $l (br $l)) unreachable";

/// A body that grows memory by 64 MiB.
pub const GROW: &str = "(drop (memory.grow (i32.const 1024))) unreachable";

/// A body that traps.
pub const TRAP: &str = "unreachable";

impl Guest<'_> {
    /// The header plugin (`HEADER_ON_REQUEST`, `HEADER_ON_RESPONSE`).
    #[must_use]
    pub fn header() -> Guest<'static> {
        Guest {
            on_request: HEADER_ON_REQUEST,
            on_response: HEADER_ON_RESPONSE,
            ..Guest::default()
        }
    }

    /// The component in WAT text (wasmtime compiles it with its `wat` feature).
    #[must_use]
    pub fn wat(&self) -> String {
        let on_request = if self.on_request.is_empty() {
            CONTINUE
        } else {
            self.on_request
        };
        let on_response = if self.on_response.is_empty() {
            NO_EDITS
        } else {
            self.on_response
        };
        let with = if self.imports.is_empty() {
            ""
        } else {
            r#"(with "env" (instance $env))"#
        };
        format!(
            r#"(component
  {imports}
  (core module $m
    {core_imports}
    (memory (export "memory") 1)
    (global $bump (mut i32) (i32.const 4096))
    (data (i32.const 16) "x-wasm")
    (data (i32.const 32) "yes")
    (data (i32.const 48) "x-wasm-response")
    (data (i32.const 80) "content-length")
    (data (i32.const 112) "denied by wasm\n")
    (data (i32.const 144) "text/plain")
    (data (i32.const 160) "content-type")
    (func (export "cabi_realloc") (param i32 i32 i32 i32) (result i32) (local $p i32)
      (local.set $p (i32.and
        (i32.add (global.get $bump) (i32.sub (local.get 2) (i32.const 1)))
        (i32.sub (i32.const 0) (local.get 2))))
      (global.set $bump (i32.add (local.get $p) (local.get 3)))
      (if (i32.gt_u (global.get $bump) (i32.mul (memory.size) (i32.const 65536)))
        (then
          (if (i32.eq
                (memory.grow (i32.sub
                  (i32.div_u (i32.add (global.get $bump) (i32.const 65535)) (i32.const 65536))
                  (memory.size)))
                (i32.const -1))
            (then unreachable))))
      (local.get $p))
    (func (export "on-request") (param $args i32) (result i32) (local $p i32)
      {on_request})
    (func (export "on-response")
      (param i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32 i32) (result i32)
      {on_response})
  )
  (core instance $i (instantiate $m {with}))
  (type $header-def (record (field "name" string) (field "value" (list u8))))
  (export $header "header" (type $header-def))
  (type $facts-def (record
    (field "client-ip" string) (field "route" string) (field "request-id" string)
    (field "tls" bool) (field "consumer" (option string))))
  (export $facts "facts" (type $facts-def))
  (type $request-def (record
    (field "method" string) (field "path" string) (field "query" (option string))
    (field "headers" (list $header))))
  (export $request "request" (type $request-def))
  (type $request-edit-def (variant
    (case "set-header" $header) (case "append-header" $header) (case "remove-header" string)
    (case "set-path" string) (case "set-query" (option string))))
  (export $request-edit "request-edit" (type $request-edit-def))
  (type $reply-def (record
    (field "status" u16) (field "headers" (list $header)) (field "body" (list u8))))
  (export $reply "reply" (type $reply-def))
  (type $request-action-def (variant
    (case "continue" (list $request-edit)) (case "respond" $reply)))
  (export $request-action "request-action" (type $request-action-def))
  (type $response-def (record (field "status" u16) (field "headers" (list $header))))
  (export $response "response" (type $response-def))
  (type $response-edit-def (variant
    (case "set-header" $header) (case "append-header" $header) (case "remove-header" string)
    (case "set-status" u16)))
  (export $response-edit "response-edit" (type $response-edit-def))
  (func $on-request (param "facts" $facts) (param "request" $request) (result $request-action)
    (canon lift (core func $i "on-request") (memory $i "memory")
      (realloc (func $i "cabi_realloc"))))
  (export "on-request" (func $on-request))
  (func $on-response (param "facts" $facts) (param "response" $response)
    (result (list $response-edit))
    (canon lift (core func $i "on-response") (memory $i "memory")
      (realloc (func $i "cabi_realloc"))))
  (export "on-response" (func $on-response))
)
"#,
            imports = self.imports,
            core_imports = self.core_imports,
        )
    }
}

/// The example guest's crate (`examples/plugins/wasm-header`).
#[must_use]
pub fn example_dir() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples/plugins/wasm-header")
}

/// Builds the example guest (`cargo build --release --locked --target wasm32-wasip2` in its
/// own directory, once per process) and returns the component's path. Needs the target:
/// `rustup target add wasm32-wasip2`.
pub fn build_example() -> Result<std::path::PathBuf, String> {
    static BUILT: std::sync::OnceLock<Result<std::path::PathBuf, String>> =
        std::sync::OnceLock::new();
    BUILT
        .get_or_init(|| {
            let dir = example_dir();
            let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
            let output = std::process::Command::new(cargo)
                .current_dir(&dir)
                .args(["build", "--release", "--locked", "--target", "wasm32-wasip2"])
                .arg("--target-dir")
                .arg(dir.join("target"))
                .env_remove("CARGO_TARGET_DIR")
                .env_remove("CARGO_ENCODED_RUSTFLAGS")
                .env_remove("RUSTFLAGS")
                .output()
                .map_err(|e| format!("running cargo: {e}"))?;
            if !output.status.success() {
                return Err(format!(
                    "building {} failed (is the target installed? `rustup target add wasm32-wasip2`):\n{}",
                    dir.display(),
                    String::from_utf8_lossy(&output.stderr)
                ));
            }
            Ok(dir.join("target/wasm32-wasip2/release/rdock_wasm_header.wasm"))
        })
        .clone()
}
