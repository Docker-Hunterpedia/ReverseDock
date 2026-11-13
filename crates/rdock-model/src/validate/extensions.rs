//! Checks of `plugin` and `agent` middlewares (F-EXT-02, F-EXT-04, ADR-0030). Whether a
//! plugin's name is registered and whether its `config` is valid are checked when the
//! configuration compiles, against the binary's plugin registry; the `protocol` values that
//! are planned are reported by the proxy's gate.

use super::Validator;
use crate::diagnostics::{Diagnostic, path_index};
use crate::middleware::{AgentConfig, HoldBodyConfig, PluginConfig, WasmConfig};
use crate::values::ByteSize;
use crate::values::is_token;

/// Whether a plugin name has the form registries accept (`rdock_plugin_api::Registry`).
fn valid_plugin_name(name: &str) -> bool {
    (1..=64).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
}

impl Validator<'_> {
    pub(super) fn check_plugin(&mut self, path: &str, plugin: &PluginConfig) {
        if !valid_plugin_name(&plugin.name) {
            self.error(
                format!("{path}.name"),
                format!(
                    "`{}` is not a plugin name: use 1 to 64 lower-case letters, digits, `_` or `-`",
                    plugin.name
                ),
            );
        }
    }

    pub(super) fn check_wasm(&mut self, path: &str, wasm: &WasmConfig) {
        if wasm.path.as_os_str().is_empty() {
            self.error(format!("{path}.path"), "the component file is required");
        }
        if wasm.sha256.len() != 64 || !wasm.sha256.bytes().all(|b| b.is_ascii_hexdigit()) {
            self.push(
                Diagnostic::error(
                    format!("{path}.sha256"),
                    "must be the file's SHA-256 digest: 64 hex digits",
                )
                .with_hint("`sha256sum <file>` prints it"),
            );
        }
        if wasm.allow_unsigned {
            self.push(
                Diagnostic::warning(
                    format!("{path}.allow_unsigned"),
                    "unsigned WASM modules are accepted: nothing proves who built this file, only that it matches its `sha256` pin",
                )
                .with_hint("sign the module with `minisign -S -m <file>` and list the public key in `trusted_keys`"),
            );
        } else if wasm.trusted_keys.is_empty() {
            self.push(
                Diagnostic::error(
                    format!("{path}.trusted_keys"),
                    "a WASM module must be signed by a trusted key: list at least one minisign public key",
                )
                .with_hint("the base64 line of the publisher's `.pub` file (`RWQ…`); `allow_unsigned: true` skips the check (unsafe)"),
            );
        }
        self.check_not_zero(&format!("{path}.fuel"), wasm.fuel == 0);
        self.check_not_zero(&format!("{path}.timeout"), wasm.timeout.is_zero());
        if wasm.timeout > WasmConfig::MAX_TIMEOUT {
            self.error(
                format!("{path}.timeout"),
                format!(
                    "at most {}: a call blocks a proxy worker thread while it runs",
                    WasmConfig::MAX_TIMEOUT
                ),
            );
        }
        if wasm.memory < ByteSize::kib(64) || wasm.memory > WasmConfig::MAX_MEMORY {
            self.error(
                format!("{path}.memory"),
                format!(
                    "between 64KiB (one WebAssembly page) and {}",
                    WasmConfig::MAX_MEMORY
                ),
            );
        }
        for (i, capability) in wasm.capabilities.iter().enumerate() {
            if wasm.capabilities[..i].contains(capability) {
                self.warning(
                    path_index(&format!("{path}.capabilities"), i),
                    "listed twice",
                );
            }
        }
    }

    pub(super) fn check_agent(&mut self, path: &str, agent: &AgentConfig) {
        if !agent.address.is_https_or_loopback() {
            self.push(
                Diagnostic::warning(
                    format!("{path}.address"),
                    "plain `http://` to a host that is not loopback: requests, their headers and bodies cross the network unencrypted",
                )
                .with_hint("use `https://`, or keep the agent on a private network (a Compose or Kubernetes network)"),
            );
        }
        if agent.address.as_url().scheme() != "https" && agent.tls.is_some() {
            self.warning(
                format!("{path}.tls"),
                "`tls` applies only to an `https://` address",
            );
        }
        if agent.tls.as_ref().is_some_and(|t| !t.verify) {
            self.warning(
                format!("{path}.tls.verify"),
                "the agent's certificate is not verified: anyone on the path can answer for it",
            );
        }
        self.check_not_zero(&format!("{path}.timeout"), agent.timeout.is_zero());
        if agent.max_body > HoldBodyConfig::MAX {
            self.error(
                format!("{path}.max_body"),
                format!(
                    "at most {}: the body is held in memory in full when it is sent",
                    HoldBodyConfig::MAX
                ),
            );
        }
        for (i, name) in agent.request_headers.iter().enumerate() {
            if name != "*" && !is_token(name) {
                self.error(
                    path_index(&format!("{path}.request_headers"), i),
                    format!("`{name}` is not a valid header name"),
                );
            }
        }
        for (i, name) in agent.response_headers.iter().enumerate() {
            let entry = path_index(&format!("{path}.response_headers"), i);
            let lower = name.to_ascii_lowercase();
            if !is_token(name) {
                self.error(entry, format!("`{name}` is not a valid header name"));
            } else if AgentConfig::is_protected_header(&lower) {
                self.error(
                    entry,
                    format!("`{name}` is managed by rdock and cannot be set by an agent"),
                );
            }
        }
        if !agent.response_headers.is_empty() && agent.max_body.as_u64() > 0 {
            self.push(
                Diagnostic::warning(
                    format!("{path}.response_headers"),
                    "headers from the agent are applied only to requests without a body: for a request with a body the verdict comes after the request head has gone to the backend",
                )
                .with_hint("set `max_body: 0` if the agent needs no body, or ignore this if body requests need no headers from it"),
            );
        }
        let breaker = &agent.breaker;
        if breaker.failures > 0 {
            self.check_not_zero(&format!("{path}.breaker.window"), breaker.window.is_zero());
            self.check_not_zero(
                &format!("{path}.breaker.open_for"),
                breaker.open_for.is_zero(),
            );
        }
    }
}
