//! Request validation, transformation and the Vault secret store (F-GW-03, F-GW-04, W-OBS-02,
//! ADR-0030).

use serde_json::Value;

use super::{Validator, reference_key};
use crate::diagnostics::{Diagnostic, path_index};
use crate::middleware::Middleware;
use crate::route::Route;
use crate::secrets::VaultAuth;
use crate::transform::TransformConfig;
use crate::validation::{ValidateConfig, external_references};

impl Validator<'_> {
    pub(super) fn check_validate(&mut self, path: &str, v: &ValidateConfig) {
        if v.openapi.is_some() && v.has_inline() {
            self.push(
                Diagnostic::error(
                    path,
                    "`openapi` and inline schemas (`path`, `query`, `headers`, `cookies`, `body`) cannot be combined",
                )
                .with_hint("use two `validate` middlewares, or move the inline schemas into the document"),
            );
        }
        if v.openapi.is_none() && !v.has_inline() {
            self.error(
                path,
                "nothing to check: set `openapi` or at least one of `path`, `query`, `headers`, `cookies`, `body`",
            );
        }
        if v.openapi.is_none() && v.base_path.is_some() {
            self.warning(format!("{path}.base_path"), "only used with `openapi`");
        }
        if let Some(base) = &v.base_path
            && (!base.starts_with('/') || (base.len() > 1 && base.ends_with('/')))
        {
            self.error(
                format!("{path}.base_path"),
                "starts with `/` and does not end with `/`, e.g. `/api`",
            );
        }
        if let Some(params) = &v.path {
            self.check_regex(&format!("{path}.path.regex"), &params.regex);
            if !params.regex.contains("(?<") && !params.regex.contains("(?P<") {
                self.warning(
                    format!("{path}.path.regex"),
                    "no named group: the schema sees an empty object",
                );
            }
        }
        let inline = [
            ("path.schema", v.path.as_ref().map(|p| &p.schema)),
            ("query", v.query.as_ref()),
            ("headers", v.headers.as_ref()),
            ("cookies", v.cookies.as_ref()),
            ("body", v.body.as_ref()),
        ];
        for (field, schema) in inline {
            if let Some(schema) = schema {
                self.check_schema(&format!("{path}.{field}"), schema);
            }
        }
        if v.body_required && v.body.is_none() && v.openapi.is_none() {
            self.warning(format!("{path}.body_required"), "only used with `body`");
        }
        self.check_not_zero(&format!("{path}.max_body"), v.max_body.as_u64() == 0);
        if v.max_body > ValidateConfig::MAX_BODY {
            self.error(
                format!("{path}.max_body"),
                format!(
                    "at most {}: the body is kept in memory to be checked",
                    ValidateConfig::MAX_BODY
                ),
            );
        }
        if v.max_errors == 0 || v.max_errors > ValidateConfig::MAX_ERRORS {
            self.error(
                format!("{path}.max_errors"),
                format!("use 1 to {}", ValidateConfig::MAX_ERRORS),
            );
        }
    }

    /// An inline schema is an object or a boolean and refers to nothing outside itself:
    /// rdock never fetches a schema (no network, no files at request time).
    fn check_schema(&mut self, path: &str, schema: &Value) {
        if !matches!(schema, Value::Object(_) | Value::Bool(_)) {
            self.error(path, "a JSON Schema is an object or a boolean");
            return;
        }
        for (at, target) in external_references(schema) {
            self.push(
                Diagnostic::error(
                    format!("{path}{}", at.replace('/', ".")),
                    format!("`{target}` is outside the schema; only references inside it (`#/$defs/…`) are allowed"),
                )
                .with_hint("copy the referenced schema under `$defs` and refer to it as `#/$defs/<name>`"),
            );
        }
    }

    pub(super) fn check_transform(&mut self, path: &str, t: &TransformConfig) {
        for (side, rules) in [("request", &t.request), ("response", &t.response)] {
            self.check_header_rules(&format!("{path}.{side}.headers"), &rules.headers);
            for (i, op) in rules.body.patch.iter().enumerate() {
                if let Err(kind) = op.check() {
                    self.error(
                        path_index(&format!("{path}.{side}.body.patch"), i),
                        format!("`{}`: {kind}", op.name()),
                    );
                }
            }
        }
        let empty = |side: &crate::transform::TransformSide| {
            side.body.patch.is_empty()
                && side.headers.set.is_empty()
                && side.headers.add.is_empty()
                && side.headers.remove.is_empty()
        };
        if empty(&t.request) && empty(&t.response) {
            self.warning(path, "nothing to change: the middleware does nothing");
        }
        self.check_not_zero(&format!("{path}.max_body"), t.max_body.as_u64() == 0);
        if t.max_body > TransformConfig::MAX_BODY {
            self.error(
                format!("{path}.max_body"),
                format!(
                    "at most {}: the body is kept in memory to be patched",
                    TransformConfig::MAX_BODY
                ),
            );
        }
    }

    /// A route whose `validate` refuses operations outside its OpenAPI document refuses CORS
    /// preflights too, unless `cors` runs first and answers them.
    pub(super) fn check_route_validation(&mut self, path: &str, route: &Route) {
        let defined = |reference: &String| self.config.middlewares.get(reference_key(reference));
        let mut strict = None;
        let mut late_cors = None;
        for (i, reference) in route.middlewares.iter().enumerate() {
            match defined(reference) {
                Some(Middleware::Validate(v))
                    if v.openapi.is_some()
                        && v.unknown_operations == crate::validation::UnknownOperations::Deny
                        && strict.is_none() =>
                {
                    strict = Some(reference.clone());
                }
                Some(Middleware::Cors(_)) if strict.is_some() && late_cors.is_none() => {
                    late_cors = Some(i);
                }
                _ => {}
            }
        }
        if let (Some(validate), Some(i)) = (strict, late_cors) {
            self.warning(
                path_index(&format!("{path}.middlewares"), i),
                format!("`{validate}` refuses CORS preflights (`OPTIONS`) that its document does not list before this `cors` can answer them; put `cors` first"),
            );
        }
    }

    /// Secret fields of provider objects (M1 of the v0.8 review): a reference there would make
    /// rdock read a file, an environment variable or a Vault secret on behalf of a container
    /// label, a Kubernetes object or an API client. Only the API, whose writers are operators,
    /// may name `${file:…}` and `${env:…}` (documented for the configuration API); `${vault:…}`
    /// is read only for the configuration file. Errors leave the object out.
    pub(super) fn check_provider_secrets(&mut self) {
        if !self.merged {
            return;
        }
        let sections: [(&str, Vec<(&String, serde_json::Value)>); 3] = [
            ("middlewares", provider_objects(&self.config.middlewares)),
            ("services", provider_objects(&self.config.services)),
            ("certificates", provider_objects(&self.config.certificates)),
        ];
        for (section, objects) in sections {
            for (name, value) in objects {
                let provider = name.rsplit_once('@').map_or("file", |(_, p)| p);
                let mut keys = vec![section.to_owned(), name.clone()];
                let path = crate::diagnostics::path_key(section, name);
                self.provider_secret_walk(provider, &value, &mut keys, &path);
            }
        }
    }

    fn provider_secret_walk(
        &mut self,
        provider: &str,
        value: &serde_json::Value,
        keys: &mut Vec<String>,
        path: &str,
    ) {
        match value {
            serde_json::Value::String(text) => {
                let segments: Vec<&str> = keys.iter().map(String::as_str).collect();
                if crate::interpolation::field_kind(&segments)
                    != crate::interpolation::FieldKind::Secret
                    || !text.contains("${")
                {
                    return;
                }
                if provider == "api" && crate::secrets::vault_references(text).is_empty() {
                    return;
                }
                let message = if provider == "api" {
                    "`${vault:…}` is read only for the configuration file; write the secret, a `${file:…}` reference, or the reference in the file"
                } else {
                    "a secret field of a provider object cannot hold a `${…}` reference; the configuration file names files, variables and Vault secrets"
                };
                self.error(path, message);
            }
            serde_json::Value::Array(items) => {
                for (i, item) in items.iter().enumerate() {
                    keys.push("*".to_owned());
                    self.provider_secret_walk(provider, item, keys, &path_index(path, i));
                    keys.pop();
                }
            }
            serde_json::Value::Object(map) => {
                for (key, item) in map {
                    keys.push(key.clone());
                    let at = crate::diagnostics::path_key(path, key);
                    self.provider_secret_walk(provider, item, keys, &at);
                    keys.pop();
                }
            }
            _ => {}
        }
    }

    pub(super) fn check_secrets(&mut self) {
        let Some(vault) = &self.config.secrets.vault else {
            return;
        };
        let path = "secrets.vault";
        let address = vault.address.as_url();
        if !vault.address.is_https_or_loopback() {
            if vault.insecure_http {
                self.warning(
                    format!("{path}.insecure_http"),
                    "the Vault token and every secret cross the network unencrypted",
                );
            } else {
                self.push(
                    Diagnostic::error(
                        format!("{path}.address"),
                        "Vault is reached over `https://`, or `http://` only on a loopback address",
                    )
                    .with_hint("use https (with `ca_file` for a private CA); `insecure_http: true` allows plain HTTP and is unsafe"),
                );
            }
        }
        if address.path() != "/" || address.query().is_some() || address.fragment().is_some() {
            self.error(
                format!("{path}.address"),
                "the address is the server's root, without a path, query or fragment",
            );
        }
        if !address.username().is_empty() || address.password().is_some() {
            self.error(
                format!("{path}.address"),
                "the address must not carry credentials; use `auth`",
            );
        }
        if let Some(ns) = &vault.namespace
            && (ns.is_empty() || !ns.bytes().all(|b| b.is_ascii_graphic()))
        {
            self.error(
                format!("{path}.namespace"),
                "a namespace is a non-empty name without spaces",
            );
        }
        match &vault.auth {
            VaultAuth::Token(token) => {
                let at = format!("{path}.auth.token");
                if token.contains("${vault:") {
                    self.error(&at, "the Vault token cannot come from Vault");
                } else {
                    self.check_secret_reference(&at, token, "vault-token");
                }
            }
            VaultAuth::Kubernetes(k) => {
                let at = format!("{path}.auth.kubernetes");
                if k.role.trim().is_empty() {
                    self.error(format!("{at}.role"), "the role is empty");
                }
                if k.mount.is_empty()
                    || !k.mount.split('/').all(|s| {
                        !s.is_empty()
                            && s.bytes().all(|b| {
                                b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.')
                            })
                    })
                {
                    self.error(format!("{at}.mount"), "a mount path is `/`-separated names");
                }
                if !k.token_file.is_absolute() {
                    self.error(format!("{at}.token_file"), "must be an absolute path");
                }
            }
        }
        if vault.refresh.as_std() < std::time::Duration::from_secs(1) {
            self.error(format!("{path}.refresh"), "use at least 1s");
        } else if vault.refresh.as_std() < std::time::Duration::from_secs(10) {
            self.warning(
                format!("{path}.refresh"),
                "every reference is read this often; below 10s it mostly adds load on Vault",
            );
        }
        self.check_not_zero(&format!("{path}.timeout"), vault.timeout.is_zero());
        if vault.timeout.as_std() >= vault.refresh.as_std() {
            self.error(format!("{path}.timeout"), "must be shorter than `refresh`");
        }
    }
}

/// The objects of `section` that a provider other than the file owns, as JSON.
fn provider_objects<T: serde::Serialize>(
    section: &std::collections::BTreeMap<String, T>,
) -> Vec<(&String, serde_json::Value)> {
    section
        .iter()
        .filter(|(name, _)| name.rsplit_once('@').is_some_and(|(_, p)| p != "file"))
        .filter_map(|(name, object)| serde_json::to_value(object).ok().map(|v| (name, v)))
        .collect()
}
