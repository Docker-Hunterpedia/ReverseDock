//! A minimal plugin: adds `X-Greeting: <config.text>` to every request it lets through.
//!
//! ```yaml
//! middlewares:
//!   hello: { type: plugin, name: greeting, config: { text: "hello from my plugin" } }
//! ```

use rdock_plugin_api::{
    Capabilities, ConfigError, Ctx, Decision, Factory, Phases, Plugin, RequestHead, async_trait,
    typed,
};
use serde::Deserialize;

/// The configuration under `config:`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// The header's value.
    pub text: String,
}

/// The plugin.
#[derive(Debug)]
pub struct Greeting {
    text: String,
}

/// The factory `main` registers.
pub fn factory() -> impl Factory {
    typed(|config: Config| {
        if config.text.trim().is_empty() {
            return Err(ConfigError::at("text", "must not be empty"));
        }
        if config.text.contains(['\r', '\n']) {
            return Err(ConfigError::at("text", "must be one line"));
        }
        Ok(Greeting { text: config.text })
    })
}

#[async_trait]
impl Plugin for Greeting {
    fn capabilities(&self) -> Capabilities {
        Capabilities::new(Phases::REQUEST)
    }

    async fn request(&self, req: &mut RequestHead, _cx: &mut Ctx<'_>) -> Decision {
        // The value was checked when the configuration was loaded.
        let _ = req.set_header("x-greeting", self.text.as_str());
        Decision::Continue
    }
}

#[cfg(test)]
mod tests {
    use rdock_plugin_api::serde_json::json;
    use rdock_plugin_api::testing::{Harness, block_on, request};

    use super::*;

    #[test]
    fn adds_the_header() {
        let mut harness = Harness::from_factory(&factory(), &json!({ "text": "hi" })).unwrap();
        let mut req = request("GET", "/");
        assert!(block_on(harness.request(&mut req)).is_continue());
        assert_eq!(req.header("x-greeting"), Some("hi"));
    }

    #[test]
    fn refuses_bad_configuration() {
        let err = Harness::from_factory(&factory(), &json!({ "text": "" })).unwrap_err();
        assert_eq!(err.issues()[0].path, "text");
        assert!(Harness::from_factory(&factory(), &json!({ "txt": "hi" })).is_err());
    }
}
