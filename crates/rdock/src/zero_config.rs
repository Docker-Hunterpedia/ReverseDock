//! Zero-config mode (B-CFG-11, ADR-0018): `rdock run` with no configuration file serves the
//! routes of labelled Docker containers over plain HTTP on port 80. v0.3 adds HTTPS.

use std::path::{Path, PathBuf};

/// The configuration used when there is no file.
pub(crate) const CONFIG: &str = "\
listeners:
  web: { address: \":80\" }
defaults:
  listeners: [web]
  tls: off
providers:
  docker: {}
";

/// Where the configuration comes from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Source {
    /// A configuration file.
    File(PathBuf),
    /// No file: the built-in zero-config document.
    ZeroConfig,
}

impl Source {
    /// The file named on the command line or in `RDOCK_CONFIG`; otherwise the default file
    /// when it exists, else zero-config mode.
    pub(crate) fn choose(explicit: Option<&Path>, default: &Path) -> Self {
        match explicit {
            Some(path) => Self::File(path.to_owned()),
            None if default.exists() => Self::File(default.to_owned()),
            None => Self::ZeroConfig,
        }
    }

    /// How logs and the status name the source.
    pub(crate) fn describe(&self) -> String {
        match self {
            Self::File(path) => path.display().to_string(),
            Self::ZeroConfig => "(zero-config)".to_owned(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_built_in_configuration_is_valid_and_runnable() {
        let loaded = rdock_config::load_str(CONFIG, rdock_config::Format::Yaml).unwrap();
        assert!(!loaded.has_errors(), "{:?}", loaded.diagnostics);
        let mut gate = Vec::new();
        rdock_proxy::gate::check(&loaded.config, rdock_proxy::Mode::Run, &mut gate);
        assert_eq!(gate, Vec::new());
        assert!(loaded.config.providers.docker.is_some());
    }

    #[test]
    fn an_explicit_or_existing_file_wins() {
        let dir = tempfile::tempdir().unwrap();
        let default = dir.path().join("rdock.yaml");
        assert_eq!(Source::choose(None, &default), Source::ZeroConfig);
        let explicit = dir.path().join("other.yaml");
        assert_eq!(
            Source::choose(Some(&explicit), &default),
            Source::File(explicit)
        );
        std::fs::write(&default, "").unwrap();
        assert_eq!(
            Source::choose(None, &default),
            Source::File(default.clone())
        );
    }
}
