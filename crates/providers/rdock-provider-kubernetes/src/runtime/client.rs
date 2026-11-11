//! The client configuration (ADR-0029, "Crate and client"): `providers.kubernetes.kubeconfig`
//! when set; otherwise the in-cluster service account when running in a pod; otherwise the
//! kubeconfig named by `KUBECONFIG` or `~/.kube/config`.

use std::time::Duration;

use kube::config::{KubeConfigOptions, Kubeconfig};
use rdock_model::providers::KubernetesProvider;

use super::Error;

/// How long connecting to the API server may take.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// How long sending a request may take. Responses have no client-wide timeout (watches are
/// long-lived; kube's watcher has its own idle timeout); single calls are bounded by the
/// runtime ([`super::CALL_TIMEOUT`]).
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(30);

/// The client configuration for `settings`.
pub async fn config(settings: &KubernetesProvider) -> Result<kube::Config, Error> {
    let mut config = if let Some(path) = &settings.kubeconfig {
        let kubeconfig = Kubeconfig::read_from(path).map_err(|e| {
            Error::Config(format!(
                "cannot read `providers.kubernetes.kubeconfig` (`{}`): {e}",
                path.display()
            ))
        })?;
        kube::Config::from_custom_kubeconfig(kubeconfig, &KubeConfigOptions::default())
            .await
            .map_err(|e| {
                Error::Config(format!(
                    "cannot use `providers.kubernetes.kubeconfig` (`{}`): {e}",
                    path.display()
                ))
            })?
    } else if std::env::var_os("KUBERNETES_SERVICE_HOST").is_some() {
        kube::Config::incluster()
            .map_err(|e| Error::Config(format!("cannot use the pod's service account: {e}")))?
    } else {
        kube::Config::from_kubeconfig(&KubeConfigOptions::default())
            .await
            .map_err(|e| {
                Error::Config(format!(
                    "not running in a cluster (`KUBERNETES_SERVICE_HOST` is unset) and no usable \
                     kubeconfig (`KUBECONFIG`, `~/.kube/config`): {e}; set \
                     `providers.kubernetes.kubeconfig`"
                ))
            })?
    };
    config.connect_timeout = Some(CONNECT_TIMEOUT);
    config.write_timeout = Some(WRITE_TIMEOUT);
    direct(&mut config)?;
    Ok(config)
}

/// This build has no HTTP proxy support (kube's `http-proxy` feature is off, ADR-0029), and
/// kube takes `HTTPS_PROXY` for the API server whenever a kubeconfig is used, without
/// looking at `NO_PROXY`. A proxy from the environment is meant for the internet, rarely
/// for the API server: it is ignored with a warning. A proxy the kubeconfig itself names
/// (`proxy-url`) is refused, so the configuration never silently means something else.
fn direct(config: &mut kube::Config) -> Result<(), Error> {
    let Some(proxy) = config.proxy_url.take() else {
        return Ok(());
    };
    let from_env = ["HTTPS_PROXY", "https_proxy"]
        .iter()
        .filter_map(|name| std::env::var(name).ok())
        .any(|value| value.trim().trim_end_matches('/') == proxy.to_string().trim_end_matches('/'));
    if from_env {
        tracing::warn!(provider = crate::PROVIDER, %proxy,
            "`HTTPS_PROXY` is set, but the Kubernetes client has no proxy support; connecting to the API server directly");
        Ok(())
    } else {
        Err(Error::Config(format!(
            "the kubeconfig names a proxy (`proxy-url: {proxy}`), which this build does not support; \
             remove it to connect to the API server directly"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_missing_kubeconfig_file_is_a_configuration_error() {
        let settings = KubernetesProvider {
            kubeconfig: Some("/nonexistent/rdock/kubeconfig".into()),
            ..KubernetesProvider::default()
        };
        let err = config(&settings).await.unwrap_err();
        assert!(matches!(err, Error::Config(_)));
        assert!(
            err.to_string().contains("providers.kubernetes.kubeconfig"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn an_explicit_kubeconfig_is_used_with_its_namespace() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("kubeconfig");
        std::fs::write(
            &path,
            "apiVersion: v1\nkind: Config\nclusters: [{name: c, cluster: {server: \"https://127.0.0.1:6443\"}}]\n\
             users: [{name: u, user: {token: t}}]\n\
             contexts: [{name: x, context: {cluster: c, user: u, namespace: team-a}}]\ncurrent-context: x\n",
        )
        .unwrap();
        let settings = KubernetesProvider {
            kubeconfig: Some(path),
            ..KubernetesProvider::default()
        };
        let config = config(&settings).await.unwrap();
        assert_eq!(config.default_namespace, "team-a");
        assert_eq!(config.connect_timeout, Some(CONNECT_TIMEOUT));
        assert_eq!(config.proxy_url, None);
    }
}
