#![doc = include_str!("../README.md")]

mod account;
mod alerts;
mod client;
mod cluster;
pub mod directory;
pub mod dns;
pub mod http;
mod issue;
pub mod local_ca;
mod local_issuer;
mod manager;
mod state;
pub mod storage;

pub use cluster::{ClusterAcme, MEMBER_TTL};
pub use issue::{AnswerSink, DnsChallenge, IssueError, Issued, LocalAnswers, OrderSpec, issue};
pub use local_ca::{LocalCa, LocalCaError};
pub use local_issuer::LocalIssuer;
pub use manager::{Manager, Plan, Services};
pub use state::CertStatus;
pub use storage::{CertMeta, Storage};

#[cfg(test)]
pub(crate) mod testing {
    /// A self-signed certificate for `name`: chain and key as PEM.
    pub(crate) fn self_signed(name: &str) -> (String, String) {
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = rcgen::CertificateParams::new(vec![name.to_owned()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        (cert.pem(), key.serialize_pem())
    }
}
