#![doc = include_str!("../README.md")]

mod alerting;
mod cache;
pub mod compile;
mod conn;
mod dns;
mod errorpage;
pub mod explain;
pub mod forwarded;
pub mod gate;
pub mod geoip;
mod health;
pub mod http3;
pub mod listener;
mod proxy;
pub mod proxy_protocol;
pub mod router;
pub mod runtime;
mod server;
pub mod tcp;
mod trace;
pub mod udp;
pub mod upstream;

pub use compile::{CompileEnv, Compiled, compile};
pub use gate::Mode;
#[doc(hidden)]
pub use proxy::fuzz_backend_response;
pub use runtime::Runtime;
pub use server::{
    ApplyError, DataPlane, InheritedSocket, ListenerHandle, ListenerStatus, random_key,
};
