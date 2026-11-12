//! Cache policy as pure functions of request and response headers. Nothing here touches a
//! store or the network; each function is unit-tested against the RFC section it implements.

pub mod cache_control;
pub mod freshness;
pub mod invalidate;
pub mod key;
pub mod query;
pub mod request;
pub mod revalidate;
pub mod status;
pub mod storable;
pub mod tags;
pub mod vary;
