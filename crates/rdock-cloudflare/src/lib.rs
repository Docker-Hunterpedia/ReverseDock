#![doc = include_str!("../README.md")]

pub mod ips;
mod sync;

pub use ips::{BUILTIN, Cache, CacheError, InvalidList, IpList};
pub use sync::{API_URL, FetchError, INTERVAL, IpSync, Options, RETRY, Ranges};
