//! An example WASM plugin for ReverseDock (experimental, ADR-0030).
//!
//! It targets the world `rdock:plugin/filter@0.1.0` from `crates/rdock-wasm/wit`:
//!
//! - `on-request` answers `403` for the path `/blocked`, and otherwise passes the request on
//!   with `x-wasm: yes`;
//! - `on-response` adds `x-wasm-response: yes` and `x-wasm-request-id` (the request ID).
//!
//! The crate is `no_std`: Rust's standard library on `wasm32-wasip2` imports WASI (stdio,
//! clocks, environment), and rdock gives plugins no WASI. Memory comes from a bump allocator,
//! because every request gets a fresh instance whose memory is dropped afterwards.
//!
//! Build: `cargo build --release --target wasm32-wasip2` (after
//! `rustup target add wasm32-wasip2`).

#![no_std]
// The generated export glue takes the 13 flattened arguments of `on-response`.
#![allow(clippy::too_many_arguments)]

extern crate alloc;

use alloc::string::ToString as _;
use alloc::vec;
use alloc::vec::Vec;

wit_bindgen::generate!({
    path: "../../../crates/rdock-wasm/wit",
    world: "filter",
});

use rdock::plugin::types::{Header, Reply, RequestEdit};

struct HeaderPlugin;

fn header(name: &str, value: &[u8]) -> Header {
    Header {
        name: name.to_string(),
        value: value.to_vec(),
    }
}

impl Guest for HeaderPlugin {
    fn on_request(_facts: Facts, request: Request) -> RequestAction {
        if request.path == "/blocked" {
            return RequestAction::Respond(Reply {
                status: 403,
                headers: vec![header("content-type", b"text/plain")],
                body: b"denied by wasm\n".to_vec(),
            });
        }
        RequestAction::Continue(vec![RequestEdit::SetHeader(header("x-wasm", b"yes"))])
    }

    fn on_response(facts: Facts, _response: Response) -> Vec<ResponseEdit> {
        vec![
            ResponseEdit::SetHeader(header("x-wasm-response", b"yes")),
            ResponseEdit::SetHeader(header("x-wasm-request-id", facts.request_id.as_bytes())),
        ]
    }
}

export!(HeaderPlugin);

/// A bump allocator over the linear memory. Nothing is freed: the instance lives for one
/// request.
mod bump {
    use core::alloc::{GlobalAlloc, Layout};
    use core::arch::wasm32::{memory_grow, memory_size};
    use core::cell::UnsafeCell;

    const PAGE: usize = 65536;

    pub struct Bump(UnsafeCell<usize>);

    // SAFETY: a component instance runs on one thread.
    unsafe impl Sync for Bump {}

    #[global_allocator]
    static ALLOCATOR: Bump = Bump(UnsafeCell::new(0));

    // SAFETY: returns aligned, non-overlapping blocks inside the linear memory, or null.
    unsafe impl GlobalAlloc for Bump {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            // SAFETY: single-threaded (see `Sync`).
            // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage -- guest allocator, runs inside the sandbox (no_std has no safe one)
            let next = unsafe { &mut *self.0.get() };
            if *next == 0 {
                *next = memory_size(0) * PAGE;
            }
            let start = (*next + layout.align() - 1) & !(layout.align() - 1);
            let end = start + layout.size();
            let have = memory_size(0) * PAGE;
            if end > have && memory_grow(0, (end - have).div_ceil(PAGE)) == usize::MAX {
                return core::ptr::null_mut();
            }
            *next = end;
            start as *mut u8
        }

        unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {}
    }
}

/// The canonical ABI's allocator (the host copies arguments into the instance with it).
///
/// # Safety
///
/// Called by the host with a block this allocator returned (or null) and a valid alignment.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cabi_realloc(
    old: *mut u8,
    old_len: usize,
    align: usize,
    new_len: usize,
) -> *mut u8 {
    if new_len == 0 {
        return align as *mut u8;
    }
    let Ok(layout) = core::alloc::Layout::from_size_align(new_len, align) else {
        core::arch::wasm32::unreachable()
    };
    // SAFETY: `layout` has a non-zero size.
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage -- guest allocator, runs inside the sandbox (no_std has no safe one)
    let new = unsafe { alloc::alloc::alloc(layout) };
    if new.is_null() {
        core::arch::wasm32::unreachable()
    }
    if !old.is_null() {
        // SAFETY: both blocks are at least `min(old_len, new_len)` long and do not overlap.
        // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage -- guest allocator, runs inside the sandbox (no_std has no safe one)
        unsafe { core::ptr::copy_nonoverlapping(old, new, old_len.min(new_len)) };
    }
    new
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    core::arch::wasm32::unreachable()
}
