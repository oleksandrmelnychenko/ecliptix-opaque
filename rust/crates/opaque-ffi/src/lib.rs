// Copyright (c) 2026 Oleksandr Melnychenko, Ukraine
// Ecliptix Security — Hybrid PQ-OPAQUE FFI Bindings
// Licensed under the MIT License

//! C-compatible FFI bindings for the Ecliptix Hybrid PQ-OPAQUE protocol.
//!
//! This crate exposes a flat, handle-based C API that wraps the safe Rust
//! implementation provided by `opaque-core`, `opaque-agent`, and `opaque-relay`.
//! It is intended for consumption from C, C#, and Android (JNI) hosts.
//!
//! All functions return `0` on success or a negative error code on failure.
//! Callers must initialize libsodium by calling [`opaque_init`] before
//! invoking any other function in this library.

mod agent_ffi;
mod relay_ffi;

use opaque_core::types::OpaqueResult;

/// Converts an `OpaqueResult<()>` into a C-friendly integer return code.
///
/// Returns `0` on `Ok(())` or a negative error code on `Err`.
pub(crate) fn result_to_int(r: OpaqueResult<()>) -> i32 {
    match r {
        Ok(()) => 0,
        Err(e) => e.to_c_int(),
    }
}
