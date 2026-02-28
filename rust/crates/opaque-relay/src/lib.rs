// Copyright (c) 2026 Oleksandr Melnychenko, Ukraine
// Ecliptix Security — Hybrid PQ-OPAQUE Relay (Responder)
// Licensed under the MIT License

//! Hybrid post-quantum OPAQUE relay (responder / server).
//!
//! This crate implements the responder side of the Ecliptix PQ-OPAQUE protocol,
//! covering both the registration and authenticated key-exchange (AKE) phases.
//! The protocol combines a classical 4DH exchange over Ristretto255 with
//! ML-KEM-768 encapsulation to achieve hybrid post-quantum security.

/// Password registration flow for the responder.
mod registration;
/// Authenticated key exchange (AKE) flow for the responder.
mod authentication;
/// Protocol state types and message containers used by the responder.
mod state;

pub use authentication::{generate_ke2, responder_finish};
pub use registration::{build_credentials, create_registration_response};
pub use state::{
    Ke2Message, OpaqueResponder, RegistrationResponse, ResponderCredentials, ResponderKeyPair,
    ResponderPhase, ResponderState,
};
