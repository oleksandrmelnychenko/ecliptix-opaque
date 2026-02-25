// Copyright (c) 2026 Oleksandr Melnychenko, Ukraine
// Ecliptix Security — Hybrid PQ-OPAQUE Agent (Initiator)
// Licensed under the MIT License

//! Hybrid post-quantum OPAQUE agent (initiator / client).
//!
//! This crate implements the initiator side of the Ecliptix PQ-OPAQUE protocol,
//! covering both the registration and authenticated key-exchange (AKE) phases.
//! The protocol combines a classical 4DH exchange over Ristretto255 with
//! ML-KEM-768 encapsulation to achieve hybrid post-quantum security.

/// Password registration flow for the initiator.
mod registration;
/// Authenticated key exchange (AKE) flow for the initiator.
mod authentication;
/// Protocol state types and message containers used by the initiator.
mod state;

pub use registration::{create_registration_request, finalize_registration};
pub use authentication::{generate_ke1, generate_ke3, initiator_finish};
pub use state::{
    InitiatorState, Ke1Message, Ke3Message, OpaqueInitiator, RegistrationRecord,
    RegistrationRequest,
};
