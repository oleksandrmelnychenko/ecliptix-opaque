// Copyright (c) 2026 Oleksandr Melnychenko, Ukraine
// Ecliptix Security — Hybrid PQ-OPAQUE Agent (Initiator)
// Licensed under the MIT License

mod registration;
mod authentication;
mod state;

pub use registration::{create_registration_request, finalize_registration};
pub use authentication::{generate_ke1, generate_ke3, initiator_finish};
pub use state::{
    InitiatorState, Ke1Message, Ke3Message, OpaqueInitiator, RegistrationRecord,
    RegistrationRequest,
};
