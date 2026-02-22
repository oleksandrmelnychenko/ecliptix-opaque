// Copyright (c) 2026 Oleksandr Melnychenko, Ukraine
// Ecliptix Security — Hybrid PQ-OPAQUE Relay (Responder)
// Licensed under the MIT License

mod registration;
mod authentication;
mod state;

pub use authentication::{generate_ke2, responder_finish};
pub use registration::{build_credentials, create_registration_response};
pub use state::{
    Ke2Message, OpaqueResponder, RegistrationResponse, ResponderCredentials, ResponderKeyPair,
    ResponderState,
};
