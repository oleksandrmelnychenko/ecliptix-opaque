/**
 C function declarations for the OPAQUE native library (Rust FFI)

 These declarations match the Rust `extern "C"` exports from opaque-ffi.
 The actual implementations are provided by the compiled Rust static/dynamic library.
 */

import Foundation

// MARK: - Initialization

/// Initialize the OPAQUE library (calls sodium_init internally).
/// Returns 0 on success, 1 if already initialized, -1 on failure.
@_silgen_name("opaque_init")
internal func opaque_init() -> Int32

// MARK: - Agent lifecycle

@_silgen_name("opaque_agent_create")
internal func opaque_agent_create(
    _ relay_public_key: UnsafePointer<UInt8>?,
    _ key_length: Int,
    _ handle: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> Int32

@_silgen_name("opaque_agent_destroy")
internal func opaque_agent_destroy(_ handle: UnsafeMutableRawPointer?)

// MARK: - Agent state lifecycle

@_silgen_name("opaque_agent_state_create")
internal func opaque_agent_state_create(
    _ handle: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> Int32

@_silgen_name("opaque_agent_state_destroy")
internal func opaque_agent_state_destroy(_ handle: UnsafeMutableRawPointer?)

// MARK: - Agent registration

@_silgen_name("opaque_agent_create_registration_request")
internal func opaque_agent_create_registration_request(
    _ agent_handle: UnsafeMutableRawPointer?,
    _ secure_key: UnsafePointer<UInt8>?,
    _ secure_key_length: Int,
    _ state_handle: UnsafeMutableRawPointer?,
    _ request_out: UnsafeMutablePointer<UInt8>?,
    _ request_length: Int
) -> Int32

@_silgen_name("opaque_agent_finalize_registration")
internal func opaque_agent_finalize_registration(
    _ agent_handle: UnsafeMutableRawPointer?,
    _ response: UnsafePointer<UInt8>?,
    _ response_length: Int,
    _ state_handle: UnsafeMutableRawPointer?,
    _ record_out: UnsafeMutablePointer<UInt8>?,
    _ record_length: Int
) -> Int32

// MARK: - Agent authentication

@_silgen_name("opaque_agent_generate_ke1")
internal func opaque_agent_generate_ke1(
    _ agent_handle: UnsafeMutableRawPointer?,
    _ secure_key: UnsafePointer<UInt8>?,
    _ secure_key_length: Int,
    _ state_handle: UnsafeMutableRawPointer?,
    _ ke1_out: UnsafeMutablePointer<UInt8>?,
    _ ke1_length: Int
) -> Int32

@_silgen_name("opaque_agent_generate_ke3")
internal func opaque_agent_generate_ke3(
    _ agent_handle: UnsafeMutableRawPointer?,
    _ ke2: UnsafePointer<UInt8>?,
    _ ke2_length: Int,
    _ state_handle: UnsafeMutableRawPointer?,
    _ ke3_out: UnsafeMutablePointer<UInt8>?,
    _ ke3_length: Int
) -> Int32

@_silgen_name("opaque_agent_finish")
internal func opaque_agent_finish(
    _ agent_handle: UnsafeMutableRawPointer?,
    _ state_handle: UnsafeMutableRawPointer?,
    _ session_key_out: UnsafeMutablePointer<UInt8>?,
    _ session_key_length: Int,
    _ master_key_out: UnsafeMutablePointer<UInt8>?,
    _ master_key_length: Int
) -> Int32

// MARK: - Agent constants

@_silgen_name("opaque_get_ke1_length")
internal func opaque_get_ke1_length() -> Int

@_silgen_name("opaque_get_ke2_length")
internal func opaque_get_ke2_length() -> Int

@_silgen_name("opaque_get_ke3_length")
internal func opaque_get_ke3_length() -> Int

@_silgen_name("opaque_get_registration_record_length")
internal func opaque_get_registration_record_length() -> Int

@_silgen_name("opaque_get_kem_public_key_length")
internal func opaque_get_kem_public_key_length() -> Int

@_silgen_name("opaque_get_kem_ciphertext_length")
internal func opaque_get_kem_ciphertext_length() -> Int

// MARK: - Relay keypair lifecycle

@_silgen_name("opaque_relay_keypair_generate")
internal func opaque_relay_keypair_generate(
    _ handle: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> Int32

@_silgen_name("opaque_relay_keypair_destroy")
internal func opaque_relay_keypair_destroy(_ handle: UnsafeMutableRawPointer?)

@_silgen_name("opaque_relay_keypair_get_public_key")
internal func opaque_relay_keypair_get_public_key(
    _ handle: UnsafeMutableRawPointer?,
    _ public_key: UnsafeMutablePointer<UInt8>?,
    _ key_buffer_size: Int
) -> Int32

// MARK: - Relay lifecycle

@_silgen_name("opaque_relay_create")
internal func opaque_relay_create(
    _ keypair_handle: UnsafeMutableRawPointer?,
    _ handle: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> Int32

@_silgen_name("opaque_relay_create_with_keys")
internal func opaque_relay_create_with_keys(
    _ private_key: UnsafePointer<UInt8>?,
    _ private_key_len: Int,
    _ public_key: UnsafePointer<UInt8>?,
    _ public_key_len: Int,
    _ handle: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> Int32

@_silgen_name("opaque_relay_destroy")
internal func opaque_relay_destroy(_ handle: UnsafeMutableRawPointer?)

// MARK: - Relay state lifecycle

@_silgen_name("opaque_relay_state_create")
internal func opaque_relay_state_create(
    _ handle: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> Int32

@_silgen_name("opaque_relay_state_destroy")
internal func opaque_relay_state_destroy(_ handle: UnsafeMutableRawPointer?)

// MARK: - Relay registration

@_silgen_name("opaque_relay_create_registration_response")
internal func opaque_relay_create_registration_response(
    _ relay_handle: UnsafeRawPointer?,
    _ request_data: UnsafePointer<UInt8>?,
    _ request_length: Int,
    _ account_id: UnsafePointer<UInt8>?,
    _ account_id_length: Int,
    _ response_data: UnsafeMutablePointer<UInt8>?,
    _ response_buffer_size: Int
) -> Int32

@_silgen_name("opaque_relay_build_credentials")
internal func opaque_relay_build_credentials(
    _ registration_record: UnsafePointer<UInt8>?,
    _ record_length: Int,
    _ credentials_out: UnsafeMutablePointer<UInt8>?,
    _ credentials_out_length: Int
) -> Int32

// MARK: - Relay authentication

@_silgen_name("opaque_relay_generate_ke2")
internal func opaque_relay_generate_ke2(
    _ relay_handle: UnsafeRawPointer?,
    _ ke1_data: UnsafePointer<UInt8>?,
    _ ke1_length: Int,
    _ account_id: UnsafePointer<UInt8>?,
    _ account_id_length: Int,
    _ credentials_data: UnsafePointer<UInt8>?,
    _ credentials_length: Int,
    _ ke2_data: UnsafeMutablePointer<UInt8>?,
    _ ke2_buffer_size: Int,
    _ state_handle: UnsafeRawPointer?
) -> Int32

@_silgen_name("opaque_relay_finish")
internal func opaque_relay_finish(
    _ relay_handle: UnsafeRawPointer?,
    _ ke3_data: UnsafePointer<UInt8>?,
    _ ke3_length: Int,
    _ state_handle: UnsafeRawPointer?,
    _ session_key: UnsafeMutablePointer<UInt8>?,
    _ session_key_buffer_size: Int,
    _ master_key_out: UnsafeMutablePointer<UInt8>?,
    _ master_key_buffer_size: Int
) -> Int32

// MARK: - Relay constants

@_silgen_name("opaque_relay_get_ke2_length")
internal func opaque_relay_get_ke2_length() -> Int

@_silgen_name("opaque_relay_get_registration_record_length")
internal func opaque_relay_get_registration_record_length() -> Int

@_silgen_name("opaque_relay_get_credentials_length")
internal func opaque_relay_get_credentials_length() -> Int

@_silgen_name("opaque_relay_get_kem_ciphertext_length")
internal func opaque_relay_get_kem_ciphertext_length() -> Int
