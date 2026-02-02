/**
 C function declarations for the OPAQUE native library

 These declarations match the C exports in initiator_exports.cpp.
 The actual implementations are provided by the XCFramework binary target.
 */

import Foundation

// MARK: - libsodium initialization

/// Initialize libsodium
/// Returns 0 on success, 1 if already initialized, -1 on failure
@_silgen_name("sodium_init")
internal func sodium_init() -> Int32

// MARK: - Client lifecycle

/// Create an OPAQUE client handle
/// - Parameters:
///   - server_public_key: Server's public key (32 bytes)
///   - key_length: Length of the public key
///   - handle: Output pointer to receive the handle
/// - Returns: 0 on success, negative error code on failure
@_silgen_name("opaque_client_create")
internal func opaque_client_create(
    _ server_public_key: UnsafePointer<UInt8>?,
    _ key_length: Int,
    _ handle: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> Int32

/// Destroy an OPAQUE client handle
@_silgen_name("opaque_client_destroy")
internal func opaque_client_destroy(_ handle: UnsafeMutableRawPointer?)

// MARK: - State lifecycle

/// Create a client state handle
@_silgen_name("opaque_client_state_create")
internal func opaque_client_state_create(
    _ handle: UnsafeMutablePointer<UnsafeMutableRawPointer?>?
) -> Int32

/// Destroy a client state handle
@_silgen_name("opaque_client_state_destroy")
internal func opaque_client_state_destroy(_ handle: UnsafeMutableRawPointer?)

// MARK: - Registration

/// Create a registration request
@_silgen_name("opaque_client_create_registration_request")
internal func opaque_client_create_registration_request(
    _ client_handle: UnsafeMutableRawPointer?,
    _ secure_key: UnsafePointer<UInt8>?,
    _ secure_key_length: Int,
    _ state_handle: UnsafeMutableRawPointer?,
    _ request_out: UnsafeMutablePointer<UInt8>?,
    _ request_length: Int
) -> Int32

/// Finalize registration
@_silgen_name("opaque_client_finalize_registration")
internal func opaque_client_finalize_registration(
    _ client_handle: UnsafeMutableRawPointer?,
    _ response: UnsafePointer<UInt8>?,
    _ response_length: Int,
    _ state_handle: UnsafeMutableRawPointer?,
    _ record_out: UnsafeMutablePointer<UInt8>?,
    _ record_length: Int
) -> Int32

// MARK: - Authentication

/// Generate KE1 message
@_silgen_name("opaque_client_generate_ke1")
internal func opaque_client_generate_ke1(
    _ client_handle: UnsafeMutableRawPointer?,
    _ secure_key: UnsafePointer<UInt8>?,
    _ secure_key_length: Int,
    _ state_handle: UnsafeMutableRawPointer?,
    _ ke1_out: UnsafeMutablePointer<UInt8>?,
    _ ke1_length: Int
) -> Int32

/// Generate KE3 message
@_silgen_name("opaque_client_generate_ke3")
internal func opaque_client_generate_ke3(
    _ client_handle: UnsafeMutableRawPointer?,
    _ ke2: UnsafePointer<UInt8>?,
    _ ke2_length: Int,
    _ state_handle: UnsafeMutableRawPointer?,
    _ ke3_out: UnsafeMutablePointer<UInt8>?,
    _ ke3_length: Int
) -> Int32

/// Finish authentication and derive keys
@_silgen_name("opaque_client_finish")
internal func opaque_client_finish(
    _ client_handle: UnsafeMutableRawPointer?,
    _ state_handle: UnsafeMutableRawPointer?,
    _ session_key_out: UnsafeMutablePointer<UInt8>?,
    _ session_key_length: Int,
    _ master_key_out: UnsafeMutablePointer<UInt8>?,
    _ master_key_length: Int
) -> Int32

// MARK: - Version

/// Get the library version string
@_silgen_name("opaque_client_get_version")
internal func opaque_client_get_version() -> UnsafePointer<CChar>?

// MARK: - Constants

/// Get KE1 message length
@_silgen_name("opaque_get_ke1_length")
internal func opaque_get_ke1_length() -> Int

/// Get KE2 message length
@_silgen_name("opaque_get_ke2_length")
internal func opaque_get_ke2_length() -> Int

/// Get KE3 message length
@_silgen_name("opaque_get_ke3_length")
internal func opaque_get_ke3_length() -> Int

/// Get registration record length
@_silgen_name("opaque_get_registration_record_length")
internal func opaque_get_registration_record_length() -> Int
