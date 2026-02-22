/**
 Errors thrown by OPAQUE protocol operations.

 Error codes match the Rust FFI `OpaqueError::to_c_int()` mapping.
 */

import Foundation

/// Errors that can occur during OPAQUE operations
public enum OpaqueError: Error, LocalizedError {
    /// The library has not been initialized
    case notInitialized

    /// Invalid input parameters (FFI code: -1)
    case invalidInput(String)

    /// Cryptographic operation failed (FFI code: -2)
    case cryptoError(String)

    /// Memory allocation failed (FFI code: -3)
    case memoryError

    /// Validation failed (FFI code: -4)
    case validationError

    /// Authentication failed — wrong password or tampering detected (FFI code: -5)
    case authenticationError

    /// Invalid public key format (FFI code: -6)
    case invalidPublicKey

    /// The agent or state handle has been invalidated
    case invalidState

    /// Unknown error with code
    case unknown(Int32)

    public var errorDescription: String? {
        switch self {
        case .notInitialized:
            return "OPAQUE library not initialized. Call OpaqueAgent.initialize() first."
        case .invalidInput(let details):
            return "Invalid input: \(details)"
        case .cryptoError(let details):
            return "Cryptographic error: \(details)"
        case .memoryError:
            return "Memory allocation failed"
        case .validationError:
            return "Validation failed"
        case .authenticationError:
            return "Authentication failed — wrong password or message tampering detected"
        case .invalidPublicKey:
            return "Invalid public key format"
        case .invalidState:
            return "Invalid handle — may have been destroyed"
        case .unknown(let code):
            return "Unknown error (code: \(code))"
        }
    }

    /// Create an error from a Rust FFI error code
    internal static func fromCode(_ code: Int32) -> OpaqueError {
        switch code {
        case 0:
            return .invalidState
        case -1:
            return .invalidInput("Invalid parameters")
        case -2:
            return .cryptoError("Cryptographic operation failed")
        case -3:
            return .memoryError
        case -4:
            return .validationError
        case -5:
            return .authenticationError
        case -6:
            return .invalidPublicKey
        default:
            return .unknown(code)
        }
    }
}
