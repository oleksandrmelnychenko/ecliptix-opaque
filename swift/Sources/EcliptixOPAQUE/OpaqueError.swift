/**
 Errors thrown by OPAQUE protocol operations
 */

import Foundation

/// Errors that can occur during OPAQUE operations
public enum OpaqueError: Error, LocalizedError {
    /// The library has not been initialized
    case notInitialized

    /// Invalid input parameters
    case invalidInput(String)

    /// Cryptographic operation failed
    case cryptoError(String)

    /// Memory allocation failed
    case memoryError

    /// Validation failed (e.g., invalid state)
    case validationError

    /// Authentication failed (wrong password or tampering detected)
    case authenticationError

    /// Invalid public key format
    case invalidPublicKey

    /// The client or state has been invalidated
    case invalidState

    /// Unknown error with code
    case unknown(Int32)

    public var errorDescription: String? {
        switch self {
        case .notInitialized:
            return "OPAQUE library not initialized. Call OpaqueClient.initialize() first."
        case .invalidInput(let details):
            return "Invalid input: \(details)"
        case .cryptoError(let details):
            return "Cryptographic error: \(details)"
        case .memoryError:
            return "Memory allocation failed"
        case .validationError:
            return "Validation failed"
        case .authenticationError:
            return "Authentication failed - wrong password or message tampering detected"
        case .invalidPublicKey:
            return "Invalid public key format"
        case .invalidState:
            return "Invalid client or state - may have been destroyed"
        case .unknown(let code):
            return "Unknown error (code: \(code))"
        }
    }

    /// Create an error from a native error code
    internal static func fromCode(_ code: Int32) -> OpaqueError {
        switch code {
        case 0:
            return .invalidState // Should not happen, but handle gracefully
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
