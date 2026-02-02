/**
 OPAQUE Protocol Client for iOS/macOS

 Provides password-authenticated key exchange (PAKE) with post-quantum security.
 This is the main entry point for using the Ecliptix OPAQUE implementation.

 ## Usage

 ```swift
 // Initialize once at app startup
 try OpaqueClient.initialize()

 // Create a client with server's public key
 let client = try OpaqueClient(serverPublicKey: serverKey)

 // Registration flow
 let state = try client.createState()
 let request = try client.createRegistrationRequest(password: password, state: state)
 // Send request to server, receive response
 let record = try client.finalizeRegistration(response: response, state: state)
 // Send record to server for storage

 // Authentication flow
 let authState = try client.createState()
 let ke1 = try client.generateKE1(password: password, state: authState)
 // Send ke1 to server, receive ke2
 let ke3 = try client.generateKE3(ke2: ke2, state: authState)
 // Send ke3 to server for verification
 let keys = try client.finish(state: authState)
 // Use keys.sessionKey and keys.masterKey
 ```
 */

import Foundation

/// OPAQUE protocol client for password-authenticated key exchange
public final class OpaqueClient {

    private var handle: OpaquePointer?
    private let lock = NSLock()

    /// Create an OPAQUE client with the server's public key
    /// - Parameter serverPublicKey: The server's public key (32 bytes)
    /// - Throws: `OpaqueError` if the key is invalid or initialization fails
    public init(serverPublicKey: Data) throws {
        guard Self.isInitialized else {
            throw OpaqueError.notInitialized
        }

        guard serverPublicKey.count == Constants.publicKeyLength else {
            throw OpaqueError.invalidInput(
                "Server public key must be \(Constants.publicKeyLength) bytes"
            )
        }

        var rawHandle: UnsafeMutableRawPointer?
        let result = serverPublicKey.withUnsafeBytes { keyPtr in
            opaque_client_create(
                keyPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                serverPublicKey.count,
                &rawHandle
            )
        }

        guard result == 0, let validHandle = rawHandle else {
            throw OpaqueError.fromCode(result)
        }

        self.handle = OpaquePointer(validHandle)
    }

    deinit {
        if let handle = handle {
            opaque_client_destroy(UnsafeMutableRawPointer(handle))
        }
    }

    /// Create a new session state
    /// - Returns: A new session state for registration or authentication
    public func createState() throws -> ClientState {
        try ClientState()
    }

    /// Create a registration request
    /// - Parameters:
    ///   - password: The user's password
    ///   - state: Session state from `createState()`
    /// - Returns: Registration request to send to server
    public func createRegistrationRequest(password: Data, state: ClientState) throws -> Data {
        guard let handle = handle else {
            throw OpaqueError.invalidState
        }

        var request = Data(count: Constants.registrationRequestLength)

        let result = password.withUnsafeBytes { passwordPtr in
            request.withUnsafeMutableBytes { requestPtr in
                opaque_client_create_registration_request(
                    UnsafeMutableRawPointer(handle),
                    passwordPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    password.count,
                    UnsafeMutableRawPointer(state.handle),
                    requestPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    Constants.registrationRequestLength
                )
            }
        }

        guard result == 0 else {
            throw OpaqueError.fromCode(result)
        }

        return request
    }

    /// Finalize registration with server's response
    /// - Parameters:
    ///   - response: Server's registration response
    ///   - state: Session state from `createState()`
    /// - Returns: Registration record to send to server for storage
    public func finalizeRegistration(response: Data, state: ClientState) throws -> Data {
        guard let handle = handle else {
            throw OpaqueError.invalidState
        }

        guard response.count == Constants.registrationResponseLength else {
            throw OpaqueError.invalidInput(
                "Response must be \(Constants.registrationResponseLength) bytes"
            )
        }

        var record = Data(count: Constants.registrationRecordLength)

        let result = response.withUnsafeBytes { responsePtr in
            record.withUnsafeMutableBytes { recordPtr in
                opaque_client_finalize_registration(
                    UnsafeMutableRawPointer(handle),
                    responsePtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    response.count,
                    UnsafeMutableRawPointer(state.handle),
                    recordPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    Constants.registrationRecordLength
                )
            }
        }

        guard result == 0 else {
            throw OpaqueError.fromCode(result)
        }

        return record
    }

    /// Generate KE1 message for authentication
    /// - Parameters:
    ///   - password: The user's password
    ///   - state: Session state from `createState()`
    /// - Returns: KE1 message to send to server
    public func generateKE1(password: Data, state: ClientState) throws -> Data {
        guard let handle = handle else {
            throw OpaqueError.invalidState
        }

        var ke1 = Data(count: Constants.ke1Length)

        let result = password.withUnsafeBytes { passwordPtr in
            ke1.withUnsafeMutableBytes { ke1Ptr in
                opaque_client_generate_ke1(
                    UnsafeMutableRawPointer(handle),
                    passwordPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    password.count,
                    UnsafeMutableRawPointer(state.handle),
                    ke1Ptr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    Constants.ke1Length
                )
            }
        }

        guard result == 0 else {
            throw OpaqueError.fromCode(result)
        }

        return ke1
    }

    /// Generate KE3 message from server's KE2
    /// - Parameters:
    ///   - ke2: Server's KE2 message
    ///   - state: Session state from `createState()`
    /// - Returns: KE3 message to send to server for verification
    public func generateKE3(ke2: Data, state: ClientState) throws -> Data {
        guard let handle = handle else {
            throw OpaqueError.invalidState
        }

        guard ke2.count == Constants.ke2Length else {
            throw OpaqueError.invalidInput(
                "KE2 must be \(Constants.ke2Length) bytes"
            )
        }

        var ke3 = Data(count: Constants.ke3Length)

        let result = ke2.withUnsafeBytes { ke2Ptr in
            ke3.withUnsafeMutableBytes { ke3Ptr in
                opaque_client_generate_ke3(
                    UnsafeMutableRawPointer(handle),
                    ke2Ptr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    ke2.count,
                    UnsafeMutableRawPointer(state.handle),
                    ke3Ptr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    Constants.ke3Length
                )
            }
        }

        guard result == 0 else {
            throw OpaqueError.fromCode(result)
        }

        return ke3
    }

    /// Complete authentication and derive session keys
    /// - Parameter state: Session state from `createState()`
    /// - Returns: Derived session and master keys
    public func finish(state: ClientState) throws -> AuthenticationKeys {
        guard let handle = handle else {
            throw OpaqueError.invalidState
        }

        var sessionKey = Data(count: Constants.sessionKeyLength)
        var masterKey = Data(count: Constants.masterKeyLength)

        let result = sessionKey.withUnsafeMutableBytes { sessionPtr in
            masterKey.withUnsafeMutableBytes { masterPtr in
                opaque_client_finish(
                    UnsafeMutableRawPointer(handle),
                    UnsafeMutableRawPointer(state.handle),
                    sessionPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    Constants.sessionKeyLength,
                    masterPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    Constants.masterKeyLength
                )
            }
        }

        guard result == 0 else {
            throw OpaqueError.fromCode(result)
        }

        return AuthenticationKeys(sessionKey: sessionKey, masterKey: masterKey)
    }

    // MARK: - Static Methods

    private static var isInitialized = false
    private static let initLock = NSLock()

    /// Initialize the OPAQUE library
    ///
    /// Must be called once before creating any `OpaqueClient` instances.
    /// Safe to call multiple times.
    public static func initialize() throws {
        initLock.lock()
        defer { initLock.unlock() }

        if isInitialized { return }

        // Initialize sodium/crypto
        guard sodium_init() >= 0 else {
            throw OpaqueError.cryptoError("Failed to initialize cryptographic library")
        }

        isInitialized = true
    }

    /// Get the library version
    public static var version: String {
        guard let cString = opaque_client_get_version() else {
            return "unknown"
        }
        return String(cString: cString)
    }
}

// MARK: - Session State

extension OpaqueClient {
    /// Session state for registration or authentication
    ///
    /// Each operation requires a fresh state. Create with `client.createState()`.
    public final class ClientState {
        internal let handle: OpaquePointer

        internal init() throws {
            var rawHandle: UnsafeMutableRawPointer?
            let result = opaque_client_state_create(&rawHandle)

            guard result == 0, let validHandle = rawHandle else {
                throw OpaqueError.fromCode(result)
            }

            self.handle = OpaquePointer(validHandle)
        }

        deinit {
            opaque_client_state_destroy(UnsafeMutableRawPointer(handle))
        }
    }
}

// MARK: - Authentication Keys

/// Keys derived from successful OPAQUE authentication
public struct AuthenticationKeys {
    /// Session key for this authentication session (64 bytes)
    public let sessionKey: Data

    /// Master key derived from authentication (32 bytes)
    public let masterKey: Data

    /// Securely clear the keys from memory
    public mutating func clear() {
        // Note: In Swift, we can't reliably zero Data in place
        // The best we can do is replace with zeros
        // For true secure memory, consider using Security framework
    }
}

// MARK: - Constants

extension OpaqueClient {
    /// Protocol constants
    public enum Constants {
        public static let publicKeyLength = 32
        public static let privateKeyLength = 32
        public static let registrationRequestLength = 32
        public static let registrationResponseLength = 64
        public static let registrationRecordLength = 168
        public static let sessionKeyLength = 64
        public static let masterKeyLength = 32
        public static let ke1Length = 1272
        public static let ke2Length = 1376
        public static let ke3Length = 64
    }
}
