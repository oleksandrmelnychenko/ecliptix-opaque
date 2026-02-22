/**
 OPAQUE Protocol Relay (Server) for iOS/macOS

 Provides server-side OPAQUE operations for password-authenticated key exchange.

 ## Usage

 ```swift
 // Generate or restore a keypair
 let keypair = try OpaqueRelay.KeyPair.generate()
 let publicKey = try keypair.publicKey()

 // Create relay with keypair
 let relay = try OpaqueRelay(keypair: keypair)

 // -- or restore from stored keys --
 let relay = try OpaqueRelay(privateKey: storedPrivateKey, publicKey: storedPublicKey)

 // Registration flow
 let response = try relay.createRegistrationResponse(
     request: clientRequest, accountId: accountId)
 // Send response to agent, receive record back
 let credentials = try OpaqueRelay.buildCredentials(record: registrationRecord)

 // Authentication flow
 let state = try relay.createState()
 let ke2 = try relay.generateKE2(
     ke1: ke1, accountId: accountId, credentials: credentials, state: state)
 // Send ke2 to agent, receive ke3 back
 let keys = try relay.finish(ke3: ke3, state: state)
 // Use keys.sessionKey and keys.masterKey
 ```
 */

import Foundation

/// OPAQUE protocol relay (server) for password-authenticated key exchange
public final class OpaqueRelay: @unchecked Sendable {

    private var handle: OpaquePointer?
    private let lock = NSLock()

    /// Create an OPAQUE relay from a generated keypair
    /// - Parameter keypair: A `KeyPair` generated via `KeyPair.generate()`
    /// - Throws: `OpaqueError` on failure
    public init(keypair: KeyPair) throws {
        var rawHandle: UnsafeMutableRawPointer?
        let result = opaque_relay_create(
            UnsafeMutableRawPointer(keypair.handle),
            &rawHandle
        )

        guard result == 0, let validHandle = rawHandle else {
            throw OpaqueError.fromCode(result)
        }

        self.handle = OpaquePointer(validHandle)
    }

    /// Create an OPAQUE relay from stored key material
    /// - Parameters:
    ///   - privateKey: Ristretto255 private key (32 bytes)
    ///   - publicKey: Ristretto255 public key (32 bytes)
    /// - Throws: `OpaqueError` if keys are invalid
    public init(privateKey: Data, publicKey: Data) throws {
        guard privateKey.count == OpaqueAgent.Constants.privateKeyLength else {
            throw OpaqueError.invalidInput(
                "Private key must be \(OpaqueAgent.Constants.privateKeyLength) bytes"
            )
        }
        guard publicKey.count == OpaqueAgent.Constants.publicKeyLength else {
            throw OpaqueError.invalidInput(
                "Public key must be \(OpaqueAgent.Constants.publicKeyLength) bytes"
            )
        }

        var rawHandle: UnsafeMutableRawPointer?
        let result = privateKey.withUnsafeBytes { skPtr in
            publicKey.withUnsafeBytes { pkPtr in
                opaque_relay_create_with_keys(
                    skPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    privateKey.count,
                    pkPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    publicKey.count,
                    &rawHandle
                )
            }
        }

        guard result == 0, let validHandle = rawHandle else {
            throw OpaqueError.fromCode(result)
        }

        self.handle = OpaquePointer(validHandle)
    }

    deinit {
        if let handle = handle {
            opaque_relay_destroy(UnsafeMutableRawPointer(handle))
        }
    }

    /// Create a new session state for authentication
    public func createState() throws -> RelayState {
        try RelayState()
    }

    /// Create a registration response for the agent's request
    /// - Parameters:
    ///   - request: Agent's registration request (32 bytes)
    ///   - accountId: Unique account identifier
    /// - Returns: Registration response to send to agent
    public func createRegistrationResponse(request: Data, accountId: Data) throws -> Data {
        guard let handle = handle else {
            throw OpaqueError.invalidState
        }

        guard request.count == OpaqueAgent.Constants.registrationRequestLength else {
            throw OpaqueError.invalidInput(
                "Request must be \(OpaqueAgent.Constants.registrationRequestLength) bytes"
            )
        }

        var response = Data(count: OpaqueAgent.Constants.registrationResponseLength)

        let result = request.withUnsafeBytes { reqPtr in
            accountId.withUnsafeBytes { aidPtr in
                response.withUnsafeMutableBytes { respPtr in
                    opaque_relay_create_registration_response(
                        UnsafeRawPointer(handle),
                        reqPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        request.count,
                        aidPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        accountId.count,
                        respPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        OpaqueAgent.Constants.registrationResponseLength
                    )
                }
            }
        }

        guard result == 0 else {
            throw OpaqueError.fromCode(result)
        }

        return response
    }

    /// Build credentials from a stored registration record
    /// - Parameter record: The registration record received from agent
    /// - Returns: Credentials bytes for use in authentication
    public static func buildCredentials(record: Data) throws -> Data {
        guard record.count >= OpaqueAgent.Constants.registrationRecordLength else {
            throw OpaqueError.invalidInput(
                "Record must be at least \(OpaqueAgent.Constants.registrationRecordLength) bytes"
            )
        }

        let credentialsLength = OpaqueAgent.Constants.registrationRecordLength
        var credentials = Data(count: credentialsLength)

        let result = record.withUnsafeBytes { recPtr in
            credentials.withUnsafeMutableBytes { credPtr in
                opaque_relay_build_credentials(
                    recPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    record.count,
                    credPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    credentialsLength
                )
            }
        }

        guard result == 0 else {
            throw OpaqueError.fromCode(result)
        }

        return credentials
    }

    /// Generate KE2 message for authentication
    /// - Parameters:
    ///   - ke1: Agent's KE1 message
    ///   - accountId: Account identifier
    ///   - credentials: Credentials from `buildCredentials(record:)`
    ///   - state: Session state from `createState()`
    /// - Returns: KE2 message to send to agent
    public func generateKE2(
        ke1: Data,
        accountId: Data,
        credentials: Data,
        state: RelayState
    ) throws -> Data {
        guard let handle = handle else {
            throw OpaqueError.invalidState
        }

        guard ke1.count == OpaqueAgent.Constants.ke1Length else {
            throw OpaqueError.invalidInput(
                "KE1 must be \(OpaqueAgent.Constants.ke1Length) bytes"
            )
        }

        var ke2 = Data(count: OpaqueAgent.Constants.ke2Length)

        let result = ke1.withUnsafeBytes { ke1Ptr in
            accountId.withUnsafeBytes { aidPtr in
                credentials.withUnsafeBytes { credPtr in
                    ke2.withUnsafeMutableBytes { ke2Ptr in
                        opaque_relay_generate_ke2(
                            UnsafeRawPointer(handle),
                            ke1Ptr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                            ke1.count,
                            aidPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                            accountId.count,
                            credPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                            credentials.count,
                            ke2Ptr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                            OpaqueAgent.Constants.ke2Length,
                            UnsafeRawPointer(state.handle)
                        )
                    }
                }
            }
        }

        guard result == 0 else {
            throw OpaqueError.fromCode(result)
        }

        return ke2
    }

    /// Complete authentication and derive session keys
    /// - Parameters:
    ///   - ke3: Agent's KE3 message
    ///   - state: Session state from `createState()`
    /// - Returns: Derived session and master keys
    public func finish(ke3: Data, state: RelayState) throws -> AuthenticationKeys {
        guard let handle = handle else {
            throw OpaqueError.invalidState
        }

        guard ke3.count == OpaqueAgent.Constants.ke3Length else {
            throw OpaqueError.invalidInput(
                "KE3 must be \(OpaqueAgent.Constants.ke3Length) bytes"
            )
        }

        var sessionKey = Data(count: OpaqueAgent.Constants.sessionKeyLength)
        var masterKey = Data(count: OpaqueAgent.Constants.masterKeyLength)

        let result = ke3.withUnsafeBytes { ke3Ptr in
            sessionKey.withUnsafeMutableBytes { skPtr in
                masterKey.withUnsafeMutableBytes { mkPtr in
                    opaque_relay_finish(
                        UnsafeRawPointer(handle),
                        ke3Ptr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        ke3.count,
                        UnsafeRawPointer(state.handle),
                        skPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        OpaqueAgent.Constants.sessionKeyLength,
                        mkPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        OpaqueAgent.Constants.masterKeyLength
                    )
                }
            }
        }

        guard result == 0 else {
            throw OpaqueError.fromCode(result)
        }

        return AuthenticationKeys(sessionKey: sessionKey, masterKey: masterKey)
    }
}

// MARK: - KeyPair

extension OpaqueRelay {
    /// Ristretto255 keypair for the relay
    public final class KeyPair {
        internal let handle: OpaquePointer

        /// Generate a new random keypair
        public static func generate() throws -> KeyPair {
            var rawHandle: UnsafeMutableRawPointer?
            let result = opaque_relay_keypair_generate(&rawHandle)

            guard result == 0, let validHandle = rawHandle else {
                throw OpaqueError.fromCode(result)
            }

            return KeyPair(handle: OpaquePointer(validHandle))
        }

        private init(handle: OpaquePointer) {
            self.handle = handle
        }

        deinit {
            opaque_relay_keypair_destroy(UnsafeMutableRawPointer(handle))
        }

        /// Extract the public key (32 bytes)
        public func publicKey() throws -> Data {
            var pk = Data(count: OpaqueAgent.Constants.publicKeyLength)

            let result = pk.withUnsafeMutableBytes { pkPtr in
                opaque_relay_keypair_get_public_key(
                    UnsafeMutableRawPointer(handle),
                    pkPtr.baseAddress?.assumingMemoryBound(to: UInt8.self),
                    OpaqueAgent.Constants.publicKeyLength
                )
            }

            guard result == 0 else {
                throw OpaqueError.fromCode(result)
            }

            return pk
        }
    }
}

// MARK: - Relay State

extension OpaqueRelay {
    /// Session state for relay authentication
    ///
    /// Each authentication session requires a fresh state.
    public final class RelayState {
        internal let handle: OpaquePointer

        internal init() throws {
            var rawHandle: UnsafeMutableRawPointer?
            let result = opaque_relay_state_create(&rawHandle)

            guard result == 0, let validHandle = rawHandle else {
                throw OpaqueError.fromCode(result)
            }

            self.handle = OpaquePointer(validHandle)
        }

        deinit {
            opaque_relay_state_destroy(UnsafeMutableRawPointer(handle))
        }
    }
}
