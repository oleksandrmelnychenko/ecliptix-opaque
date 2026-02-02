/**
 * OPAQUE Protocol Client for Android
 *
 * Provides password-authenticated key exchange (PAKE) with post-quantum security.
 * This is the main entry point for using the Ecliptix OPAQUE implementation.
 *
 * Example usage:
 * ```kotlin
 * // Initialize once at application startup
 * OpaqueAgent.initialize()
 *
 * // Create a client with server's public key
 * val client = OpaqueAgent(serverPublicKey)
 *
 * // Registration flow
 * client.startSession { state ->
 *     val request = client.createRegistrationRequest(password.toByteArray(), state)
 *     // Send request to server, receive response
 *     val record = client.finalizeRegistration(response, state)
 *     // Send record to server for storage
 * }
 *
 * // Authentication flow
 * client.startSession { state ->
 *     val ke1 = client.generateKe1(password.toByteArray(), state)
 *     // Send ke1 to server, receive ke2
 *     val ke3 = client.generateKe3(ke2, state)
 *     // Send ke3 to server for verification
 *     val keys = client.finish(state)
 *     // Use keys.sessionKey and keys.masterKey
 * }
 *
 * // Clean up
 * client.close()
 * ```
 */
package com.ecliptix.security.opaque

import java.io.Closeable
import java.util.concurrent.atomic.AtomicBoolean

/**
 * OPAQUE protocol client
 *
 * Thread-safe client for OPAQUE password-authenticated key exchange.
 * Each instance maintains a native handle that must be closed when done.
 *
 * @property serverPublicKey The server's public key (32 bytes)
 */
class OpaqueAgent(
    serverPublicKey: ByteArray
) : Closeable {

    private var nativeHandle: Long
    private val closed = AtomicBoolean(false)

    init {
        require(isInitialized) {
            "OpaqueAgent must be initialized first. Call OpaqueAgent.initialize()"
        }
        require(serverPublicKey.size == Constants.PUBLIC_KEY_LENGTH) {
            "Server public key must be ${Constants.PUBLIC_KEY_LENGTH} bytes, got ${serverPublicKey.size}"
        }
        nativeHandle = OpaqueNative.nativeClientCreate(serverPublicKey)
        if (nativeHandle == 0L) {
            throw OpaqueException("Failed to create OPAQUE client")
        }
    }

    /**
     * Start a new session for registration or authentication
     *
     * The session state is automatically cleaned up after the block completes.
     *
     * @param block The operation to perform with the session state
     * @return The result of the block
     */
    fun <T> startSession(block: (ClientState) -> T): T {
        checkNotClosed()
        val state = ClientState()
        return try {
            block(state)
        } finally {
            state.close()
        }
    }

    /**
     * Create a registration request
     *
     * This is the first step of user registration.
     *
     * @param secureKey The user's password as bytes
     * @param state The session state from [startSession]
     * @return Registration request to send to server
     */
    fun createRegistrationRequest(secureKey: ByteArray, state: ClientState): ByteArray {
        checkNotClosed()
        state.checkNotClosed()
        return OpaqueNative.nativeCreateRegistrationRequest(
            nativeHandle,
            secureKey,
            state.nativeHandle
        )
    }

    /**
     * Finalize registration with server's response
     *
     * This is the second step of user registration.
     *
     * @param response The server's registration response
     * @param state The session state from [startSession]
     * @return Registration record to send to server for storage
     */
    fun finalizeRegistration(response: ByteArray, state: ClientState): ByteArray {
        checkNotClosed()
        state.checkNotClosed()
        require(response.size == Constants.REGISTRATION_RESPONSE_LENGTH) {
            "Response must be ${Constants.REGISTRATION_RESPONSE_LENGTH} bytes"
        }
        return OpaqueNative.nativeFinalizeRegistration(
            nativeHandle,
            response,
            state.nativeHandle
        )
    }

    /**
     * Generate KE1 message for authentication
     *
     * This is the first step of user authentication.
     *
     * @param secureKey The user's password as bytes
     * @param state The session state from [startSession]
     * @return KE1 message to send to server
     */
    fun generateKe1(secureKey: ByteArray, state: ClientState): ByteArray {
        checkNotClosed()
        state.checkNotClosed()
        return OpaqueNative.nativeGenerateKe1(
            nativeHandle,
            secureKey,
            state.nativeHandle
        )
    }

    /**
     * Generate KE3 message from server's KE2
     *
     * This is the second step of user authentication.
     *
     * @param ke2 The server's KE2 message
     * @param state The session state from [startSession]
     * @return KE3 message to send to server for verification
     */
    fun generateKe3(ke2: ByteArray, state: ClientState): ByteArray {
        checkNotClosed()
        state.checkNotClosed()
        require(ke2.size == Constants.KE2_LENGTH) {
            "KE2 must be ${Constants.KE2_LENGTH} bytes"
        }
        return OpaqueNative.nativeGenerateKe3(
            nativeHandle,
            ke2,
            state.nativeHandle
        )
    }

    /**
     * Complete authentication and derive session keys
     *
     * Call this after generating KE3 to get the session and master keys.
     *
     * @param state The session state from [startSession]
     * @return The derived session and master keys
     */
    fun finish(state: ClientState): FinishResult {
        checkNotClosed()
        state.checkNotClosed()
        return OpaqueNative.nativeFinish(nativeHandle, state.nativeHandle)
    }

    /**
     * Release native resources
     *
     * After calling close(), the client cannot be used.
     */
    override fun close() {
        if (closed.compareAndSet(false, true)) {
            if (nativeHandle != 0L) {
                OpaqueNative.nativeClientDestroy(nativeHandle)
                nativeHandle = 0
            }
        }
    }

    private fun checkNotClosed() {
        check(!closed.get()) { "OpaqueAgent has been closed" }
    }

    /**
     * Session state for registration or authentication
     *
     * Each operation (registration or authentication) requires a fresh state.
     * The state is automatically cleaned up when using [startSession].
     */
    class ClientState internal constructor() : Closeable {
        internal var nativeHandle: Long = OpaqueNative.nativeStateCreate()
        private val closed = AtomicBoolean(false)

        init {
            if (nativeHandle == 0L) {
                throw OpaqueException("Failed to create client state")
            }
        }

        override fun close() {
            if (closed.compareAndSet(false, true)) {
                if (nativeHandle != 0L) {
                    OpaqueNative.nativeStateDestroy(nativeHandle)
                    nativeHandle = 0
                }
            }
        }

        internal fun checkNotClosed() {
            check(!closed.get()) { "ClientState has been closed" }
        }
    }

    /**
     * Protocol constants
     */
    object Constants {
        val PUBLIC_KEY_LENGTH: Int by lazy { OpaqueNative.nativeGetPublicKeyLength() }
        val KE1_LENGTH: Int by lazy { OpaqueNative.nativeGetKe1Length() }
        val KE2_LENGTH: Int by lazy { OpaqueNative.nativeGetKe2Length() }
        val KE3_LENGTH: Int by lazy { OpaqueNative.nativeGetKe3Length() }
        val REGISTRATION_REQUEST_LENGTH: Int by lazy { OpaqueNative.nativeGetRegistrationRequestLength() }
        val REGISTRATION_RESPONSE_LENGTH: Int by lazy { OpaqueNative.nativeGetRegistrationResponseLength() }
        val REGISTRATION_RECORD_LENGTH: Int by lazy { OpaqueNative.nativeGetRegistrationRecordLength() }
        val SESSION_KEY_LENGTH: Int by lazy { OpaqueNative.nativeGetSessionKeyLength() }
        val MASTER_KEY_LENGTH: Int by lazy { OpaqueNative.nativeGetMasterKeyLength() }
    }

    companion object {
        private var isInitialized = false

        /**
         * Initialize the OPAQUE library
         *
         * Must be called once before creating any [OpaqueAgent] instances.
         * Safe to call multiple times.
         *
         * @return true if initialization succeeded
         * @throws OpaqueException if initialization fails
         */
        @JvmStatic
        @Synchronized
        fun initialize(): Boolean {
            if (!isInitialized) {
                isInitialized = OpaqueNative.nativeInit()
                if (!isInitialized) {
                    throw OpaqueException("Failed to initialize OPAQUE library")
                }
            }
            return isInitialized
        }

        /**
         * Get the library version
         */
        @JvmStatic
        fun getVersion(): String = OpaqueNative.nativeGetVersion()
    }
}
