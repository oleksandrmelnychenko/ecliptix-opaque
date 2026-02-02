/**
 * Native JNI interface for Ecliptix OPAQUE Protocol
 *
 * This internal object provides low-level JNI bindings to the native library.
 * Use [OpaqueAgent] for a higher-level Kotlin API.
 */
package com.ecliptix.security.opaque

internal object OpaqueNative {
    init {
        System.loadLibrary("eop.agent")
    }

    // Initialization
    @JvmStatic
    external fun nativeInit(): Boolean

    @JvmStatic
    external fun nativeGetVersion(): String

    // Agent lifecycle
    @JvmStatic
    external fun nativeAgentCreate(relayPublicKey: ByteArray): Long

    @JvmStatic
    external fun nativeAgentDestroy(handle: Long)

    // State lifecycle
    @JvmStatic
    external fun nativeStateCreate(): Long

    @JvmStatic
    external fun nativeStateDestroy(handle: Long)

    // Registration
    @JvmStatic
    external fun nativeCreateRegistrationRequest(
        agentHandle: Long,
        secureKey: ByteArray,
        stateHandle: Long
    ): ByteArray

    @JvmStatic
    external fun nativeFinalizeRegistration(
        agentHandle: Long,
        response: ByteArray,
        stateHandle: Long
    ): ByteArray

    // Authentication
    @JvmStatic
    external fun nativeGenerateKe1(
        agentHandle: Long,
        secureKey: ByteArray,
        stateHandle: Long
    ): ByteArray

    @JvmStatic
    external fun nativeGenerateKe3(
        agentHandle: Long,
        ke2: ByteArray,
        stateHandle: Long
    ): ByteArray

    @JvmStatic
    external fun nativeFinish(
        agentHandle: Long,
        stateHandle: Long
    ): FinishResult

    // Constants
    @JvmStatic
    external fun nativeGetKe1Length(): Int

    @JvmStatic
    external fun nativeGetKe2Length(): Int

    @JvmStatic
    external fun nativeGetKe3Length(): Int

    @JvmStatic
    external fun nativeGetRegistrationRecordLength(): Int

    @JvmStatic
    external fun nativeGetPublicKeyLength(): Int

    @JvmStatic
    external fun nativeGetRegistrationRequestLength(): Int

    @JvmStatic
    external fun nativeGetRegistrationResponseLength(): Int

    @JvmStatic
    external fun nativeGetSessionKeyLength(): Int

    @JvmStatic
    external fun nativeGetMasterKeyLength(): Int
}
