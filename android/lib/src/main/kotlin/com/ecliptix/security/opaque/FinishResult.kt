/**
 * Result of completing OPAQUE authentication
 */
package com.ecliptix.security.opaque

/**
 * Contains the cryptographic keys derived from successful OPAQUE authentication
 *
 * @property sessionKey The session key for this authentication session (64 bytes)
 * @property masterKey The master key derived from authentication (32 bytes)
 */
data class FinishResult(
    val sessionKey: ByteArray,
    val masterKey: ByteArray
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (javaClass != other?.javaClass) return false

        other as FinishResult

        if (!sessionKey.contentEquals(other.sessionKey)) return false
        if (!masterKey.contentEquals(other.masterKey)) return false

        return true
    }

    override fun hashCode(): Int {
        var result = sessionKey.contentHashCode()
        result = 31 * result + masterKey.contentHashCode()
        return result
    }

    override fun toString(): String =
        "FinishResult(sessionKey=[${sessionKey.size} bytes], masterKey=[${masterKey.size} bytes])"

    /**
     * Securely clear the keys from memory
     * Call this when done with the keys to minimize exposure
     */
    fun clear() {
        sessionKey.fill(0)
        masterKey.fill(0)
    }
}
