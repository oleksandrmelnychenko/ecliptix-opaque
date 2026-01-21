/**
 * Exception thrown when OPAQUE protocol operations fail
 */
package com.ecliptix.security.opaque

/**
 * Error codes returned by the OPAQUE protocol
 */
enum class OpaqueError(val code: Int) {
    SUCCESS(0),
    INVALID_INPUT(-1),
    CRYPTO_ERROR(-2),
    MEMORY_ERROR(-3),
    VALIDATION_ERROR(-4),
    AUTHENTICATION_ERROR(-5),
    INVALID_PUBLIC_KEY(-6);

    companion object {
        fun fromCode(code: Int): OpaqueError =
            entries.find { it.code == code } ?: CRYPTO_ERROR
    }
}

/**
 * Exception thrown by OPAQUE operations
 *
 * @property errorCode The underlying error code from the native library
 * @property error The error type
 */
class OpaqueException(
    message: String,
    val errorCode: Int = OpaqueError.CRYPTO_ERROR.code
) : Exception(message) {

    val error: OpaqueError
        get() = OpaqueError.fromCode(errorCode)

    override fun toString(): String =
        "OpaqueException(error=$error, code=$errorCode): $message"
}
