namespace Ecliptix.OPAQUE.Client;

/// <summary>
/// OPAQUE protocol constants matching the native C++ library definitions.
/// </summary>
public static class OpaqueConstants
{
    public const int PUBLIC_KEY_LENGTH = 32;
    public const int HASH_LENGTH = 64;
    public const int MASTER_KEY_LENGTH = 32;
    public const int REGISTRATION_REQUEST_LENGTH = 32;
    public const int REGISTRATION_RESPONSE_LENGTH = 64;
    public const int REGISTRATION_RECORD_LENGTH = 168;
    public const int KE1_LENGTH = 88;
    public const int KE2_LENGTH = 288;
    public const int KE3_LENGTH = 64;
}

/// <summary>
/// Result codes from OPAQUE protocol operations.
/// </summary>
public enum OpaqueResult
{
    SUCCESS = 0,
    INVALID_INPUT = -1,
    CRYPTO_ERROR = -2,
    MEMORY_ERROR = -3,
    VALIDATION_ERROR = -4,
    AUTHENTICATION_ERROR = -5,
    INVALID_PUBLIC_KEY = -6
}

/// <summary>
/// Error message templates for OPAQUE operations.
/// </summary>
public static class OpaqueErrorMessages
{
    public const string SERVER_PUBLIC_KEY_INVALID_SIZE = "Server public key must be exactly {0} bytes";
    public const string FAILED_TO_CREATE_OPAQUE_CLIENT = "Failed to create OPAQUE client: {0}";
    public const string SECURE_KEY_NULL_OR_EMPTY = "SecureKey cannot be null or empty";
    public const string FAILED_TO_CREATE_STATE = "Failed to create state: {0}";
    public const string FAILED_TO_CREATE_REGISTRATION_REQUEST = "Failed to create registration request: {0}";
    public const string SERVER_RESPONSE_INVALID_SIZE = "Server response must be exactly {0} bytes";
    public const string FAILED_TO_FINALIZE_REGISTRATION = "Failed to finalize registration: {0}";
    public const string FAILED_TO_GENERATE_KE1 = "Failed to generate KE1: {0}";
    public const string FAILED_TO_DERIVE_SESSION_KEY = "Failed to derive session key: {0}";
}
