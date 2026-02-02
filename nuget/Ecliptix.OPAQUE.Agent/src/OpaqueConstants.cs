namespace Ecliptix.OPAQUE.Agent;

public static class OpaqueConstants
{
    public const int PUBLIC_KEY_LENGTH = 32;
    public const int HASH_LENGTH = 64;
    public const int MASTER_KEY_LENGTH = 32;
    public const int REGISTRATION_REQUEST_LENGTH = 32;
    public const int REGISTRATION_RESPONSE_LENGTH = 64;
    public const int REGISTRATION_RECORD_LENGTH = 168;
    public const int KE1_LENGTH = 1272;
    public const int KE2_LENGTH = 1376;
    public const int KE3_LENGTH = 64;
}

public enum OpaqueResult
{
    Success = 0,
    InvalidInput = -1,
    CryptoError = -2,
    MemoryError = -3,
    ValidationError = -4,
    AuthenticationError = -5,
    InvalidPublicKey = -6
}

public static class OpaqueErrorMessages
{
    public const string SERVER_PUBLIC_KEY_INVALID_SIZE = "Server public key must be exactly {0} bytes";
    public const string FAILED_TO_CREATE_OPAQUE_CLIENT = "Failed to create OPAQUE client";
    public const string SECURE_KEY_NULL_OR_EMPTY = "SecureKey cannot be null or empty";
    public const string FAILED_TO_CREATE_STATE = "Failed to create state";
    public const string FAILED_TO_CREATE_REGISTRATION_REQUEST = "Failed to create registration request";
    public const string SERVER_RESPONSE_INVALID_SIZE = "Server response must be exactly {0} bytes";
    public const string KE2_INVALID_SIZE = "KE2 must be exactly {0} bytes";
    public const string FAILED_TO_FINALIZE_REGISTRATION = "Failed to finalize registration";
    public const string FAILED_TO_GENERATE_KE1 = "Failed to generate KE1";
    public const string FAILED_TO_DERIVE_SESSION_KEY = "Failed to derive session key";
}
