namespace Ecliptix.OPAQUE.Relay;

public static class OpaqueConstants
{
    public const int OPRF_SEED_LENGTH = 32;
    public const int PRIVATE_KEY_LENGTH = 32;
    public const int PUBLIC_KEY_LENGTH = 32;
    public const int MASTER_KEY_LENGTH = 32;
    public const int NONCE_LENGTH = 24;
    public const int MAC_LENGTH = 64;
    public const int HASH_LENGTH = 64;
    public const int ENVELOPE_LENGTH = 136;
    public const int REGISTRATION_REQUEST_LENGTH = 32;
    public const int REGISTRATION_RESPONSE_LENGTH = 64;
    public const int REGISTRATION_RECORD_LENGTH = 168;
    public const int RELAY_CREDENTIALS_LENGTH = 168;
    public const int CREDENTIAL_RESPONSE_LENGTH = 168;
    public const int KE1_LENGTH = 1272;
    public const int KE2_LENGTH = 1376;
    public const int KE3_LENGTH = 64;
    public const int SESSION_KEY_LENGTH = HASH_LENGTH;
    public const int MASKING_KEY_LENGTH = 32;
}
