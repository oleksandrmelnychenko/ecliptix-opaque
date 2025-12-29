namespace Ecliptix.OPAQUE.Server;

/// <summary>
/// OPAQUE protocol constants matching the native C++ library definitions.
/// </summary>
public static class OpaqueConstants
{
    /// <summary>OPRF seed length in bytes.</summary>
    public const int OPRF_SEED_LENGTH = 32;

    /// <summary>Private key length in bytes (Ristretto255).</summary>
    public const int PRIVATE_KEY_LENGTH = 32;

    /// <summary>Public key length in bytes (Ristretto255).</summary>
    public const int PUBLIC_KEY_LENGTH = 32;

    /// <summary>Master key length in bytes.</summary>
    public const int MASTER_KEY_LENGTH = 32;

    /// <summary>Nonce length in bytes (XChaCha20-Poly1305).</summary>
    public const int NONCE_LENGTH = 24;

    /// <summary>MAC length in bytes (HMAC-SHA512).</summary>
    public const int MAC_LENGTH = 64;

    /// <summary>Hash output length in bytes (SHA512).</summary>
    public const int HASH_LENGTH = 64;

    /// <summary>Envelope length in bytes.</summary>
    public const int ENVELOPE_LENGTH = 136;

    /// <summary>Registration request message length in bytes.</summary>
    public const int REGISTRATION_REQUEST_LENGTH = 32;

    /// <summary>Registration response message length in bytes.</summary>
    public const int REGISTRATION_RESPONSE_LENGTH = 64;

    /// <summary>Registration record (credentials) length in bytes.</summary>
    public const int REGISTRATION_RECORD_LENGTH = 168;

    /// <summary>Server credentials length in bytes (same as registration record).</summary>
    public const int SERVER_CREDENTIALS_LENGTH = 168;

    /// <summary>Credential response message length in bytes.</summary>
    public const int CREDENTIAL_RESPONSE_LENGTH = 168;

    /// <summary>KE1 (key exchange message 1) length in bytes.</summary>
    public const int KE1_LENGTH = 88;

    /// <summary>KE2 (key exchange message 2) length in bytes.</summary>
    public const int KE2_LENGTH = 288;

    /// <summary>KE3 (key exchange message 3) length in bytes.</summary>
    public const int KE3_LENGTH = 64;

    /// <summary>Session key length in bytes.</summary>
    public const int SESSION_KEY_LENGTH = HASH_LENGTH;

    /// <summary>Masking key length in bytes.</summary>
    public const int MASKING_KEY_LENGTH = 32;
}
