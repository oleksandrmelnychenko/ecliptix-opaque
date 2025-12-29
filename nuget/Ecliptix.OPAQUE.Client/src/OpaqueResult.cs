namespace Ecliptix.OPAQUE.Client;

/// <summary>
/// Result codes from OPAQUE native library operations.
/// </summary>
public enum OpaqueResult
{
    /// <summary>Operation completed successfully.</summary>
    Success = 0,

    /// <summary>Invalid input parameter.</summary>
    InvalidInput = -1,

    /// <summary>Cryptographic operation failed.</summary>
    CryptoError = -2,

    /// <summary>Memory allocation failed.</summary>
    MemoryError = -3,

    /// <summary>Validation check failed.</summary>
    ValidationError = -4,

    /// <summary>Authentication failed.</summary>
    AuthenticationError = -5,

    /// <summary>Invalid public key format.</summary>
    InvalidPublicKey = -6
}

/// <summary>
/// Exception thrown when an OPAQUE protocol operation fails.
/// </summary>
public class OpaqueException : Exception
{
    /// <summary>Gets the result code from the native library.</summary>
    public OpaqueResult ResultCode { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="OpaqueException"/> class.
    /// </summary>
    public OpaqueException(OpaqueResult resultCode, string message)
        : base($"{message}: {resultCode}")
    {
        ResultCode = resultCode;
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="OpaqueException"/> class.
    /// </summary>
    public OpaqueException(string message) : base(message)
    {
        ResultCode = OpaqueResult.InvalidInput;
    }
}
