using System;
using System.Security.Cryptography;

namespace Ecliptix.OPAQUE.Server;

/// <summary>
/// Represents an OPAQUE server keypair (private + public key).
/// </summary>
public sealed class ServerKeyPair : IDisposable
{
    private byte[] _privateKey;
    private byte[] _publicKey;
    private IntPtr _nativeHandle;
    private bool _disposed;

    /// <summary>Gets a copy of the public key.</summary>
    public byte[] GetPublicKeyCopy() => (byte[])_publicKey.Clone();

    /// <summary>Gets the public key as a read-only span.</summary>
    public ReadOnlySpan<byte> PublicKey => _publicKey;

    internal byte[] PrivateKey => _privateKey;
    internal IntPtr NativeHandle => _nativeHandle;

    internal ServerKeyPair(byte[] privateKey, byte[] publicKey, IntPtr nativeHandle)
    {
        _privateKey = privateKey;
        _publicKey = publicKey;
        _nativeHandle = nativeHandle;
    }

    /// <summary>
    /// Generates a new random server keypair.
    /// </summary>
    public static ServerKeyPair Generate()
    {
        int result = OpaqueServerNative.opaque_server_keypair_generate(out IntPtr handle);
        if (result != (int)OpaqueResult.Success)
        {
            throw new OpaqueException((OpaqueResult)result, "Failed to generate server keypair");
        }

        byte[] publicKey = new byte[OpaqueConstants.PUBLIC_KEY_LENGTH];
        result = OpaqueServerNative.opaque_server_keypair_get_public_key(
            handle,
            publicKey,
            (UIntPtr)publicKey.Length);

        if (result != (int)OpaqueResult.Success)
        {
            OpaqueServerNative.opaque_server_keypair_destroy(handle);
            throw new OpaqueException((OpaqueResult)result, "Failed to get public key from keypair");
        }

        return new ServerKeyPair(Array.Empty<byte>(), publicKey, handle);
    }

    /// <summary>
    /// Derives a deterministic keypair from a seed.
    /// </summary>
    /// <param name="seed">The 32-byte seed for key derivation.</param>
    public static ServerKeyPair DeriveFromSeed(byte[] seed)
    {
        if (seed == null || seed.Length != OpaqueConstants.OPRF_SEED_LENGTH)
        {
            throw new ArgumentException(
                $"Seed must be exactly {OpaqueConstants.OPRF_SEED_LENGTH} bytes",
                nameof(seed));
        }

        byte[] privateKey = new byte[OpaqueConstants.PRIVATE_KEY_LENGTH];
        byte[] publicKey = new byte[OpaqueConstants.PUBLIC_KEY_LENGTH];

        int result = OpaqueServerNative.opaque_server_derive_keypair_from_seed(
            seed,
            (UIntPtr)seed.Length,
            privateKey,
            (UIntPtr)privateKey.Length,
            publicKey,
            (UIntPtr)publicKey.Length);

        if (result != (int)OpaqueResult.Success)
        {
            CryptographicOperations.ZeroMemory(privateKey);
            throw new OpaqueException((OpaqueResult)result, "Failed to derive keypair from seed");
        }

        return new ServerKeyPair(privateKey, publicKey, IntPtr.Zero);
    }

    /// <summary>
    /// Creates a keypair from existing key material.
    /// </summary>
    public static ServerKeyPair FromKeys(byte[] privateKey, byte[] publicKey)
    {
        if (privateKey == null || privateKey.Length != OpaqueConstants.PRIVATE_KEY_LENGTH)
        {
            throw new ArgumentException(
                $"Private key must be exactly {OpaqueConstants.PRIVATE_KEY_LENGTH} bytes",
                nameof(privateKey));
        }

        if (publicKey == null || publicKey.Length != OpaqueConstants.PUBLIC_KEY_LENGTH)
        {
            throw new ArgumentException(
                $"Public key must be exactly {OpaqueConstants.PUBLIC_KEY_LENGTH} bytes",
                nameof(publicKey));
        }

        return new ServerKeyPair((byte[])privateKey.Clone(), (byte[])publicKey.Clone(), IntPtr.Zero);
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (_disposed) return;

        if (_nativeHandle != IntPtr.Zero)
        {
            OpaqueServerNative.opaque_server_keypair_destroy(_nativeHandle);
            _nativeHandle = IntPtr.Zero;
        }

        if (_privateKey.Length > 0)
        {
            CryptographicOperations.ZeroMemory(_privateKey);
        }

        _disposed = true;
        GC.SuppressFinalize(this);
    }

    /// <summary>Finalizer.</summary>
    ~ServerKeyPair() => Dispose();
}

/// <summary>
/// Holds the state for an authentication session.
/// </summary>
public sealed class AuthenticationState : IDisposable
{
    private IntPtr _stateHandle;
    private bool _disposed;

    internal IntPtr StateHandle => _stateHandle;

    internal AuthenticationState(IntPtr stateHandle)
    {
        _stateHandle = stateHandle;
    }

    /// <summary>
    /// Creates a new authentication state.
    /// </summary>
    public static AuthenticationState Create()
    {
        int result = OpaqueServerNative.opaque_server_state_create(out IntPtr handle);
        if (result != (int)OpaqueResult.Success)
        {
            throw new OpaqueException((OpaqueResult)result, "Failed to create authentication state");
        }

        return new AuthenticationState(handle);
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (_disposed) return;

        if (_stateHandle != IntPtr.Zero)
        {
            OpaqueServerNative.opaque_server_state_destroy(_stateHandle);
            _stateHandle = IntPtr.Zero;
        }

        _disposed = true;
        GC.SuppressFinalize(this);
    }

    /// <summary>Finalizer.</summary>
    ~AuthenticationState() => Dispose();
}

/// <summary>
/// Contains the session and master keys derived after successful authentication.
/// </summary>
public readonly struct DerivedKeys
{
    /// <summary>Gets the session key (64 bytes).</summary>
    public byte[] SessionKey { get; }

    /// <summary>Gets the master key (32 bytes).</summary>
    public byte[] MasterKey { get; }

    internal DerivedKeys(byte[] sessionKey, byte[] masterKey)
    {
        SessionKey = sessionKey;
        MasterKey = masterKey;
    }
}
