using System;
using System.Security.Cryptography;

namespace Ecliptix.OPAQUE.Relay;

public sealed class RelayKeyPair : IDisposable
{
    private byte[] _privateKey;
    private byte[] _publicKey;
    private IntPtr _nativeHandle;
    private bool _disposed;

    public byte[] GetPublicKeyCopy()
    {
        ThrowIfDisposed();
        return (byte[])_publicKey.Clone();
    }

    public ReadOnlySpan<byte> PublicKey
    {
        get
        {
            ThrowIfDisposed();
            return _publicKey;
        }
    }

    internal byte[] PrivateKey
    {
        get
        {
            ThrowIfDisposed();
            return _privateKey;
        }
    }

    internal IntPtr NativeHandle
    {
        get
        {
            ThrowIfDisposed();
            return _nativeHandle;
        }
    }

    internal RelayKeyPair(byte[] privateKey, byte[] publicKey, IntPtr nativeHandle)
    {
        _privateKey = privateKey;
        _publicKey = publicKey;
        _nativeHandle = nativeHandle;
    }

    public static RelayKeyPair Generate()
    {
        int result = OpaqueRelayNative.opaque_relay_keypair_generate(out IntPtr handle);
        if (result != (int)OpaqueResult.Success)
        {
            throw new OpaqueException((OpaqueResult)result, "Failed to generate relay keypair");
        }

        byte[] publicKey = new byte[OpaqueConstants.PUBLIC_KEY_LENGTH];
        result = OpaqueRelayNative.opaque_relay_keypair_get_public_key(
            handle,
            publicKey,
            (UIntPtr)publicKey.Length);

        if (result != (int)OpaqueResult.Success)
        {
            OpaqueRelayNative.opaque_relay_keypair_destroy(handle);
            throw new OpaqueException((OpaqueResult)result, "Failed to get public key from keypair");
        }

        return new RelayKeyPair(Array.Empty<byte>(), publicKey, handle);
    }

    public static RelayKeyPair DeriveFromSeed(byte[] seed)
    {
        if (seed == null || seed.Length != OpaqueConstants.OPRF_SEED_LENGTH)
        {
            throw new ArgumentException(
                $"Seed must be exactly {OpaqueConstants.OPRF_SEED_LENGTH} bytes",
                nameof(seed));
        }

        byte[] privateKey = new byte[OpaqueConstants.PRIVATE_KEY_LENGTH];
        byte[] publicKey = new byte[OpaqueConstants.PUBLIC_KEY_LENGTH];

        int result = OpaqueRelayNative.opaque_relay_derive_keypair_from_seed(
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

        return new RelayKeyPair(privateKey, publicKey, IntPtr.Zero);
    }

    public static RelayKeyPair FromKeys(byte[] privateKey, byte[] publicKey)
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

        return new RelayKeyPair((byte[])privateKey.Clone(), (byte[])publicKey.Clone(), IntPtr.Zero);
    }

    public void Dispose()
    {
        if (_disposed) return;

        if (_nativeHandle != IntPtr.Zero)
        {
            OpaqueRelayNative.opaque_relay_keypair_destroy(_nativeHandle);
            _nativeHandle = IntPtr.Zero;
        }

        if (_privateKey.Length > 0)
        {
            CryptographicOperations.ZeroMemory(_privateKey);
        }

        _disposed = true;
        GC.SuppressFinalize(this);
    }

    ~RelayKeyPair() => Dispose();

    private void ThrowIfDisposed()
    {
        if (_disposed)
        {
            throw new ObjectDisposedException(nameof(RelayKeyPair));
        }
    }
}

public sealed class AuthenticationState : IDisposable
{
    private IntPtr _stateHandle;
    private bool _disposed;

    internal IntPtr StateHandle
    {
        get
        {
            ThrowIfDisposed();
            return _stateHandle;
        }
    }

    internal AuthenticationState(IntPtr stateHandle)
    {
        _stateHandle = stateHandle;
    }

    public static AuthenticationState Create()
    {
        int result = OpaqueRelayNative.opaque_relay_state_create(out IntPtr handle);
        if (result != (int)OpaqueResult.Success)
        {
            throw new OpaqueException((OpaqueResult)result, "Failed to create authentication state");
        }

        return new AuthenticationState(handle);
    }

    public void Dispose()
    {
        if (_disposed) return;

        if (_stateHandle != IntPtr.Zero)
        {
            OpaqueRelayNative.opaque_relay_state_destroy(_stateHandle);
            _stateHandle = IntPtr.Zero;
        }

        _disposed = true;
        GC.SuppressFinalize(this);
    }

    ~AuthenticationState() => Dispose();

    private void ThrowIfDisposed()
    {
        if (_disposed)
        {
            throw new ObjectDisposedException(nameof(AuthenticationState));
        }
    }
}

public readonly struct DerivedKeys
{
    public byte[] SessionKey { get; }
    public byte[] MasterKey { get; }

    internal DerivedKeys(byte[] sessionKey, byte[] masterKey)
    {
        SessionKey = sessionKey;
        MasterKey = masterKey;
    }
}
