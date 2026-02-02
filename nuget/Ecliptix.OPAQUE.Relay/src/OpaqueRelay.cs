using System;
using System.Security.Cryptography;

namespace Ecliptix.OPAQUE.Relay;

public sealed class OpaqueRelay : IDisposable
{
    private IntPtr _serverHandle;
    private bool _disposed;

    private OpaqueRelay(IntPtr serverHandle)
    {
        _serverHandle = serverHandle;
    }

    public static OpaqueRelay Create(ServerKeyPair keyPair)
    {
        if (keyPair == null)
            throw new ArgumentNullException(nameof(keyPair));

        int result;
        IntPtr serverHandle;

        if (keyPair.NativeHandle != IntPtr.Zero)
        {
            result = OpaqueRelayNative.opaque_relay_create(keyPair.NativeHandle, out serverHandle);
        }
        else
        {
            result = OpaqueRelayNative.opaque_relay_create_with_keys(
                keyPair.PrivateKey,
                (UIntPtr)keyPair.PrivateKey.Length,
                keyPair.GetPublicKeyCopy(),
                (UIntPtr)OpaqueConstants.PUBLIC_KEY_LENGTH,
                out serverHandle);
        }

        if (result != (int)OpaqueResult.Success || serverHandle == IntPtr.Zero)
        {
            throw new OpaqueException((OpaqueResult)result, "Failed to create OPAQUE server");
        }

        return new OpaqueRelay(serverHandle);
    }

    public static OpaqueRelay Create(byte[] privateKey, byte[] publicKey)
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

        int result = OpaqueRelayNative.opaque_relay_create_with_keys(
            privateKey,
            (UIntPtr)privateKey.Length,
            publicKey,
            (UIntPtr)publicKey.Length,
            out IntPtr serverHandle);

        if (result != (int)OpaqueResult.Success || serverHandle == IntPtr.Zero)
        {
            throw new OpaqueException((OpaqueResult)result, "Failed to create OPAQUE server");
        }

        return new OpaqueRelay(serverHandle);
    }

    public byte[] CreateRegistrationResponse(byte[] registrationRequest, byte[] accountId)
    {
        ThrowIfDisposed();

        if (registrationRequest == null || registrationRequest.Length != OpaqueConstants.REGISTRATION_REQUEST_LENGTH)
        {
            throw new ArgumentException(
                $"Registration request must be exactly {OpaqueConstants.REGISTRATION_REQUEST_LENGTH} bytes",
                nameof(registrationRequest));
        }

        if (accountId == null || accountId.Length == 0)
            throw new ArgumentException("Account ID cannot be null or empty", nameof(accountId));

        byte[] response = new byte[OpaqueConstants.REGISTRATION_RESPONSE_LENGTH];

        int result = OpaqueRelayNative.opaque_relay_create_registration_response(
            _serverHandle,
            registrationRequest,
            (UIntPtr)registrationRequest.Length,
            accountId,
            (UIntPtr)accountId.Length,
            response,
            (UIntPtr)response.Length);

        if (result != (int)OpaqueResult.Success)
        {
            throw new OpaqueException((OpaqueResult)result, "Failed to create registration response");
        }

        return response;
    }

    public byte[] GenerateKe2(byte[] ke1, byte[] accountId, byte[] storedCredentials, AuthenticationState authState)
    {
        ThrowIfDisposed();

        if (ke1 == null || ke1.Length != OpaqueConstants.KE1_LENGTH)
        {
            throw new ArgumentException(
                $"KE1 must be exactly {OpaqueConstants.KE1_LENGTH} bytes",
                nameof(ke1));
        }

        if (accountId == null || accountId.Length == 0)
            throw new ArgumentException("Account ID cannot be null or empty", nameof(accountId));

        if (storedCredentials == null || storedCredentials.Length != OpaqueConstants.SERVER_CREDENTIALS_LENGTH)
        {
            throw new ArgumentException(
                $"Stored credentials must be exactly {OpaqueConstants.SERVER_CREDENTIALS_LENGTH} bytes",
                nameof(storedCredentials));
        }

        if (authState == null)
            throw new ArgumentNullException(nameof(authState));

        byte[] ke2 = new byte[OpaqueConstants.KE2_LENGTH];

        int result = OpaqueRelayNative.opaque_relay_generate_ke2(
            _serverHandle,
            ke1,
            (UIntPtr)ke1.Length,
            accountId,
            (UIntPtr)accountId.Length,
            storedCredentials,
            (UIntPtr)storedCredentials.Length,
            ke2,
            (UIntPtr)ke2.Length,
            authState.StateHandle);

        if (result != (int)OpaqueResult.Success)
        {
            throw new OpaqueException((OpaqueResult)result, "Failed to generate KE2");
        }

        return ke2;
    }

    public DerivedKeys FinishAuthentication(byte[] ke3, AuthenticationState authState)
    {
        ThrowIfDisposed();

        if (ke3 == null)
        {
            throw new ArgumentNullException(nameof(ke3));
        }

        if (ke3.Length != OpaqueConstants.KE3_LENGTH)
        {
            throw new ArgumentException(
                $"KE3 must be exactly {OpaqueConstants.KE3_LENGTH} bytes",
                nameof(ke3));
        }

        if (authState == null)
            throw new ArgumentNullException(nameof(authState));

        byte[] sessionKey = new byte[OpaqueConstants.SESSION_KEY_LENGTH];
        byte[] masterKey = new byte[OpaqueConstants.MASTER_KEY_LENGTH];

        int result = OpaqueRelayNative.opaque_relay_finish(
            _serverHandle,
            ke3,
            (UIntPtr)ke3.Length,
            authState.StateHandle,
            sessionKey,
            (UIntPtr)sessionKey.Length,
            masterKey,
            (UIntPtr)masterKey.Length);

        if (result != (int)OpaqueResult.Success)
        {
            CryptographicOperations.ZeroMemory(sessionKey);
            CryptographicOperations.ZeroMemory(masterKey);
            throw new OpaqueException((OpaqueResult)result, "Failed to finish authentication");
        }

        return new DerivedKeys(sessionKey, masterKey);
    }

    public static string GetNativeVersion()
    {
        IntPtr versionPtr = OpaqueRelayNative.opaque_relay_get_version();
        return versionPtr != IntPtr.Zero
            ? System.Runtime.InteropServices.Marshal.PtrToStringAnsi(versionPtr) ?? "unknown"
            : "unknown";
    }

    private void ThrowIfDisposed()
    {
        if (_disposed)
            throw new ObjectDisposedException(nameof(OpaqueRelay));
    }

    public void Dispose()
    {
        if (_disposed) return;

        if (_serverHandle != IntPtr.Zero)
        {
            OpaqueRelayNative.opaque_relay_destroy(_serverHandle);
            _serverHandle = IntPtr.Zero;
        }

        _disposed = true;
        GC.SuppressFinalize(this);
    }

    ~OpaqueRelay() => Dispose();
}
