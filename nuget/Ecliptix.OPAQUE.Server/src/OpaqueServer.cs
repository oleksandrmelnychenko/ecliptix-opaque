using System;
using System.Security.Cryptography;

namespace Ecliptix.OPAQUE.Server;

/// <summary>
/// OPAQUE protocol server (responder) for secure password authentication.
/// Implements the server-side of the OPAQUE PAKE protocol.
/// </summary>
/// <remarks>
/// The server stores only a password verifier - the actual password is never transmitted
/// and cannot be recovered from the stored data.
/// </remarks>
public sealed class OpaqueServer : IDisposable
{
    private IntPtr _serverHandle;
    private bool _disposed;

    private OpaqueServer(IntPtr serverHandle)
    {
        _serverHandle = serverHandle;
    }

    /// <summary>
    /// Creates a new OPAQUE server from a keypair.
    /// </summary>
    /// <param name="keyPair">The server's keypair.</param>
    public static OpaqueServer Create(ServerKeyPair keyPair)
    {
        if (keyPair == null)
            throw new ArgumentNullException(nameof(keyPair));

        int result;
        IntPtr serverHandle;

        if (keyPair.NativeHandle != IntPtr.Zero)
        {
            result = OpaqueServerNative.opaque_server_create(keyPair.NativeHandle, out serverHandle);
        }
        else
        {
            result = OpaqueServerNative.opaque_server_create_with_keys(
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

        return new OpaqueServer(serverHandle);
    }

    /// <summary>
    /// Creates a new OPAQUE server with explicit key material.
    /// </summary>
    /// <param name="privateKey">The 32-byte private key.</param>
    /// <param name="publicKey">The 32-byte public key.</param>
    public static OpaqueServer Create(byte[] privateKey, byte[] publicKey)
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

        int result = OpaqueServerNative.opaque_server_create_with_keys(
            privateKey,
            (UIntPtr)privateKey.Length,
            publicKey,
            (UIntPtr)publicKey.Length,
            out IntPtr serverHandle);

        if (result != (int)OpaqueResult.Success || serverHandle == IntPtr.Zero)
        {
            throw new OpaqueException((OpaqueResult)result, "Failed to create OPAQUE server");
        }

        return new OpaqueServer(serverHandle);
    }

    /// <summary>
    /// Creates a registration response for a new user registration.
    /// </summary>
    /// <param name="registrationRequest">The 32-byte registration request from the client.</param>
    /// <param name="accountId">The unique account identifier (e.g., username, email, user ID).</param>
    /// <returns>The 64-byte registration response to send to the client.</returns>
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

        int result = OpaqueServerNative.opaque_server_create_registration_response(
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

    /// <summary>
    /// Generates the KE2 message for the authentication key exchange.
    /// </summary>
    /// <param name="ke1">The 88-byte KE1 message from the client.</param>
    /// <param name="accountId">The account identifier.</param>
    /// <param name="storedCredentials">The 168-byte stored credentials (registration record) for this user.</param>
    /// <param name="authState">The authentication state to track this session.</param>
    /// <returns>The 288-byte KE2 message to send to the client.</returns>
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

        int result = OpaqueServerNative.opaque_server_generate_ke2(
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

    /// <summary>
    /// Completes authentication by verifying KE3 and deriving session keys.
    /// </summary>
    /// <param name="ke3">The 64-byte KE3 message from the client.</param>
    /// <param name="authState">The authentication state from <see cref="GenerateKe2"/>.</param>
    /// <returns>The derived session and master keys if authentication succeeds, or null if it fails.</returns>
    public DerivedKeys? FinishAuthentication(byte[] ke3, AuthenticationState authState)
    {
        ThrowIfDisposed();

        if (ke3 == null || ke3.Length != OpaqueConstants.KE3_LENGTH)
        {
            return null;
        }

        if (authState == null)
            throw new ArgumentNullException(nameof(authState));

        byte[] sessionKey = new byte[OpaqueConstants.SESSION_KEY_LENGTH];
        byte[] masterKey = new byte[OpaqueConstants.MASTER_KEY_LENGTH];

        int result = OpaqueServerNative.opaque_server_finish(
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
            return null;
        }

        return new DerivedKeys(sessionKey, masterKey);
    }

    /// <summary>
    /// Gets the version of the native OPAQUE library.
    /// </summary>
    public static string GetNativeVersion()
    {
        IntPtr versionPtr = OpaqueServerNative.opaque_server_get_version();
        return versionPtr != IntPtr.Zero
            ? System.Runtime.InteropServices.Marshal.PtrToStringAnsi(versionPtr) ?? "unknown"
            : "unknown";
    }

    private void ThrowIfDisposed()
    {
        if (_disposed)
            throw new ObjectDisposedException(nameof(OpaqueServer));
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (_disposed) return;

        if (_serverHandle != IntPtr.Zero)
        {
            OpaqueServerNative.opaque_server_destroy(_serverHandle);
            _serverHandle = IntPtr.Zero;
        }

        _disposed = true;
        GC.SuppressFinalize(this);
    }

    /// <summary>Finalizer.</summary>
    ~OpaqueServer() => Dispose();
}
