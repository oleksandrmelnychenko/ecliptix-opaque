using System;
using System.Security.Cryptography;

namespace Ecliptix.OPAQUE.Client;

/// <summary>
/// OPAQUE protocol client (initiator) for secure password authentication.
/// Implements the client-side of the OPAQUE PAKE protocol.
/// </summary>
/// <remarks>
/// The OPAQUE protocol ensures that passwords never leave the client device.
/// Server stores only a verifier that cannot be used to impersonate the client.
/// </remarks>
public sealed class OpaqueClient : IDisposable
{
    private IntPtr _clientHandle;
    private bool _disposed;

    /// <summary>
    /// Initializes a new OPAQUE client with the server's public key.
    /// </summary>
    /// <param name="serverPublicKey">The server's 32-byte Ristretto255 public key.</param>
    /// <exception cref="ArgumentException">If the public key is not exactly 32 bytes.</exception>
    /// <exception cref="OpaqueException">If client creation fails.</exception>
    public OpaqueClient(byte[] serverPublicKey)
    {
        if (serverPublicKey == null || serverPublicKey.Length != OpaqueConstants.PUBLIC_KEY_LENGTH)
        {
            throw new ArgumentException(
                $"Server public key must be exactly {OpaqueConstants.PUBLIC_KEY_LENGTH} bytes",
                nameof(serverPublicKey));
        }

        int result = OpaqueClientNative.opaque_client_create(
            serverPublicKey,
            (UIntPtr)serverPublicKey.Length,
            out _clientHandle);

        if (result != (int)OpaqueResult.Success || _clientHandle == IntPtr.Zero)
        {
            throw new OpaqueException((OpaqueResult)result, "Failed to create OPAQUE client");
        }
    }

    /// <summary>
    /// Creates a registration request to register a new password with the server.
    /// </summary>
    /// <param name="password">The password bytes (will be securely cleared after use).</param>
    /// <returns>A <see cref="RegistrationState"/> containing the request to send to the server.</returns>
    /// <exception cref="ArgumentException">If password is null or empty.</exception>
    /// <exception cref="OpaqueException">If request creation fails.</exception>
    public RegistrationState CreateRegistrationRequest(byte[] password)
    {
        ThrowIfDisposed();

        if (password == null || password.Length == 0)
            throw new ArgumentException("Password cannot be null or empty", nameof(password));

        try
        {
            int stateResult = OpaqueClientNative.opaque_client_state_create(out IntPtr stateHandle);
            if (stateResult != (int)OpaqueResult.Success)
            {
                throw new OpaqueException((OpaqueResult)stateResult, "Failed to create registration state");
            }

            byte[] request = new byte[OpaqueConstants.REGISTRATION_REQUEST_LENGTH];

            int result = OpaqueClientNative.opaque_client_create_registration_request(
                _clientHandle,
                password,
                (UIntPtr)password.Length,
                stateHandle,
                request,
                (UIntPtr)request.Length);

            if (result != (int)OpaqueResult.Success)
            {
                OpaqueClientNative.opaque_client_state_destroy(stateHandle);
                throw new OpaqueException((OpaqueResult)result, "Failed to create registration request");
            }

            return new RegistrationState(request, stateHandle);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(password);
        }
    }

    /// <summary>
    /// Finalizes registration after receiving the server's response.
    /// </summary>
    /// <param name="serverResponse">The 64-byte response from the server.</param>
    /// <param name="registrationState">The state from <see cref="CreateRegistrationRequest"/>.</param>
    /// <returns>The registration record (168 bytes) to be stored on the server.</returns>
    /// <exception cref="ArgumentException">If server response has invalid length.</exception>
    /// <exception cref="OpaqueException">If finalization fails.</exception>
    public byte[] FinalizeRegistration(byte[] serverResponse, RegistrationState registrationState)
    {
        ThrowIfDisposed();

        if (serverResponse == null || serverResponse.Length != OpaqueConstants.REGISTRATION_RESPONSE_LENGTH)
        {
            throw new ArgumentException(
                $"Server response must be exactly {OpaqueConstants.REGISTRATION_RESPONSE_LENGTH} bytes",
                nameof(serverResponse));
        }

        if (registrationState == null)
            throw new ArgumentNullException(nameof(registrationState));

        try
        {
            byte[] record = new byte[OpaqueConstants.REGISTRATION_RECORD_LENGTH];

            int result = OpaqueClientNative.opaque_client_finalize_registration(
                _clientHandle,
                serverResponse,
                (UIntPtr)serverResponse.Length,
                registrationState.StateHandle,
                record,
                (UIntPtr)record.Length);

            if (result != (int)OpaqueResult.Success)
            {
                throw new OpaqueException((OpaqueResult)result, "Failed to finalize registration");
            }

            return record;
        }
        finally
        {
            registrationState.Dispose();
        }
    }

    /// <summary>
    /// Generates the first key exchange message (KE1) to begin authentication.
    /// </summary>
    /// <param name="password">The password bytes (will be securely cleared after use).</param>
    /// <returns>A <see cref="KeyExchangeState"/> containing KE1 to send to the server.</returns>
    /// <exception cref="ArgumentException">If password is null or empty.</exception>
    /// <exception cref="OpaqueException">If KE1 generation fails.</exception>
    public KeyExchangeState GenerateKe1(byte[] password)
    {
        ThrowIfDisposed();

        if (password == null || password.Length == 0)
            throw new ArgumentException("Password cannot be null or empty", nameof(password));

        try
        {
            int stateResult = OpaqueClientNative.opaque_client_state_create(out IntPtr stateHandle);
            if (stateResult != (int)OpaqueResult.Success)
            {
                throw new OpaqueException((OpaqueResult)stateResult, "Failed to create key exchange state");
            }

            byte[] ke1 = new byte[OpaqueConstants.KE1_LENGTH];

            int result = OpaqueClientNative.opaque_client_generate_ke1(
                _clientHandle,
                password,
                (UIntPtr)password.Length,
                stateHandle,
                ke1,
                (UIntPtr)ke1.Length);

            if (result != (int)OpaqueResult.Success)
            {
                OpaqueClientNative.opaque_client_state_destroy(stateHandle);
                throw new OpaqueException((OpaqueResult)result, "Failed to generate KE1");
            }

            return new KeyExchangeState(ke1, stateHandle);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(password);
        }
    }

    /// <summary>
    /// Generates the third key exchange message (KE3) after receiving KE2 from the server.
    /// </summary>
    /// <param name="ke2">The 288-byte KE2 message from the server.</param>
    /// <param name="keyExchangeState">The state from <see cref="GenerateKe1"/>.</param>
    /// <returns>The KE3 message (64 bytes) to send to the server, or null if authentication failed.</returns>
    /// <exception cref="ArgumentException">If KE2 has invalid length.</exception>
    public byte[]? GenerateKe3(byte[] ke2, KeyExchangeState keyExchangeState)
    {
        ThrowIfDisposed();

        if (ke2 == null || ke2.Length != OpaqueConstants.KE2_LENGTH)
        {
            return null;
        }

        if (keyExchangeState == null)
            throw new ArgumentNullException(nameof(keyExchangeState));

        byte[] ke3 = new byte[OpaqueConstants.KE3_LENGTH];

        int result = OpaqueClientNative.opaque_client_generate_ke3(
            _clientHandle,
            ke2,
            (UIntPtr)ke2.Length,
            keyExchangeState.StateHandle,
            ke3,
            (UIntPtr)ke3.Length);

        if (result != (int)OpaqueResult.Success)
        {
            return null;
        }

        return ke3;
    }

    /// <summary>
    /// Derives the session and master keys after successful authentication.
    /// Call this after the server confirms KE3.
    /// </summary>
    /// <param name="keyExchangeState">The state from <see cref="GenerateKe1"/>.</param>
    /// <returns>The derived session and master keys.</returns>
    /// <exception cref="OpaqueException">If key derivation fails.</exception>
    public DerivedKeys FinishAuthentication(KeyExchangeState keyExchangeState)
    {
        ThrowIfDisposed();

        if (keyExchangeState == null)
            throw new ArgumentNullException(nameof(keyExchangeState));

        byte[] sessionKey = new byte[OpaqueConstants.SESSION_KEY_LENGTH];
        byte[] masterKey = new byte[OpaqueConstants.MASTER_KEY_LENGTH];

        int result = OpaqueClientNative.opaque_client_finish(
            _clientHandle,
            keyExchangeState.StateHandle,
            sessionKey,
            (UIntPtr)sessionKey.Length,
            masterKey,
            (UIntPtr)masterKey.Length);

        if (result != (int)OpaqueResult.Success)
        {
            CryptographicOperations.ZeroMemory(sessionKey);
            CryptographicOperations.ZeroMemory(masterKey);
            throw new OpaqueException((OpaqueResult)result, "Failed to derive session keys");
        }

        return new DerivedKeys(sessionKey, masterKey);
    }

    /// <summary>
    /// Gets the version of the native OPAQUE library.
    /// </summary>
    public static string GetNativeVersion()
    {
        IntPtr versionPtr = OpaqueClientNative.opaque_client_get_version();
        return versionPtr != IntPtr.Zero
            ? System.Runtime.InteropServices.Marshal.PtrToStringAnsi(versionPtr) ?? "unknown"
            : "unknown";
    }

    private void ThrowIfDisposed()
    {
        if (_disposed)
            throw new ObjectDisposedException(nameof(OpaqueClient));
    }

    /// <inheritdoc />
    public void Dispose()
    {
        if (_disposed) return;

        if (_clientHandle != IntPtr.Zero)
        {
            OpaqueClientNative.opaque_client_destroy(_clientHandle);
            _clientHandle = IntPtr.Zero;
        }

        _disposed = true;
        GC.SuppressFinalize(this);
    }

    /// <summary>Finalizer.</summary>
    ~OpaqueClient() => Dispose();
}
