using System;
using System.Security.Cryptography;

namespace Ecliptix.OPAQUE.Client;

/// <summary>
/// OPAQUE protocol client (initiator) for secure password authentication.
/// </summary>
public sealed class OpaqueClient : IDisposable
{
    private readonly IntPtr _clientHandle;
    private bool _disposed;

    /// <summary>
    /// Initializes a new OPAQUE client with the server's public key.
    /// </summary>
    /// <param name="serverPublicKey">The server's 32-byte Ristretto255 public key.</param>
    public OpaqueClient(byte[] serverPublicKey)
    {
        if (serverPublicKey.Length != OpaqueConstants.PUBLIC_KEY_LENGTH)
        {
            throw new ArgumentException(string.Format(OpaqueErrorMessages.SERVER_PUBLIC_KEY_INVALID_SIZE,
                OpaqueConstants.PUBLIC_KEY_LENGTH));
        }

        int result = OpaqueClientNative.opaque_client_create(
            serverPublicKey, (UIntPtr)serverPublicKey.Length, out _clientHandle);

        if (result != (int)OpaqueResult.SUCCESS || _clientHandle == IntPtr.Zero)
        {
            throw new InvalidOperationException(string.Format(OpaqueErrorMessages.FAILED_TO_CREATE_OPAQUE_CLIENT,
                (OpaqueResult)result));
        }
    }

    /// <summary>
    /// Creates a registration request to register a new password with the server.
    /// </summary>
    /// <param name="secureKey">The secure key bytes (will be securely cleared after use).</param>
    /// <returns>A <see cref="RegistrationResult"/> containing the request to send to the server.</returns>
    public RegistrationResult CreateRegistrationRequest(byte[] secureKey)
    {
        ThrowIfDisposed();
        if (secureKey == null || secureKey.Length == 0)
        {
            throw new ArgumentException(OpaqueErrorMessages.SECURE_KEY_NULL_OR_EMPTY);
        }

        try
        {
            byte[] request = new byte[OpaqueConstants.REGISTRATION_REQUEST_LENGTH];

            int stateResult = OpaqueClientNative.opaque_client_state_create(out IntPtr state);
            if (stateResult != (int)OpaqueResult.SUCCESS)
            {
                throw new InvalidOperationException(string.Format(OpaqueErrorMessages.FAILED_TO_CREATE_STATE,
                    (OpaqueResult)stateResult));
            }

            int result = OpaqueClientNative.opaque_client_create_registration_request(
                _clientHandle, secureKey, (UIntPtr)secureKey.Length, state, request, (UIntPtr)request.Length);

            if (result == (int)OpaqueResult.SUCCESS)
            {
                return new RegistrationResult(request, state);
            }

            OpaqueClientNative.opaque_client_state_destroy(state);
            throw new InvalidOperationException(string.Format(OpaqueErrorMessages.FAILED_TO_CREATE_REGISTRATION_REQUEST,
                (OpaqueResult)result));
        }
        finally
        {
            ClearSecureKey(secureKey);
        }
    }

    /// <summary>
    /// Finalizes registration after receiving the server's response.
    /// </summary>
    /// <param name="serverResponse">The 64-byte response from the server.</param>
    /// <param name="registrationState">The state from <see cref="CreateRegistrationRequest"/>.</param>
    /// <returns>The registration record (168 bytes) to be stored on the server.</returns>
    public byte[] FinalizeRegistration(byte[]? serverResponse, RegistrationResult registrationState)
    {
        try
        {
            ThrowIfDisposed();
            if (serverResponse?.Length != OpaqueConstants.REGISTRATION_RESPONSE_LENGTH)
            {
                throw new ArgumentException(
                    string.Format(OpaqueErrorMessages.SERVER_RESPONSE_INVALID_SIZE,
                        OpaqueConstants.REGISTRATION_RESPONSE_LENGTH));
            }

            byte[] record = new byte[OpaqueConstants.REGISTRATION_RECORD_LENGTH];

            int result = OpaqueClientNative.opaque_client_finalize_registration(
                _clientHandle, serverResponse, (UIntPtr)serverResponse.Length,
                registrationState.StateHandle, record, (UIntPtr)record.Length);

            return result != (int)OpaqueResult.SUCCESS
                ? throw new InvalidOperationException(string.Format(
                    OpaqueErrorMessages.FAILED_TO_FINALIZE_REGISTRATION,
                    (OpaqueResult)result))
                : record;
        }
        finally
        {
            registrationState.Dispose();
        }
    }

    /// <summary>
    /// Generates the first key exchange message (KE1) to begin authentication.
    /// </summary>
    /// <param name="secureKey">The secure key bytes (will be securely cleared after use).</param>
    /// <returns>A <see cref="KeyExchangeResult"/> containing KE1 to send to the server.</returns>
    public KeyExchangeResult GenerateKe1(byte[] secureKey)
    {
        ThrowIfDisposed();
        if (secureKey == null || secureKey.Length == 0)
        {
            throw new ArgumentException(OpaqueErrorMessages.SECURE_KEY_NULL_OR_EMPTY);
        }

        try
        {
            byte[] ke1 = new byte[OpaqueConstants.KE1_LENGTH];

            int stateResult = OpaqueClientNative.opaque_client_state_create(out IntPtr state);
            if (stateResult != (int)OpaqueResult.SUCCESS)
            {
                throw new InvalidOperationException(string.Format(OpaqueErrorMessages.FAILED_TO_CREATE_STATE,
                    (OpaqueResult)stateResult));
            }

            int result = OpaqueClientNative.opaque_client_generate_ke1(
                _clientHandle, secureKey, (UIntPtr)secureKey.Length, state, ke1, (UIntPtr)ke1.Length);

            if (result == (int)OpaqueResult.SUCCESS)
            {
                return new KeyExchangeResult(ke1, state);
            }

            OpaqueClientNative.opaque_client_state_destroy(state);
            throw new InvalidOperationException(string.Format(OpaqueErrorMessages.FAILED_TO_GENERATE_KE1,
                (OpaqueResult)result));
        }
        finally
        {
            ClearSecureKey(secureKey);
        }
    }

    /// <summary>
    /// Generates the third key exchange message (KE3) after receiving KE2 from the server.
    /// </summary>
    /// <param name="ke2">The KE2 message from the server.</param>
    /// <param name="keyExchangeState">The state from <see cref="GenerateKe1"/>.</param>
    /// <returns>A tuple containing (success, ke3 data or null).</returns>
    public (OpaqueResult Result, byte[]? Ke3) GenerateKe3(byte[]? ke2, KeyExchangeResult keyExchangeState)
    {
        ThrowIfDisposed();
        if (ke2?.Length != OpaqueConstants.KE2_LENGTH)
        {
            return (OpaqueResult.INVALID_INPUT, null);
        }

        byte[] ke3 = new byte[OpaqueConstants.KE3_LENGTH];

        int result = OpaqueClientNative.opaque_client_generate_ke3(
            _clientHandle, ke2, (UIntPtr)ke2.Length, keyExchangeState.StateHandle, ke3, (UIntPtr)ke3.Length);

        return result != (int)OpaqueResult.SUCCESS
            ? ((OpaqueResult)result, null)
            : (OpaqueResult.SUCCESS, ke3);
    }

    /// <summary>
    /// Derives the session and master keys after successful authentication.
    /// Call this after the server confirms KE3.
    /// </summary>
    /// <param name="keyExchangeState">The state from <see cref="GenerateKe1"/>.</param>
    /// <returns>A tuple containing (SessionKey, MasterKey).</returns>
    public (byte[] SessionKey, byte[] MasterKey) DeriveBaseMasterKey(KeyExchangeResult keyExchangeState)
    {
        ThrowIfDisposed();

        byte[] sessionKey = new byte[OpaqueConstants.HASH_LENGTH];
        byte[] masterKey = new byte[OpaqueConstants.MASTER_KEY_LENGTH];

        int result = OpaqueClientNative.opaque_client_finish(
            _clientHandle, keyExchangeState.StateHandle,
            sessionKey, (UIntPtr)sessionKey.Length,
            masterKey, (UIntPtr)masterKey.Length);

        if (result != (int)OpaqueResult.SUCCESS)
        {
            throw new InvalidOperationException(string.Format(OpaqueErrorMessages.FAILED_TO_DERIVE_SESSION_KEY,
                (OpaqueResult)result));
        }

        return (sessionKey, masterKey);
    }

    private void ThrowIfDisposed()
    {
        if (_disposed)
        {
            throw new ObjectDisposedException(nameof(OpaqueClient));
        }
    }

    private static void ClearSecureKey(byte[] secureKey) => CryptographicOperations.ZeroMemory(secureKey);

    /// <inheritdoc />
    public void Dispose()
    {
        if (_disposed || _clientHandle == IntPtr.Zero)
        {
            return;
        }

        OpaqueClientNative.opaque_client_destroy(_clientHandle);
        _disposed = true;
    }
}
