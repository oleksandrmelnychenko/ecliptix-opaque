using System;
using System.Security.Cryptography;

namespace Ecliptix.OPAQUE.Agent;

public sealed class OpaqueAgent : IDisposable
{
    private readonly IntPtr _agentHandle;
    private bool _disposed;

    public OpaqueAgent(byte[] relayPublicKey)
    {
        if (relayPublicKey == null)
        {
            throw new ArgumentNullException(nameof(relayPublicKey));
        }

        if (relayPublicKey.Length != OpaqueConstants.PUBLIC_KEY_LENGTH)
        {
            throw new ArgumentException(string.Format(OpaqueErrorMessages.RELAY_PUBLIC_KEY_INVALID_SIZE,
                OpaqueConstants.PUBLIC_KEY_LENGTH));
        }

        int result = OpaqueAgentNative.opaque_agent_create(
            relayPublicKey, (UIntPtr)relayPublicKey.Length, out _agentHandle);

        if (result != (int)OpaqueResult.Success || _agentHandle == IntPtr.Zero)
        {
            throw new OpaqueException((OpaqueResult)result,
                OpaqueErrorMessages.FAILED_TO_CREATE_OPAQUE_AGENT);
        }
    }

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

            int stateResult = OpaqueAgentNative.opaque_agent_state_create(out IntPtr state);
            if (stateResult != (int)OpaqueResult.Success)
            {
                throw new OpaqueException((OpaqueResult)stateResult,
                    OpaqueErrorMessages.FAILED_TO_CREATE_STATE);
            }

            int result = OpaqueAgentNative.opaque_agent_create_registration_request(
                _agentHandle, secureKey, (UIntPtr)secureKey.Length, state, request, (UIntPtr)request.Length);

            if (result == (int)OpaqueResult.Success)
            {
                return new RegistrationResult(request, state);
            }

            OpaqueAgentNative.opaque_agent_state_destroy(state);
            throw new OpaqueException((OpaqueResult)result,
                OpaqueErrorMessages.FAILED_TO_CREATE_REGISTRATION_REQUEST);
        }
        finally
        {
            ClearSecureKey(secureKey);
        }
    }

    public byte[] FinalizeRegistration(byte[]? relayResponse, RegistrationResult registrationState)
    {
        if (registrationState == null)
        {
            throw new ArgumentNullException(nameof(registrationState));
        }

        try
        {
            ThrowIfDisposed();
            if (relayResponse?.Length != OpaqueConstants.REGISTRATION_RESPONSE_LENGTH)
            {
                throw new ArgumentException(
                    string.Format(OpaqueErrorMessages.RELAY_RESPONSE_INVALID_SIZE,
                        OpaqueConstants.REGISTRATION_RESPONSE_LENGTH));
            }

            byte[] record = new byte[OpaqueConstants.REGISTRATION_RECORD_LENGTH];

            int result = OpaqueAgentNative.opaque_agent_finalize_registration(
                _agentHandle, relayResponse, (UIntPtr)relayResponse.Length,
                registrationState.StateHandle, record, (UIntPtr)record.Length);

            return result != (int)OpaqueResult.Success
                ? throw new OpaqueException((OpaqueResult)result,
                    OpaqueErrorMessages.FAILED_TO_FINALIZE_REGISTRATION)
                : record;
        }
        finally
        {
            registrationState.Dispose();
        }
    }

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

            int stateResult = OpaqueAgentNative.opaque_agent_state_create(out IntPtr state);
            if (stateResult != (int)OpaqueResult.Success)
            {
                throw new OpaqueException((OpaqueResult)stateResult,
                    OpaqueErrorMessages.FAILED_TO_CREATE_STATE);
            }

            int result = OpaqueAgentNative.opaque_agent_generate_ke1(
                _agentHandle, secureKey, (UIntPtr)secureKey.Length, state, ke1, (UIntPtr)ke1.Length);

            if (result == (int)OpaqueResult.Success)
            {
                return new KeyExchangeResult(ke1, state);
            }

            OpaqueAgentNative.opaque_agent_state_destroy(state);
            throw new OpaqueException((OpaqueResult)result,
                OpaqueErrorMessages.FAILED_TO_GENERATE_KE1);
        }
        finally
        {
            ClearSecureKey(secureKey);
        }
    }

    public byte[] GenerateKe3(byte[] ke2, KeyExchangeResult keyExchangeState)
    {
        ThrowIfDisposed();
        if (ke2 == null || ke2.Length != OpaqueConstants.KE2_LENGTH)
        {
            throw new ArgumentException(
                string.Format(OpaqueErrorMessages.KE2_INVALID_SIZE, OpaqueConstants.KE2_LENGTH),
                nameof(ke2));
        }

        if (keyExchangeState == null)
        {
            throw new ArgumentNullException(nameof(keyExchangeState));
        }

        byte[] ke3 = new byte[OpaqueConstants.KE3_LENGTH];

        int result = OpaqueAgentNative.opaque_agent_generate_ke3(
            _agentHandle, ke2, (UIntPtr)ke2.Length, keyExchangeState.StateHandle, ke3, (UIntPtr)ke3.Length);

        if (result != (int)OpaqueResult.Success)
        {
            throw new OpaqueException((OpaqueResult)result, "Failed to generate KE3");
        }

        return ke3;
    }

    public (byte[] SessionKey, byte[] MasterKey) DeriveBaseMasterKey(KeyExchangeResult keyExchangeState)
    {
        ThrowIfDisposed();

        if (keyExchangeState == null)
        {
            throw new ArgumentNullException(nameof(keyExchangeState));
        }

        byte[] sessionKey = new byte[OpaqueConstants.HASH_LENGTH];
        byte[] masterKey = new byte[OpaqueConstants.MASTER_KEY_LENGTH];

        int result = OpaqueAgentNative.opaque_agent_finish(
            _agentHandle, keyExchangeState.StateHandle,
            sessionKey, (UIntPtr)sessionKey.Length,
            masterKey, (UIntPtr)masterKey.Length);

        if (result != (int)OpaqueResult.Success)
        {
            throw new OpaqueException((OpaqueResult)result,
                OpaqueErrorMessages.FAILED_TO_DERIVE_SESSION_KEY);
        }

        return (sessionKey, masterKey);
    }

    private void ThrowIfDisposed()
    {
        if (_disposed)
        {
            throw new ObjectDisposedException(nameof(OpaqueAgent));
        }
    }

    private static void ClearSecureKey(byte[] secureKey) => CryptographicOperations.ZeroMemory(secureKey);

    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    private void Dispose(bool disposing)
    {
        if (_disposed || _agentHandle == IntPtr.Zero)
        {
            return;
        }

        OpaqueAgentNative.opaque_agent_destroy(_agentHandle);
        _disposed = true;
    }

    ~OpaqueAgent() => Dispose(false);
}
