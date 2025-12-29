using System;

namespace Ecliptix.OPAQUE.Client;

/// <summary>
/// Holds the state for a registration operation, including the request data and native state handle.
/// </summary>
public sealed class RegistrationResult : IDisposable
{
    private readonly byte[] _request;
    private IntPtr _stateHandle;
    private bool _disposed;

    internal RegistrationResult(byte[] request, IntPtr stateHandle)
    {
        _request = request;
        _stateHandle = stateHandle;
    }

    /// <summary>
    /// Gets a copy of the registration request data to send to the server.
    /// </summary>
    public byte[] GetRequestCopy() => (byte[])_request.Clone();

    internal IntPtr StateHandle => _stateHandle;

    /// <inheritdoc />
    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    private void Dispose(bool disposing)
    {
        if (_disposed) return;

        if (_stateHandle != IntPtr.Zero)
        {
            OpaqueClientNative.opaque_client_state_destroy(_stateHandle);
            _stateHandle = IntPtr.Zero;
        }

        _disposed = true;
    }

    /// <summary>Finalizer.</summary>
    ~RegistrationResult() => Dispose(false);
}

/// <summary>
/// Holds the state for a key exchange (authentication) operation.
/// </summary>
public sealed class KeyExchangeResult : IDisposable
{
    private readonly byte[] _keyExchangeData;
    private IntPtr _stateHandle;
    private bool _disposed;

    internal KeyExchangeResult(byte[] keyExchangeData, IntPtr stateHandle)
    {
        _keyExchangeData = keyExchangeData;
        _stateHandle = stateHandle;
    }

    /// <summary>
    /// Gets a copy of the KE1 message to send to the server.
    /// </summary>
    public byte[] GetKeyExchangeDataCopy() => (byte[])_keyExchangeData.Clone();

    internal IntPtr StateHandle => _stateHandle;

    /// <inheritdoc />
    public void Dispose()
    {
        Dispose(true);
        GC.SuppressFinalize(this);
    }

    private void Dispose(bool disposing)
    {
        if (_disposed) return;

        if (_stateHandle != IntPtr.Zero)
        {
            OpaqueClientNative.opaque_client_state_destroy(_stateHandle);
            _stateHandle = IntPtr.Zero;
        }

        _disposed = true;
    }

    /// <summary>Finalizer.</summary>
    ~KeyExchangeResult() => Dispose(false);
}
