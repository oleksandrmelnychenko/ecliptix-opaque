using System;

namespace Ecliptix.OPAQUE.Client;

/// <summary>
/// Holds the state for a registration operation, including the request data and native state handle.
/// </summary>
public sealed class RegistrationState : IDisposable
{
    private readonly byte[] _request;
    private IntPtr _stateHandle;
    private bool _disposed;

    internal RegistrationState(byte[] request, IntPtr stateHandle)
    {
        _request = request;
        _stateHandle = stateHandle;
    }

    /// <summary>
    /// Gets a copy of the registration request data to send to the server.
    /// </summary>
    public byte[] GetRequestCopy() => (byte[])_request.Clone();

    /// <summary>
    /// Gets the registration request data as a read-only span.
    /// </summary>
    public ReadOnlySpan<byte> Request => _request;

    internal IntPtr StateHandle => _stateHandle;

    /// <inheritdoc />
    public void Dispose()
    {
        if (_disposed) return;

        if (_stateHandle != IntPtr.Zero)
        {
            OpaqueClientNative.opaque_client_state_destroy(_stateHandle);
            _stateHandle = IntPtr.Zero;
        }

        _disposed = true;
        GC.SuppressFinalize(this);
    }

    /// <summary>Finalizer.</summary>
    ~RegistrationState() => Dispose();
}

/// <summary>
/// Holds the state for a key exchange (authentication) operation.
/// </summary>
public sealed class KeyExchangeState : IDisposable
{
    private readonly byte[] _ke1Data;
    private IntPtr _stateHandle;
    private bool _disposed;

    internal KeyExchangeState(byte[] ke1Data, IntPtr stateHandle)
    {
        _ke1Data = ke1Data;
        _stateHandle = stateHandle;
    }

    /// <summary>
    /// Gets a copy of the KE1 message to send to the server.
    /// </summary>
    public byte[] GetKe1Copy() => (byte[])_ke1Data.Clone();

    /// <summary>
    /// Gets the KE1 message data as a read-only span.
    /// </summary>
    public ReadOnlySpan<byte> Ke1 => _ke1Data;

    internal IntPtr StateHandle => _stateHandle;

    /// <inheritdoc />
    public void Dispose()
    {
        if (_disposed) return;

        if (_stateHandle != IntPtr.Zero)
        {
            OpaqueClientNative.opaque_client_state_destroy(_stateHandle);
            _stateHandle = IntPtr.Zero;
        }

        _disposed = true;
        GC.SuppressFinalize(this);
    }

    /// <summary>Finalizer.</summary>
    ~KeyExchangeState() => Dispose();
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
