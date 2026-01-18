using System;

namespace Ecliptix.OPAQUE.Agent;

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

    public byte[] GetRequestCopy()
    {
        ThrowIfDisposed();
        return (byte[])_request.Clone();
    }

    internal IntPtr StateHandle
    {
        get
        {
            ThrowIfDisposed();
            return _stateHandle;
        }
    }

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

    ~RegistrationResult() => Dispose(false);

    private void ThrowIfDisposed()
    {
        if (_disposed)
        {
            throw new ObjectDisposedException(nameof(RegistrationResult));
        }
    }
}

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

    public byte[] GetKeyExchangeDataCopy()
    {
        ThrowIfDisposed();
        return (byte[])_keyExchangeData.Clone();
    }

    internal IntPtr StateHandle
    {
        get
        {
            ThrowIfDisposed();
            return _stateHandle;
        }
    }

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

    ~KeyExchangeResult() => Dispose(false);

    private void ThrowIfDisposed()
    {
        if (_disposed)
        {
            throw new ObjectDisposedException(nameof(KeyExchangeResult));
        }
    }
}
