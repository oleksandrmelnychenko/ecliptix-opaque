using System;

namespace Ecliptix.OPAQUE.Agent;

public class OpaqueException : Exception
{
    public OpaqueResult ResultCode { get; }

    public OpaqueException(OpaqueResult resultCode, string message)
        : base($"{message}: {resultCode}")
    {
        ResultCode = resultCode;
    }

    public OpaqueException(string message) : base(message)
    {
        ResultCode = OpaqueResult.InvalidInput;
    }
}
