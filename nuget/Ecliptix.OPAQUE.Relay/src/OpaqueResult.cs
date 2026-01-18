namespace Ecliptix.OPAQUE.Relay;




public enum OpaqueResult
{

    Success = 0,


    InvalidInput = -1,


    CryptoError = -2,


    MemoryError = -3,


    ValidationError = -4,


    AuthenticationError = -5,


    InvalidPublicKey = -6
}




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
