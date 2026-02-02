using System;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;

namespace Ecliptix.OPAQUE.Relay;




public static class OpaqueRelayNative
{
    private const string LibraryName = "eop.relay";

    static OpaqueRelayNative()
    {
        NativeLibrary.SetDllImportResolver(typeof(OpaqueRelayNative).Assembly, DllImportResolver);
    }

    private static IntPtr DllImportResolver(string libraryName, Assembly assembly, DllImportSearchPath? searchPath)
    {
        if (libraryName != LibraryName)
            return IntPtr.Zero;

        string platformLibrary = GetPlatformLibraryName();
        string runtimeId = GetRuntimeIdentifier();

        string[] searchPaths =
        [
            Path.Combine(AppContext.BaseDirectory, platformLibrary),
            Path.Combine(AppContext.BaseDirectory, "runtimes", runtimeId, "native", platformLibrary),
            Path.Combine(Path.GetDirectoryName(assembly.Location) ?? string.Empty, platformLibrary),
            Path.Combine(Path.GetDirectoryName(assembly.Location) ?? string.Empty, "runtimes", runtimeId, "native", platformLibrary),
        ];

        foreach (string path in searchPaths)
        {
            if (NativeLibrary.TryLoad(path, out IntPtr handle))
                return handle;
        }

        if (NativeLibrary.TryLoad(platformLibrary, assembly, DllImportSearchPath.AssemblyDirectory | DllImportSearchPath.SafeDirectories, out IntPtr fallbackHandle))
            return fallbackHandle;

        return IntPtr.Zero;
    }

    private static string GetPlatformLibraryName()
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            return "eop.relay.dll";
        if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            return "libeop.relay.dylib";
        return "libeop.relay.so";
    }

    private static string GetRuntimeIdentifier()
    {
        var arch = RuntimeInformation.ProcessArchitecture;

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            return arch switch
            {
                Architecture.X64 => "win-x64",
                Architecture.X86 => "win-x86",
                Architecture.Arm64 => "win-arm64",
                _ => "win-x64"
            };
        }

        if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
        {
            bool isMusl = File.Exists("/lib/ld-musl-x86_64.so.1") || File.Exists("/lib/ld-musl-aarch64.so.1");
            string suffix = isMusl ? "-musl" : "";
            return arch switch
            {
                Architecture.X64 => $"linux{suffix}-x64",
                Architecture.Arm64 => $"linux{suffix}-arm64",
                _ => $"linux{suffix}-x64"
            };
        }

        if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
        {
            return arch switch
            {
                Architecture.Arm64 => "osx-arm64",
                _ => "osx-x64"
            };
        }

        return "linux-x64";
    }


    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern int opaque_server_keypair_generate(out IntPtr handle);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern void opaque_server_keypair_destroy(IntPtr handle);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern int opaque_server_keypair_get_public_key(
        IntPtr handle,
        [Out] byte[] publicKey,
        UIntPtr keyBufferSize);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern int opaque_server_derive_keypair_from_seed(
        [In] byte[] seed,
        UIntPtr seedLen,
        [Out] byte[] privateKey,
        UIntPtr privateKeyBufferLen,
        [Out] byte[] publicKey,
        UIntPtr publicKeyBufferLen);


    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern int opaque_server_create(IntPtr keypairHandle, out IntPtr handle);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern int opaque_server_create_with_keys(
        [In] byte[] privateKey,
        UIntPtr privateKeyLen,
        [In] byte[] publicKey,
        UIntPtr publicKeyLen,
        out IntPtr serverHandle);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern int opaque_server_create_default(out IntPtr handle);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern void opaque_server_destroy(IntPtr handle);


    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern int opaque_server_state_create(out IntPtr handle);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern void opaque_server_state_destroy(IntPtr handle);


    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern int opaque_server_create_registration_response(
        IntPtr serverHandle,
        [In] byte[] requestData,
        UIntPtr requestLength,
        [In] byte[] accountId,
        UIntPtr accountIdLength,
        [Out] byte[] responseData,
        UIntPtr responseBufferSize);


    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern int opaque_server_generate_ke2(
        IntPtr serverHandle,
        [In] byte[] ke1Data,
        UIntPtr ke1Length,
        [In] byte[] accountId,
        UIntPtr accountIdLength,
        [In] byte[] credentialsData,
        UIntPtr credentialsLength,
        [Out] byte[] ke2Data,
        UIntPtr ke2BufferSize,
        IntPtr stateHandle);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern int opaque_server_finish(
        IntPtr serverHandle,
        [In] byte[] ke3Data,
        UIntPtr ke3Length,
        IntPtr stateHandle,
        [Out] byte[] sessionKey,
        UIntPtr sessionKeyBufferSize,
        [Out] byte[] masterKey,
        UIntPtr masterKeyBufferSize);


    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    public static extern IntPtr opaque_server_get_version();
}
