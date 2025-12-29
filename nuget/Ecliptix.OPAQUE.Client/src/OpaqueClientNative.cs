using System;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;

namespace Ecliptix.OPAQUE.Client;

/// <summary>
/// P/Invoke declarations for the native OPAQUE client library.
/// </summary>
internal static class OpaqueClientNative
{
    private const string LibraryName = "libopaque_client";

    static OpaqueClientNative()
    {
        NativeLibrary.SetDllImportResolver(typeof(OpaqueClientNative).Assembly, DllImportResolver);
    }

    private static IntPtr DllImportResolver(string libraryName, Assembly assembly, DllImportSearchPath? searchPath)
    {
        if (libraryName != LibraryName)
            return IntPtr.Zero;

        string platformLibrary = GetPlatformLibraryName();
        string runtimeId = GetRuntimeIdentifier();

        // Search paths in priority order
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

        // Fallback to system search
        if (NativeLibrary.TryLoad(platformLibrary, assembly, DllImportSearchPath.AssemblyDirectory | DllImportSearchPath.SafeDirectories, out IntPtr fallbackHandle))
            return fallbackHandle;

        return IntPtr.Zero;
    }

    private static string GetPlatformLibraryName()
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            return "libopaque_client.dll";
        if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            return "libopaque_client.dylib";
        return "libopaque_client.so";
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

    // Client lifecycle
    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int opaque_client_create(byte[] serverPublicKey, UIntPtr keyLength, out IntPtr handle);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void opaque_client_destroy(IntPtr handle);

    // State management
    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int opaque_client_state_create(out IntPtr handle);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern void opaque_client_state_destroy(IntPtr handle);

    // Registration
    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int opaque_client_create_registration_request(
        IntPtr clientHandle,
        byte[] password,
        UIntPtr passwordLength,
        IntPtr stateHandle,
        byte[] requestData,
        UIntPtr requestBufferSize);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int opaque_client_finalize_registration(
        IntPtr clientHandle,
        byte[] responseData,
        UIntPtr responseLength,
        IntPtr stateHandle,
        byte[] recordData,
        UIntPtr recordBufferSize);

    // Authentication
    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int opaque_client_generate_ke1(
        IntPtr clientHandle,
        byte[] password,
        UIntPtr passwordLength,
        IntPtr stateHandle,
        byte[] ke1Data,
        UIntPtr ke1BufferSize);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int opaque_client_generate_ke3(
        IntPtr clientHandle,
        byte[] ke2Data,
        UIntPtr ke2Length,
        IntPtr stateHandle,
        byte[] ke3Data,
        UIntPtr ke3BufferSize);

    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern int opaque_client_finish(
        IntPtr clientHandle,
        IntPtr stateHandle,
        byte[] sessionKey,
        UIntPtr sessionKeyBufferSize,
        byte[] masterKey,
        UIntPtr masterKeyBufferSize);

    // Version
    [DllImport(LibraryName, CallingConvention = CallingConvention.Cdecl)]
    internal static extern IntPtr opaque_client_get_version();
}
