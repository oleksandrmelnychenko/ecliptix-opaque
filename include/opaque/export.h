#pragma once
#ifdef _WIN32
    #ifdef ECLIPTIX_OPAQUE_EXPORTS
        #define ECLIPTIX_OPAQUE_API __declspec(dllexport)
    #else
        #define ECLIPTIX_OPAQUE_API __declspec(dllimport)
    #endif
    #define ECLIPTIX_OPAQUE_CALL __cdecl
    #define ECLIPTIX_OPAQUE_LOCAL
#elif defined(__GNUC__) && __GNUC__ >= 4
    #define ECLIPTIX_OPAQUE_API __attribute__((visibility("default")))
    #define ECLIPTIX_OPAQUE_CALL
    #define ECLIPTIX_OPAQUE_LOCAL __attribute__((visibility("hidden")))
#else
    #define ECLIPTIX_OPAQUE_API
    #define ECLIPTIX_OPAQUE_CALL
    #define ECLIPTIX_OPAQUE_LOCAL
#endif
#ifdef __cplusplus
    #define ECLIPTIX_OPAQUE_EXTERN_C extern "C"
    #define ECLIPTIX_OPAQUE_EXTERN_C_BEGIN extern "C" {
    #define ECLIPTIX_OPAQUE_EXTERN_C_END }
#else
    #define ECLIPTIX_OPAQUE_EXTERN_C
    #define ECLIPTIX_OPAQUE_EXTERN_C_BEGIN
    #define ECLIPTIX_OPAQUE_EXTERN_C_END
#endif
#define ECLIPTIX_OPAQUE_EXPORT ECLIPTIX_OPAQUE_EXTERN_C ECLIPTIX_OPAQUE_API
#define ECLIPTIX_OPAQUE_DEPRECATED(msg) \
    [[deprecated(msg)]]
#define ECLIPTIX_OPAQUE_NODISCARD \
    [[nodiscard]]
#define ECLIPTIX_OPAQUE_NORETURN \
    [[noreturn]]
#ifdef NDEBUG
    #define ECLIPTIX_OPAQUE_ASSERT(condition) ((void)0)
#else
    #include <cassert>
    #define ECLIPTIX_OPAQUE_ASSERT(condition) assert(condition)
#endif
namespace ecliptix::security::opaque {
enum class ApiVersion : uint32_t {
    Version_1_0 = 0x00010000,
    Current = Version_1_0
};
constexpr const char* GetVersionString() noexcept {
    return "1.0.0";
}
constexpr ApiVersion GetApiVersion() noexcept {
    return ApiVersion::Current;
}
}