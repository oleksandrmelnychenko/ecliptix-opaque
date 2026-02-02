cmake_minimum_required(VERSION 3.20)
project(Ecliptix_Security_OPAQUE VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU")
    if(CMAKE_CXX_COMPILER_VERSION VERSION_LESS "13.0")
        message(WARNING "GCC version ${CMAKE_CXX_COMPILER_VERSION} may have incomplete C++23 support. GCC 13+ recommended.")
    endif()
elseif(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    if(CMAKE_CXX_COMPILER_VERSION VERSION_LESS "17.0")
        message(WARNING "Clang version ${CMAKE_CXX_COMPILER_VERSION} may have incomplete C++23 support. Clang 17+ recommended.")
    endif()
elseif(CMAKE_CXX_COMPILER_ID MATCHES "MSVC")
    if(CMAKE_CXX_COMPILER_VERSION VERSION_LESS "19.36")
        message(WARNING "MSVC version ${CMAKE_CXX_COMPILER_VERSION} may have incomplete C++23 support. MSVC 19.36+ recommended.")
    endif()
endif()
option(BUILD_CLIENT "Build client library" ON)
option(BUILD_SERVER "Build server library" ON)
option(BUILD_SHARED_LIBS "Build shared libraries" ON)
option(BUILD_DOTNET_INTEROP "Build .NET interop layer" ON)
option(ENABLE_HARDENING "Enable security hardening flags" ON)
option(BUILD_TESTS "Build unit tests" ON)
option(RUN_TESTS_BEFORE_BUILD "Run tests before building libraries" ON)
option(BUILD_STATIC_SODIUM "Link libsodium statically" OFF)
option(STATIC_MSVC_RUNTIME "Link MSVC runtime statically (Windows only)" OFF)
option(ENABLE_OBFUSCATION "Enable LLVM-based code obfuscation (requires Clang)" OFF)
option(BUILD_ANDROID_JNI "Build JNI bindings for Android" OFF)

if(MSVC AND STATIC_MSVC_RUNTIME)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    message(STATUS "Using static MSVC runtime (/MT)")
endif()
set(OBFUSCATION_LEVEL "standard" CACHE STRING "Obfuscation level: light, standard, aggressive")

include(${CMAKE_SOURCE_DIR}/cmake/LLVMObfuscator.cmake)

if(IOS OR CMAKE_SYSTEM_NAME STREQUAL "iOS")
    # For iOS, use pre-built dependencies passed via cmake args
    if(DEFINED SODIUM_LIBRARIES AND EXISTS "${SODIUM_LIBRARIES}")
        message(STATUS "Using pre-built libsodium for iOS: ${SODIUM_LIBRARIES}")
        set(SODIUM_FOUND TRUE)
    else()
        find_package(PkgConfig REQUIRED)
        pkg_check_modules(SODIUM REQUIRED libsodium)
        message(STATUS "Using libsodium from pkg-config for iOS")
    endif()
elseif(DEFINED ENV{VCPKG_ROOT})
    find_package(unofficial-sodium CONFIG REQUIRED)
    set(SODIUM_LIBRARIES unofficial-sodium::sodium)
    set(SODIUM_INCLUDE_DIRS "")
    set(SODIUM_LIBRARY_DIRS "")
else()
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(SODIUM REQUIRED libsodium)
endif()

if(IOS OR CMAKE_SYSTEM_NAME STREQUAL "iOS")
    # For iOS, use pre-built dependencies passed via cmake args
    if(DEFINED OQS_LIBRARIES AND EXISTS "${OQS_LIBRARIES}")
        message(STATUS "Using pre-built liboqs for iOS: ${OQS_LIBRARIES}")
        set(OQS_FOUND TRUE)
    else()
        find_package(PkgConfig REQUIRED)
        pkg_check_modules(OQS REQUIRED liboqs)
        message(STATUS "Using liboqs from pkg-config for iOS")
    endif()
elseif(DEFINED ENV{VCPKG_ROOT})
    find_package(liboqs CONFIG REQUIRED)
    set(OQS_LIBRARIES OQS::oqs)
    set(OQS_INCLUDE_DIRS "")
    set(OQS_LIBRARY_DIRS "")
else()
    # Try pkg-config first, then fall back to find_library
    find_package(PkgConfig QUIET)
    if(PKG_CONFIG_FOUND)
        pkg_check_modules(OQS QUIET liboqs)
    endif()

    if(NOT OQS_FOUND)
        # Fallback: find liboqs manually
        find_library(OQS_LIBRARY NAMES oqs liboqs
            HINTS
                /opt/homebrew/lib
                /usr/local/lib
                /usr/lib
                $ENV{HOME}/.local/lib
        )
        find_path(OQS_INCLUDE_DIR NAMES oqs/oqs.h
            HINTS
                /opt/homebrew/include
                /usr/local/include
                /usr/include
                $ENV{HOME}/.local/include
        )

        if(OQS_LIBRARY AND OQS_INCLUDE_DIR)
            set(OQS_FOUND TRUE)
            set(OQS_LIBRARIES ${OQS_LIBRARY})
            set(OQS_INCLUDE_DIRS ${OQS_INCLUDE_DIR})
            set(OQS_LIBRARY_DIRS "")
            message(STATUS "Found liboqs via find_library: ${OQS_LIBRARY}")
        else()
            message(FATAL_ERROR "liboqs not found. Install with: brew install liboqs (macOS) or apt install liboqs-dev (Linux)")
        endif()
    endif()
endif()
message(STATUS "liboqs found - ML-KEM-768 post-quantum security enabled")
if(WIN32)
    set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS OFF)
elseif(APPLE)
    set(CMAKE_MACOSX_RPATH ON)
    if(NOT IOS AND NOT CMAKE_SYSTEM_NAME STREQUAL "iOS")
        if(NOT CMAKE_OSX_DEPLOYMENT_TARGET)
            set(CMAKE_OSX_DEPLOYMENT_TARGET "10.15")
        endif()
    endif()
endif()
if(ENABLE_HARDENING)
    if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
        add_compile_options(
            -fstack-protector-strong
            -fPIC
            -D_FORTIFY_SOURCE=2
            -Wformat
            -Wformat-security
            -Wall
            -Wextra
            -Wpedantic
            -Werror
            -Wconversion
            -Wsign-conversion
            -Wnull-dereference
        )
        if(UNIX AND NOT APPLE)
            add_link_options(-Wl,-z,relro,-z,now)
        endif()
    elseif(MSVC)
        add_compile_options(/W4 /WX /GS /sdl)
        add_link_options(/DYNAMICBASE /NXCOMPAT)
    endif()
endif()
include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${SODIUM_INCLUDE_DIRS})
include_directories(${OQS_INCLUDE_DIRS})
set(CORE_SOURCES
    src/core/oprf.cpp
    src/core/envelope.cpp
    src/core/memory.cpp
    src/core/crypto.cpp
    src/core/pq_kem.cpp
    src/core/protocol.cpp
)
if(BUILD_TESTS)
    enable_testing()
    find_package(Catch2 3 QUIET)
    if(NOT Catch2_FOUND)
        include(FetchContent)
        FetchContent_Declare(
            Catch2
            GIT_REPOSITORY https://github.com/catchorg/Catch2.git
            GIT_TAG v3.4.0
            GIT_SHALLOW TRUE
        )
        FetchContent_MakeAvailable(Catch2)

        if(TARGET Catch2)
            target_compile_options(Catch2 PRIVATE -Wno-sign-conversion -Wno-conversion)
        endif()
    endif()
    add_subdirectory(tests)
endif()
if(BUILD_CLIENT)
    add_subdirectory(cmake/client)
endif()
if(BUILD_SERVER)
    add_subdirectory(cmake/server)
endif()
if(NOT BUILD_CLIENT AND NOT BUILD_SERVER)
    message(FATAL_ERROR "At least one of BUILD_CLIENT or BUILD_SERVER must be enabled")
endif()
