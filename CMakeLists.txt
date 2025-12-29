cmake_minimum_required(VERSION 3.20)
project(Ecliptix_Security_OPAQUE VERSION 1.0.0 LANGUAGES CXX)

# Require C++23 for modern features (concepts, std::expected, etc.)
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Compiler version checks for C++23 support
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
option(ENABLE_OBFUSCATION "Enable LLVM-based code obfuscation (requires Clang)" OFF)
set(OBFUSCATION_LEVEL "standard" CACHE STRING "Obfuscation level: light, standard, aggressive")

# Include obfuscation module
include(${CMAKE_SOURCE_DIR}/cmake/LLVMObfuscator.cmake)

# Find libsodium - support both vcpkg (find_package) and pkg-config
# For iOS builds, always use pkg-config (brew)
if(IOS OR CMAKE_SYSTEM_NAME STREQUAL "iOS")
    # iOS build - use Homebrew's libsodium via pkg-config
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(SODIUM REQUIRED libsodium)
    message(STATUS "Using libsodium from pkg-config for iOS")
elseif(DEFINED ENV{VCPKG_ROOT})
    # Using vcpkg or another package manager that provides find_package
    find_package(unofficial-sodium CONFIG REQUIRED)
    set(SODIUM_LIBRARIES unofficial-sodium::sodium)
    set(SODIUM_INCLUDE_DIRS "")  # Handled by target
    set(SODIUM_LIBRARY_DIRS "")  # Handled by target
else()
    # Using system package manager (apt, brew, etc.)
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(SODIUM REQUIRED libsodium)
endif()
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
set(CORE_SOURCES
    src/core/oprf.cpp
    src/core/envelope.cpp
    src/core/memory.cpp
    src/core/crypto.cpp
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

        # Disable strict warnings for third-party Catch2 library
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
