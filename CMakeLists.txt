cmake_minimum_required(VERSION 3.20)
project(Ecliptix_Security_OPAQUE VERSION 1.0.0 LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
option(BUILD_CLIENT "Build client library" ON)
option(BUILD_SERVER "Build server library" ON)
option(BUILD_SHARED_LIBS "Build shared libraries" ON)
option(BUILD_DOTNET_INTEROP "Build .NET interop layer" ON)
option(ENABLE_HARDENING "Enable security hardening flags" ON)
option(BUILD_TESTS "Build unit tests" ON)
option(RUN_TESTS_BEFORE_BUILD "Run tests before building libraries" ON)
option(BUILD_STATIC_SODIUM "Link libsodium statically" OFF)
find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED libsodium)
if(WIN32)
    set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS OFF)
elseif(APPLE)
    set(CMAKE_MACOSX_RPATH ON)
    set(CMAKE_OSX_DEPLOYMENT_TARGET "10.15")
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
            -Werror
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
