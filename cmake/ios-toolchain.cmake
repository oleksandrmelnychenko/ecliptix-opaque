set(CMAKE_SYSTEM_NAME iOS)
set(CMAKE_SYSTEM_VERSION 17.0)
set(IOS TRUE)

if(NOT DEFINED PLATFORM)
    set(PLATFORM "OS64")
endif()

if(PLATFORM STREQUAL "OS64")
    set(CMAKE_OSX_SYSROOT iphoneos)
    set(CMAKE_OSX_ARCHITECTURES arm64)
    set(IOS_PLATFORM_LOCATION "iPhoneOS.platform")
    set(CMAKE_XCODE_EFFECTIVE_PLATFORMS "-iphoneos")

elseif(PLATFORM STREQUAL "SIMULATOR64")
    set(CMAKE_OSX_SYSROOT iphonesimulator)
    set(CMAKE_OSX_ARCHITECTURES "arm64;x86_64")
    set(IOS_PLATFORM_LOCATION "iPhoneSimulator.platform")
    set(CMAKE_XCODE_EFFECTIVE_PLATFORMS "-iphonesimulator")

elseif(PLATFORM STREQUAL "SIMULATORARM64")
    set(CMAKE_OSX_SYSROOT iphonesimulator)
    set(CMAKE_OSX_ARCHITECTURES arm64)
    set(IOS_PLATFORM_LOCATION "iPhoneSimulator.platform")
    set(CMAKE_XCODE_EFFECTIVE_PLATFORMS "-iphonesimulator")

else()
    message(FATAL_ERROR "Invalid PLATFORM: ${PLATFORM}. Must be OS64, SIMULATOR64, or SIMULATORARM64")
endif()

set(CMAKE_OSX_DEPLOYMENT_TARGET "17.0" CACHE STRING "Minimum iOS deployment version")

set(CMAKE_C_COMPILER_WORKS TRUE)
set(CMAKE_CXX_COMPILER_WORKS TRUE)

# CMAKE_SYSTEM_PROCESSOR must be a single value, not a list
# For multi-arch builds, use the first architecture
list(GET CMAKE_OSX_ARCHITECTURES 0 _FIRST_ARCH)
set(CMAKE_SYSTEM_PROCESSOR ${_FIRST_ARCH})

set(CMAKE_CXX_FLAGS_INIT "-stdlib=libc++")

set(CMAKE_C_COMPILER_WORKS 1)
set(CMAKE_CXX_COMPILER_WORKS 1)

set(CMAKE_INSTALL_NAME_DIR "@rpath")
set(CMAKE_BUILD_WITH_INSTALL_NAME_DIR TRUE)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fembed-bitcode-marker")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fembed-bitcode-marker")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fobjc-arc")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fobjc-arc")

set(CMAKE_SKIP_RPATH TRUE)
set(CMAKE_SKIP_BUILD_RPATH TRUE)
set(CMAKE_SKIP_INSTALL_RPATH TRUE)

if(PLATFORM STREQUAL "OS64")
    set(IOS_ARCH_SUFFIX "ios-arm64")
elseif(PLATFORM STREQUAL "SIMULATOR64")
    set(IOS_ARCH_SUFFIX "ios-arm64_x86_64-simulator")
elseif(PLATFORM STREQUAL "SIMULATORARM64")
    set(IOS_ARCH_SUFFIX "ios-arm64-simulator")
endif()

set(BUILD_SHARED_LIBS OFF CACHE BOOL "Build shared libraries" FORCE)

message(STATUS "=== iOS Toolchain Configuration ===")
message(STATUS "Platform: ${PLATFORM}")
message(STATUS "SDK: ${CMAKE_OSX_SYSROOT}")
message(STATUS "Architectures: ${CMAKE_OSX_ARCHITECTURES}")
message(STATUS "Min iOS Version: ${CMAKE_OSX_DEPLOYMENT_TARGET}")
message(STATUS "Architecture Suffix: ${IOS_ARCH_SUFFIX}")
message(STATUS "===================================")
