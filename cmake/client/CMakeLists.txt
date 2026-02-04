cmake_minimum_required(VERSION 3.15)
project(opaque_client)

set(CLIENT_SOURCES
    ${OPAQUE_ROOT_DIR}/src/core/memory.cpp
    ${OPAQUE_ROOT_DIR}/src/core/oprf.cpp
    ${OPAQUE_ROOT_DIR}/src/core/crypto.cpp
    ${OPAQUE_ROOT_DIR}/src/core/envelope.cpp
    ${OPAQUE_ROOT_DIR}/src/core/pq_kem.cpp
    ${OPAQUE_ROOT_DIR}/src/core/protocol.cpp
    ${OPAQUE_ROOT_DIR}/src/initiator/registration.cpp
    ${OPAQUE_ROOT_DIR}/src/initiator/authentication.cpp
    ${OPAQUE_ROOT_DIR}/src/initiator/key_management.cpp
    ${OPAQUE_ROOT_DIR}/src/interop/initiator_exports.cpp
    ${OPAQUE_ROOT_DIR}/include/opaque/export.h
    ${OPAQUE_ROOT_DIR}/include/opaque/version.h
    ${OPAQUE_ROOT_DIR}/include/opaque/opaque.h
    ${OPAQUE_ROOT_DIR}/include/opaque/initiator.h
    ${OPAQUE_ROOT_DIR}/include/opaque/pq.h
    ${OPAQUE_ROOT_DIR}/include/opaque/hardcoded_keys.h
)

# Add JNI sources for Android builds
if(BUILD_ANDROID_JNI AND ANDROID)
    list(APPEND CLIENT_SOURCES
        ${OPAQUE_ROOT_DIR}/src/interop/jni/OpaqueJni.cpp
    )
    message(STATUS "Building with JNI bindings for Android")
endif()
if(IOS OR CMAKE_SYSTEM_NAME STREQUAL "iOS")
    add_library(opaque_client STATIC ${CLIENT_SOURCES})
else()
    add_library(opaque_client ${CLIENT_SOURCES})
endif()
set_target_properties(opaque_client PROPERTIES
    OUTPUT_NAME "eop.agent"
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
)
set(CLIENT_TARGET opaque_client)
target_include_directories(${CLIENT_TARGET} PUBLIC
    ${OPAQUE_ROOT_DIR}/include
    ${SODIUM_INCLUDE_DIRS}
    ${OQS_INCLUDE_DIRS}
)

if(TARGET unofficial-sodium::sodium)
    target_link_libraries(${CLIENT_TARGET} unofficial-sodium::sodium)
elseif(BUILD_STATIC_SODIUM)
    if(SODIUM_LIBRARY_DIRS)
        set(SODIUM_STATIC_LIB "${SODIUM_LIBRARY_DIRS}/libsodium.a")
        if(NOT EXISTS "${SODIUM_STATIC_LIB}")
            set(SODIUM_STATIC_LIB "")
        endif()
    endif()

    if(NOT SODIUM_STATIC_LIB)
        set(SEARCH_PATHS
            /opt/homebrew/opt/libsodium/lib
            /opt/homebrew/lib
            /usr/local/opt/libsodium/lib
            /usr/local/lib
        )
        foreach(search_path ${SEARCH_PATHS})
            if(EXISTS "${search_path}/libsodium.a")
                set(SODIUM_STATIC_LIB "${search_path}/libsodium.a")
                break()
            endif()
        endforeach()
    endif()

    if(SODIUM_STATIC_LIB AND EXISTS "${SODIUM_STATIC_LIB}")
        message(STATUS "Found static libsodium: ${SODIUM_STATIC_LIB}")
        target_link_libraries(${CLIENT_TARGET} ${SODIUM_STATIC_LIB})
    else()
        message(STATUS "SODIUM_LIBRARY_DIRS: ${SODIUM_LIBRARY_DIRS}")
        message(FATAL_ERROR "Static libsodium not found. Searched in ${SODIUM_LIBRARY_DIRS}, /opt/homebrew/opt/libsodium/lib")
    endif()
else()
    target_link_libraries(${CLIENT_TARGET} ${SODIUM_LIBRARIES})
    target_link_directories(${CLIENT_TARGET} PRIVATE ${SODIUM_LIBRARY_DIRS})
    if(NOT SODIUM_LIBRARIES)
        target_link_libraries(${CLIENT_TARGET} sodium)
    endif()
endif()

if(TARGET OQS::oqs)
    target_link_libraries(${CLIENT_TARGET} OQS::oqs)
else()
    target_link_libraries(${CLIENT_TARGET} ${OQS_LIBRARIES})
    target_link_directories(${CLIENT_TARGET} PRIVATE ${OQS_LIBRARY_DIRS})
    if(NOT OQS_LIBRARIES)
        target_link_libraries(${CLIENT_TARGET} oqs)
    endif()
endif()

# OpenSSL is optional - liboqs can be built without it
find_package(OpenSSL QUIET)
if(OPENSSL_FOUND)
    target_link_libraries(${CLIENT_TARGET} OpenSSL::SSL OpenSSL::Crypto)
elseif(NOT MINGW)
    # Only require OpenSSL on non-MinGW builds
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(OPENSSL QUIET openssl)
    if(OPENSSL_FOUND)
        target_link_libraries(${CLIENT_TARGET} ${OPENSSL_LIBRARIES})
        target_link_directories(${CLIENT_TARGET} PRIVATE ${OPENSSL_LIBRARY_DIRS})
    endif()
endif()

if(WIN32)
    set_target_properties(opaque_client PROPERTIES PREFIX "")
    target_compile_definitions(opaque_client PRIVATE
            BUILDING_DLL
            ECLIPTIX_OPAQUE_EXPORTS
    )
    if(MSVC)
        target_compile_options(${CLIENT_TARGET} PRIVATE /wd4251)
    endif()
    if(MINGW)
        target_link_options(${CLIENT_TARGET} PRIVATE
            -static-libgcc
            -static-libstdc++
            -Wl,-Bstatic -lstdc++ -lpthread -Wl,-Bdynamic
        )
    endif()
endif()

target_compile_definitions(${CLIENT_TARGET} PRIVATE
    OPAQUE_CLIENT_BUILD
)

if(ENABLE_OBFUSCATION)
    target_enable_obfuscation(${CLIENT_TARGET})
endif()
if(BUILD_DOTNET_INTEROP AND TARGET opaque_client)
    if(WIN32)
        set_target_properties(opaque_client PROPERTIES
            SUFFIX ".dll"
        )
    elseif(APPLE)
        set_target_properties(opaque_client PROPERTIES
            SUFFIX ".dylib"
        )
    else()
        set_target_properties(opaque_client PROPERTIES
            SUFFIX ".so"
        )
    endif()
endif()
install(TARGETS ${CLIENT_TARGET}
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
)
install(DIRECTORY ${OPAQUE_ROOT_DIR}/include/opaque
    DESTINATION include
    FILES_MATCHING PATTERN "*.h"
)
