cmake_minimum_required(VERSION 3.15)
project(opaque_client)

set(SERVER_SOURCES
    ${OPAQUE_ROOT_DIR}/src/core/memory.cpp
    ${OPAQUE_ROOT_DIR}/src/core/oprf.cpp
    ${OPAQUE_ROOT_DIR}/src/core/crypto.cpp
    ${OPAQUE_ROOT_DIR}/src/core/envelope.cpp
    ${OPAQUE_ROOT_DIR}/src/core/pq_kem.cpp
    ${OPAQUE_ROOT_DIR}/src/core/protocol.cpp
    ${OPAQUE_ROOT_DIR}/src/responder/registration.cpp
    ${OPAQUE_ROOT_DIR}/src/responder/authentication.cpp
    ${OPAQUE_ROOT_DIR}/src/responder/server.cpp
    ${OPAQUE_ROOT_DIR}/src/interop/responder_exports.cpp
    ${OPAQUE_ROOT_DIR}/include/opaque/export.h
    ${OPAQUE_ROOT_DIR}/include/opaque/version.h
    ${OPAQUE_ROOT_DIR}/include/opaque/opaque.h
    ${OPAQUE_ROOT_DIR}/include/opaque/responder.h
    ${OPAQUE_ROOT_DIR}/include/opaque/pq.h
    ${OPAQUE_ROOT_DIR}/include/opaque/hardcoded_keys.h
)
add_library(opaque_server SHARED ${SERVER_SOURCES})
set_target_properties(opaque_server PROPERTIES
    OUTPUT_NAME "eop.relay"
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
)
set(SERVER_TARGET opaque_server)
target_include_directories(${SERVER_TARGET} PUBLIC
    ${OPAQUE_ROOT_DIR}/include
    ${SODIUM_INCLUDE_DIRS}
    ${OQS_INCLUDE_DIRS}
)

if(TARGET unofficial-sodium::sodium)
    target_link_libraries(${SERVER_TARGET} unofficial-sodium::sodium)
elseif(BUILD_STATIC_SODIUM)
    find_library(SODIUM_STATIC_LIB NAMES libsodium.a PATHS ${SODIUM_LIBRARY_DIRS} REQUIRED)
    target_link_libraries(${SERVER_TARGET} ${SODIUM_STATIC_LIB})
else()
    target_link_libraries(${SERVER_TARGET} ${SODIUM_LIBRARIES})
    target_link_directories(${SERVER_TARGET} PRIVATE ${SODIUM_LIBRARY_DIRS})
    if(NOT SODIUM_LIBRARIES)
        target_link_libraries(${SERVER_TARGET} sodium)
    endif()
endif()

if(TARGET OQS::oqs)
    target_link_libraries(${SERVER_TARGET} OQS::oqs)
else()
    target_link_libraries(${SERVER_TARGET} ${OQS_LIBRARIES})
    target_link_directories(${SERVER_TARGET} PRIVATE ${OQS_LIBRARY_DIRS})
    if(NOT OQS_LIBRARIES)
        target_link_libraries(${SERVER_TARGET} oqs)
    endif()
endif()

# OpenSSL is optional - liboqs can be built without it
find_package(OpenSSL QUIET)
if(OPENSSL_FOUND)
    target_link_libraries(${SERVER_TARGET} OpenSSL::SSL OpenSSL::Crypto)
elseif(NOT MINGW)
    # Only require OpenSSL on non-MinGW builds
    find_package(PkgConfig REQUIRED)
    pkg_check_modules(OPENSSL QUIET openssl)
    if(OPENSSL_FOUND)
        target_link_libraries(${SERVER_TARGET} ${OPENSSL_LIBRARIES})
        target_link_directories(${SERVER_TARGET} PRIVATE ${OPENSSL_LIBRARY_DIRS})
    endif()
endif()

if(WIN32)
    set_target_properties(opaque_server PROPERTIES PREFIX "")
    target_compile_definitions(opaque_server PRIVATE
            BUILDING_DLL
            ECLIPTIX_OPAQUE_EXPORTS
    )
    if(MSVC)
        target_compile_options(${SERVER_TARGET} PRIVATE /wd4251)
    endif()
    if(MINGW)
        target_link_options(${SERVER_TARGET} PRIVATE
            -static-libgcc
            -static-libstdc++
            -Wl,-Bstatic -lstdc++ -lpthread -Wl,-Bdynamic
        )
    endif()
endif()

target_compile_definitions(${SERVER_TARGET} PRIVATE
    OPAQUE_SERVER_BUILD
)

if(ENABLE_OBFUSCATION)
    target_enable_obfuscation(${SERVER_TARGET})
endif()

if(BUILD_DOTNET_INTEROP AND TARGET opaque_server)
    if(WIN32)
        set_target_properties(opaque_server PROPERTIES
            SUFFIX ".dll"
        )
    elseif(APPLE)
        set_target_properties(opaque_server PROPERTIES
            SUFFIX ".dylib"
        )
    else()
        set_target_properties(opaque_server PROPERTIES
            SUFFIX ".so"
        )
    endif()
endif()
install(TARGETS ${SERVER_TARGET}
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
)
install(DIRECTORY ${OPAQUE_ROOT_DIR}/include/opaque
    DESTINATION include
    FILES_MATCHING PATTERN "*.h"
)
