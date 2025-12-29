cmake_minimum_required(VERSION 3.15)
project(opaque_client)

set(SERVER_SOURCES
    ${CMAKE_SOURCE_DIR}/src/core/memory.cpp
    ${CMAKE_SOURCE_DIR}/src/core/oprf.cpp
    ${CMAKE_SOURCE_DIR}/src/core/crypto.cpp
    ${CMAKE_SOURCE_DIR}/src/core/envelope.cpp
    ${CMAKE_SOURCE_DIR}/src/responder/registration.cpp
    ${CMAKE_SOURCE_DIR}/src/responder/authentication.cpp
    ${CMAKE_SOURCE_DIR}/src/responder/server.cpp
    ${CMAKE_SOURCE_DIR}/src/interop/responder_exports.cpp
    ${CMAKE_SOURCE_DIR}/include/opaque/export.h
    ${CMAKE_SOURCE_DIR}/include/opaque/version.h
    ${CMAKE_SOURCE_DIR}/include/opaque/opaque.h
    ${CMAKE_SOURCE_DIR}/include/opaque/responder.h
    ${CMAKE_SOURCE_DIR}/include/opaque/hardcoded_keys.h
)
add_library(opaque_server SHARED ${SERVER_SOURCES})
set_target_properties(opaque_server PROPERTIES
    OUTPUT_NAME "opaque_server"
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
)
set(SERVER_TARGET opaque_server)
target_include_directories(${SERVER_TARGET} PUBLIC
    ${CMAKE_SOURCE_DIR}/include
    ${SODIUM_INCLUDE_DIRS}
)

# Link libsodium - handle vcpkg target vs pkg-config variables
if(TARGET unofficial-sodium::sodium)
    # vcpkg provides a target
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

if(WIN32)
    target_compile_definitions(opaque_server PRIVATE
            BUILDING_DLL
            ECLIPTIX_OPAQUE_EXPORTS
    )
    if(MSVC)
        target_compile_options(${SERVER_TARGET} PRIVATE /wd4251)
    endif()
endif()

target_compile_definitions(${SERVER_TARGET} PRIVATE
    OPAQUE_SERVER_BUILD
)

# Apply LLVM obfuscation if enabled
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
install(DIRECTORY ${CMAKE_SOURCE_DIR}/include/opaque
    DESTINATION include
    FILES_MATCHING PATTERN "*.h"
)