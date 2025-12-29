cmake_minimum_required(VERSION 3.15)
project(opaque_client)

set(CLIENT_SOURCES
    ${CMAKE_SOURCE_DIR}/src/core/memory.cpp
    ${CMAKE_SOURCE_DIR}/src/core/oprf.cpp
    ${CMAKE_SOURCE_DIR}/src/core/crypto.cpp
    ${CMAKE_SOURCE_DIR}/src/core/envelope.cpp
    ${CMAKE_SOURCE_DIR}/src/initiator/registration.cpp
    ${CMAKE_SOURCE_DIR}/src/initiator/authentication.cpp
    ${CMAKE_SOURCE_DIR}/src/initiator/key_management.cpp
    ${CMAKE_SOURCE_DIR}/src/interop/initiator_exports.cpp
    ${CMAKE_SOURCE_DIR}/include/opaque/export.h
    ${CMAKE_SOURCE_DIR}/include/opaque/version.h
    ${CMAKE_SOURCE_DIR}/include/opaque/opaque.h
    ${CMAKE_SOURCE_DIR}/include/opaque/initiator.h
    ${CMAKE_SOURCE_DIR}/include/opaque/hardcoded_keys.h
)
# Use STATIC for iOS, otherwise respect BUILD_SHARED_LIBS
if(IOS OR CMAKE_SYSTEM_NAME STREQUAL "iOS")
    add_library(opaque_client STATIC ${CLIENT_SOURCES})
else()
    add_library(opaque_client ${CLIENT_SOURCES})
endif()
set_target_properties(opaque_client PROPERTIES
    OUTPUT_NAME "opaque_client"
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
)
set(CLIENT_TARGET opaque_client)
target_include_directories(${CLIENT_TARGET} PUBLIC
    ${CMAKE_SOURCE_DIR}/include
    ${SODIUM_INCLUDE_DIRS}
)

# Link libsodium - handle vcpkg target vs pkg-config variables
if(TARGET unofficial-sodium::sodium)
    # vcpkg provides a target
    target_link_libraries(${CLIENT_TARGET} unofficial-sodium::sodium)
elseif(BUILD_STATIC_SODIUM)
    # For static linking, find libsodium.a
    # Construct path directly from pkg-config library dirs
    if(SODIUM_LIBRARY_DIRS)
        set(SODIUM_STATIC_LIB "${SODIUM_LIBRARY_DIRS}/libsodium.a")
        if(NOT EXISTS "${SODIUM_STATIC_LIB}")
            set(SODIUM_STATIC_LIB "")
        endif()
    endif()

    # Try fallback locations if not found
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

if(WIN32)
    target_compile_definitions(opaque_client PRIVATE
            BUILDING_DLL
            ECLIPTIX_OPAQUE_EXPORTS
    )
    target_compile_options(${CLIENT_TARGET} PRIVATE /wd4251)
endif()

target_compile_definitions(${CLIENT_TARGET} PRIVATE
    OPAQUE_CLIENT_BUILD
)

# Apply LLVM obfuscation if enabled
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
install(DIRECTORY ${CMAKE_SOURCE_DIR}/include/opaque
    DESTINATION include
    FILES_MATCHING PATTERN "*.h"
)