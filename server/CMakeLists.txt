cmake_minimum_required(VERSION 3.20)
project(Ecliptix_OPAQUE_Server VERSION 1.0.1 LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
option(BUILD_SHARED_LIBS "Build shared libraries" ON)
option(ENABLE_HARDENING "Enable security hardening flags" ON)
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
include_directories(${CMAKE_SOURCE_DIR}/../include)
include_directories(${SODIUM_INCLUDE_DIRS})
set(SERVER_SOURCES
    ${CMAKE_SOURCE_DIR}/../src/core/memory.cpp
    ${CMAKE_SOURCE_DIR}/../src/core/oprf.cpp
    ${CMAKE_SOURCE_DIR}/../src/core/crypto.cpp
    ${CMAKE_SOURCE_DIR}/../src/core/envelope.cpp
    ${CMAKE_SOURCE_DIR}/../src/server/authentication.cpp
    ${CMAKE_SOURCE_DIR}/../src/server/credential_store.cpp
    ${CMAKE_SOURCE_DIR}/../src/server/registration.cpp
    ${CMAKE_SOURCE_DIR}/../src/interop/server_exports.cpp
)
add_library(opaque_server ${SERVER_SOURCES})
set_target_properties(opaque_server PROPERTIES
    OUTPUT_NAME "opaque_server"
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
)
target_include_directories(opaque_server PUBLIC
    ${CMAKE_SOURCE_DIR}/../include
    ${SODIUM_INCLUDE_DIRS}
)
if(BUILD_STATIC_SODIUM)
    find_library(SODIUM_STATIC_LIB libsodium.a PATHS ${SODIUM_LIBRARY_DIRS} /opt/homebrew/lib /usr/local/lib)
    if(SODIUM_STATIC_LIB)
        target_link_libraries(opaque_server ${SODIUM_STATIC_LIB})
        message(STATUS "Linking statically with libsodium: ${SODIUM_STATIC_LIB}")
    else()
        message(WARNING "Static libsodium not found, falling back to dynamic linking")
        target_link_libraries(opaque_server ${SODIUM_LIBRARIES})
    endif()
else()
    target_link_libraries(opaque_server ${SODIUM_LIBRARIES})
endif()
target_link_directories(opaque_server PRIVATE ${SODIUM_LIBRARY_DIRS})
if(NOT SODIUM_LIBRARIES AND NOT BUILD_STATIC_SODIUM)
    target_link_libraries(opaque_server sodium)
endif()
target_compile_definitions(opaque_server PRIVATE
    OPAQUE_SERVER_BUILD
)
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
install(TARGETS opaque_server
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
)
install(FILES
    ${CMAKE_SOURCE_DIR}/../include/opaque/opaque.h
    ${CMAKE_SOURCE_DIR}/../include/opaque/server.h
    DESTINATION include/opaque
)
message(STATUS "=== Ecliptix OPAQUE Server Library ===")
message(STATUS "Version: ${PROJECT_VERSION}")
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "C++ Standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "Shared libs: ${BUILD_SHARED_LIBS}")
message(STATUS "Hardening: ${ENABLE_HARDENING}")
message(STATUS "Static sodium: ${BUILD_STATIC_SODIUM}")
message(STATUS "libsodium: ${SODIUM_VERSION}")