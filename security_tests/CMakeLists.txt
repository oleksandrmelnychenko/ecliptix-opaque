cmake_minimum_required(VERSION 3.20)
project(opaque_security_tests LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Dependencies
find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED libsodium)

pkg_check_modules(OQS QUIET liboqs)
if(NOT OQS_FOUND)
    find_library(OQS_LIBRARY NAMES oqs liboqs
        HINTS /opt/homebrew/lib /usr/local/lib /usr/lib)
    find_path(OQS_INCLUDE_DIR NAMES oqs/oqs.h
        HINTS /opt/homebrew/include /usr/local/include /usr/include)
    if(OQS_LIBRARY AND OQS_INCLUDE_DIR)
        set(OQS_FOUND TRUE)
        set(OQS_LIBRARIES ${OQS_LIBRARY})
        set(OQS_INCLUDE_DIRS ${OQS_INCLUDE_DIR})
    endif()
endif()

if(APPLE)
    set(OPENSSL_ROOT_DIR "/opt/homebrew/opt/openssl@3")
endif()
find_package(OpenSSL QUIET)

# Catch2
find_package(Catch2 3 QUIET)
if(NOT Catch2_FOUND)
    include(FetchContent)
    FetchContent_Declare(Catch2
        GIT_REPOSITORY https://github.com/catchorg/Catch2.git
        GIT_TAG v3.4.0
        GIT_SHALLOW TRUE)
    FetchContent_MakeAvailable(Catch2)
    if(TARGET Catch2)
        target_compile_options(Catch2 PRIVATE -Wno-sign-conversion -Wno-conversion)
    endif()
endif()

set(OPAQUE_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/..)

set(CORE_SOURCES
    ${OPAQUE_ROOT}/src/core/oprf.cpp
    ${OPAQUE_ROOT}/src/core/envelope.cpp
    ${OPAQUE_ROOT}/src/core/memory.cpp
    ${OPAQUE_ROOT}/src/core/crypto.cpp
    ${OPAQUE_ROOT}/src/core/pq_kem.cpp
    ${OPAQUE_ROOT}/src/core/protocol.cpp
    ${OPAQUE_ROOT}/src/initiator/registration.cpp
    ${OPAQUE_ROOT}/src/initiator/authentication.cpp
    ${OPAQUE_ROOT}/src/initiator/key_management.cpp
    ${OPAQUE_ROOT}/src/responder/registration.cpp
    ${OPAQUE_ROOT}/src/responder/authentication.cpp
    ${OPAQUE_ROOT}/src/responder/server.cpp
)

add_library(opaque_core_st STATIC ${CORE_SOURCES})
target_include_directories(opaque_core_st PUBLIC
    ${OPAQUE_ROOT}/include
    ${SODIUM_INCLUDE_DIRS}
    ${OQS_INCLUDE_DIRS})
target_link_libraries(opaque_core_st ${SODIUM_LIBRARIES} ${OQS_LIBRARIES})
target_link_directories(opaque_core_st PUBLIC ${SODIUM_LIBRARY_DIRS} ${OQS_LIBRARY_DIRS})
if(OPENSSL_FOUND)
    target_link_libraries(opaque_core_st OpenSSL::SSL OpenSSL::Crypto)
endif()
target_compile_options(opaque_core_st PRIVATE -w)

# Security test executable
add_executable(security_tests
    test_session_key_independence.cpp
    test_security_properties.cpp
    test_cross_session_isolation.cpp
    test_kem_robustness.cpp
)
target_include_directories(security_tests PRIVATE ${OPAQUE_ROOT}/include)
target_link_libraries(security_tests opaque_core_st Catch2::Catch2WithMain)
target_compile_options(security_tests PRIVATE -w)

include(CTest)
include(Catch)
catch_discover_tests(security_tests)
