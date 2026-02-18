cmake_minimum_required(VERSION 3.20)
project(opaque_test_vectors LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

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
    ${OPAQUE_ROOT}/src/interop/initiator_exports.cpp
    ${OPAQUE_ROOT}/src/interop/responder_exports.cpp
)

add_library(opaque_core_tv STATIC ${CORE_SOURCES})
target_include_directories(opaque_core_tv PUBLIC
    ${OPAQUE_ROOT}/include
    ${SODIUM_INCLUDE_DIRS}
    ${OQS_INCLUDE_DIRS})
target_link_libraries(opaque_core_tv ${SODIUM_LIBRARIES} ${OQS_LIBRARIES})
target_link_directories(opaque_core_tv PUBLIC ${SODIUM_LIBRARY_DIRS} ${OQS_LIBRARY_DIRS})
if(OPENSSL_FOUND)
    target_link_libraries(opaque_core_tv OpenSSL::SSL OpenSSL::Crypto)
endif()
target_compile_options(opaque_core_tv PRIVATE -w)

add_executable(generate_test_vectors generate_test_vectors.cpp)
target_include_directories(generate_test_vectors PRIVATE ${OPAQUE_ROOT}/include)
target_link_libraries(generate_test_vectors opaque_core_tv)
target_compile_options(generate_test_vectors PRIVATE -w)
