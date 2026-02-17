cmake_minimum_required(VERSION 3.20)
project(opaque_benchmarks LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Build in Release for meaningful benchmarks
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# Find dependencies
find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED libsodium)

# Try pkg-config for liboqs, then manual find
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
    else()
        message(FATAL_ERROR "liboqs not found")
    endif()
endif()

# OpenSSL (optional, needed by liboqs on some platforms)
if(APPLE)
    set(OPENSSL_ROOT_DIR "/opt/homebrew/opt/openssl@3")
endif()
find_package(OpenSSL QUIET)

# Project root (parent of benchmarks/)
set(OPAQUE_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/..)

# Core library sources
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

# Static library for benchmarks (no exports needed)
add_library(opaque_core_static STATIC ${CORE_SOURCES})
target_include_directories(opaque_core_static PUBLIC
    ${OPAQUE_ROOT}/include
    ${SODIUM_INCLUDE_DIRS}
    ${OQS_INCLUDE_DIRS}
)
target_link_libraries(opaque_core_static
    ${SODIUM_LIBRARIES}
    ${OQS_LIBRARIES}
)
target_link_directories(opaque_core_static PUBLIC
    ${SODIUM_LIBRARY_DIRS}
    ${OQS_LIBRARY_DIRS}
)
if(OPENSSL_FOUND)
    target_link_libraries(opaque_core_static OpenSSL::SSL OpenSSL::Crypto)
endif()
# Suppress warnings in benchmarks (we want -O2, not -Werror)
target_compile_options(opaque_core_static PRIVATE -w)

# Helper function to add benchmark executables
function(add_bench NAME SOURCE)
    add_executable(${NAME} ${SOURCE})
    target_include_directories(${NAME} PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${OPAQUE_ROOT}/include
    )
    target_link_libraries(${NAME} opaque_core_static)
    target_compile_options(${NAME} PRIVATE -O2 -w)
endfunction()

# Benchmark targets
add_bench(bench_micro       micro/bench_micro_primitives.cpp)
add_bench(bench_protocol    protocol/bench_protocol_phases.cpp)
add_bench(bench_throughput  throughput/bench_throughput.cpp)
add_bench(bench_overhead    overhead/bench_wire_overhead.cpp)

# Convenience target to run all benchmarks
add_custom_target(run_benchmarks
    COMMAND echo "\\n========== MICRO BENCHMARKS =========="
    COMMAND $<TARGET_FILE:bench_micro>
    COMMAND echo "\\n========== PROTOCOL PHASES =========="
    COMMAND $<TARGET_FILE:bench_protocol>
    COMMAND echo "\\n========== THROUGHPUT =========="
    COMMAND $<TARGET_FILE:bench_throughput>
    COMMAND echo "\\n========== WIRE OVERHEAD =========="
    COMMAND $<TARGET_FILE:bench_overhead>
    DEPENDS bench_micro bench_protocol bench_throughput bench_overhead
    COMMENT "Running all benchmarks..."
)
