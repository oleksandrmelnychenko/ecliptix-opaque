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

# Test for protocol integration
add_executable(test_opaque_protocol test_opaque_protocol.cpp)

target_include_directories(test_opaque_protocol PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${SODIUM_INCLUDE_DIRS}
)

target_link_libraries(test_opaque_protocol
    Catch2::Catch2WithMain
    ${SODIUM_LIBRARIES}
)

target_compile_definitions(test_opaque_protocol PRIVATE
    OPAQUE_KSF_OPSLIMIT=crypto_pwhash_OPSLIMIT_INTERACTIVE
    OPAQUE_KSF_MEMLIMIT=crypto_pwhash_MEMLIMIT_INTERACTIVE
)

# Link against the core library sources directly for testing
target_sources(test_opaque_protocol PRIVATE
    ${CMAKE_SOURCE_DIR}/src/core/memory.cpp
    ${CMAKE_SOURCE_DIR}/src/core/oprf.cpp
    ${CMAKE_SOURCE_DIR}/src/core/crypto.cpp
    ${CMAKE_SOURCE_DIR}/src/core/envelope.cpp
    ${CMAKE_SOURCE_DIR}/src/initiator/registration.cpp
    ${CMAKE_SOURCE_DIR}/src/initiator/authentication.cpp
    ${CMAKE_SOURCE_DIR}/src/initiator/key_management.cpp
    ${CMAKE_SOURCE_DIR}/src/responder/registration.cpp
    ${CMAKE_SOURCE_DIR}/src/responder/authentication.cpp
    ${CMAKE_SOURCE_DIR}/src/responder/server.cpp
    ${CMAKE_SOURCE_DIR}/src/interop/initiator_exports.cpp
    ${CMAKE_SOURCE_DIR}/src/interop/responder_exports.cpp
)

target_link_directories(test_opaque_protocol PRIVATE ${SODIUM_LIBRARY_DIRS})

if(NOT SODIUM_LIBRARIES)
    target_link_libraries(test_opaque_protocol sodium)
endif()

# Register test with CTest
add_test(NAME OpaqueProtocolTest COMMAND test_opaque_protocol)

# Set test properties
set_tests_properties(OpaqueProtocolTest PROPERTIES
    LABELS "unit;protocol;security"
    TIMEOUT 30
)
