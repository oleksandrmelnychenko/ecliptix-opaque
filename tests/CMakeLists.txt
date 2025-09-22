find_package(Catch2 3 REQUIRED PATHS ${CMAKE_SOURCE_DIR}/extern/Catch2)

set(TEST_SOURCES_CORE
    unit/core/secure_memory_test.cpp
    unit/core/cryptographic_primitives_test.cpp
    unit/core/oprf_operations_test.cpp
    unit/core/envelope_cryptography_test.cpp
)

set(TEST_SOURCES_CLIENT
    unit/client/client_registration_test.cpp
    unit/client/client_authentication_test.cpp
    unit/client/client_key_management_test.cpp
)

set(TEST_SOURCES_SERVER
    unit/server/server_registration_test.cpp
    unit/server/server_authentication_test.cpp
    unit/server/credential_store_test.cpp
)

set(TEST_SOURCES_INTEGRATION
    integration/full_protocol_flow_test.cpp
    integration/interoperability_test.cpp
    integration/security_validation_test.cpp
)

add_executable(ecliptix_opaque_core_tests
    ${TEST_SOURCES_CORE}
    ${CORE_SOURCES}
)

target_include_directories(ecliptix_opaque_core_tests PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
    ${SODIUM_INCLUDE_DIRS}
)

target_link_libraries(ecliptix_opaque_core_tests PRIVATE
    Catch2::Catch2WithMain
    ${SODIUM_LIBRARIES}
)

target_compile_definitions(ecliptix_opaque_core_tests PRIVATE
    ECLIPTIX_OPAQUE_EXPORTS
    ECLIPTIX_TESTING_MODE
)

if(BUILD_CLIENT)
    add_executable(ecliptix_opaque_client_tests
        ${TEST_SOURCES_CLIENT}
        ${CORE_SOURCES}
        ${CMAKE_SOURCE_DIR}/src/client/registration.cpp
        ${CMAKE_SOURCE_DIR}/src/client/authentication.cpp
        ${CMAKE_SOURCE_DIR}/src/client/key_management.cpp
    )

    target_include_directories(ecliptix_opaque_client_tests PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/src
        ${SODIUM_INCLUDE_DIRS}
    )

    target_link_libraries(ecliptix_opaque_client_tests PRIVATE
        Catch2::Catch2WithMain
        ${SODIUM_LIBRARIES}
    )

    target_compile_definitions(ecliptix_opaque_client_tests PRIVATE
        ECLIPTIX_OPAQUE_EXPORTS
        ECLIPTIX_OPAQUE_CLIENT_BUILD
        ECLIPTIX_TESTING_MODE
    )
endif()

if(BUILD_SERVER)
    add_executable(ecliptix_opaque_server_tests
        ${TEST_SOURCES_SERVER}
        ${CORE_SOURCES}
        ${CMAKE_SOURCE_DIR}/src/server/registration.cpp
        ${CMAKE_SOURCE_DIR}/src/server/authentication.cpp
        ${CMAKE_SOURCE_DIR}/src/server/credential_store.cpp
    )

    target_include_directories(ecliptix_opaque_server_tests PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/src
        ${SODIUM_INCLUDE_DIRS}
    )

    target_link_libraries(ecliptix_opaque_server_tests PRIVATE
        Catch2::Catch2WithMain
        ${SODIUM_LIBRARIES}
    )

    target_compile_definitions(ecliptix_opaque_server_tests PRIVATE
        ECLIPTIX_OPAQUE_EXPORTS
        ECLIPTIX_OPAQUE_SERVER_BUILD
        ECLIPTIX_TESTING_MODE
    )
endif()

if(BUILD_CLIENT AND BUILD_SERVER)
    add_executable(ecliptix_opaque_integration_tests
        ${TEST_SOURCES_INTEGRATION}
        ${CORE_SOURCES}
        ${CMAKE_SOURCE_DIR}/src/client/registration.cpp
        ${CMAKE_SOURCE_DIR}/src/client/authentication.cpp
        ${CMAKE_SOURCE_DIR}/src/client/key_management.cpp
        ${CMAKE_SOURCE_DIR}/src/server/registration.cpp
        ${CMAKE_SOURCE_DIR}/src/server/authentication.cpp
        ${CMAKE_SOURCE_DIR}/src/server/credential_store.cpp
    )

    target_include_directories(ecliptix_opaque_integration_tests PRIVATE
        ${CMAKE_SOURCE_DIR}/include
        ${CMAKE_SOURCE_DIR}/src
        ${SODIUM_INCLUDE_DIRS}
    )

    target_link_libraries(ecliptix_opaque_integration_tests PRIVATE
        Catch2::Catch2WithMain
        ${SODIUM_LIBRARIES}
    )

    target_compile_definitions(ecliptix_opaque_integration_tests PRIVATE
        ECLIPTIX_OPAQUE_EXPORTS
        ECLIPTIX_OPAQUE_CLIENT_BUILD
        ECLIPTIX_OPAQUE_SERVER_BUILD
        ECLIPTIX_TESTING_MODE
    )
endif()

include(CTest)

add_test(NAME CoreTests COMMAND ecliptix_opaque_core_tests)

if(BUILD_CLIENT)
    add_test(NAME ClientTests COMMAND ecliptix_opaque_client_tests)
endif()

if(BUILD_SERVER)
    add_test(NAME ServerTests COMMAND ecliptix_opaque_server_tests)
endif()

if(BUILD_CLIENT AND BUILD_SERVER)
    add_test(NAME IntegrationTests COMMAND ecliptix_opaque_integration_tests)
endif()