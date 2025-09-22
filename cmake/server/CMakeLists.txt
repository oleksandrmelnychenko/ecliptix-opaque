set(SERVER_SOURCES
    ${CMAKE_SOURCE_DIR}/src/core/oprf.cpp
    ${CMAKE_SOURCE_DIR}/src/core/envelope.cpp
    ${CMAKE_SOURCE_DIR}/src/core/memory.cpp
    ${CMAKE_SOURCE_DIR}/src/core/crypto.cpp
    ${CMAKE_SOURCE_DIR}/src/server/registration.cpp
    ${CMAKE_SOURCE_DIR}/src/server/authentication.cpp
    ${CMAKE_SOURCE_DIR}/src/server/credential_store.cpp
)

if(BUILD_DOTNET_INTEROP)
    list(APPEND SERVER_SOURCES ${CMAKE_SOURCE_DIR}/src/interop/server_exports.cpp)
    add_library(opaque_server SHARED ${SERVER_SOURCES})
    set_target_properties(opaque_server PROPERTIES
        OUTPUT_NAME "opaque_server"
        VERSION ${PROJECT_VERSION}
        SOVERSION ${PROJECT_VERSION_MAJOR}
    )
else()
    add_library(opaque_server_static STATIC ${SERVER_SOURCES})
    set_target_properties(opaque_server_static PROPERTIES
        OUTPUT_NAME "opaque_server"
    )
    target_compile_definitions(opaque_server_static PRIVATE OPAQUE_STATIC_LIB)
    set(SERVER_TARGET opaque_server_static)
endif()

if(TARGET opaque_server)
    set(SERVER_TARGET opaque_server)
endif()

target_include_directories(${SERVER_TARGET} PUBLIC
    ${CMAKE_SOURCE_DIR}/include
    ${SODIUM_INCLUDE_DIRS}
)

target_link_libraries(${SERVER_TARGET}
    ${SODIUM_LIBRARIES}
)

target_compile_definitions(${SERVER_TARGET} PRIVATE
    OPAQUE_SERVER_BUILD
)

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