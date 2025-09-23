#include <catch2/catch_test_macros.hpp>
#include "opaque/opaque.h"
#include "opaque/client.h"
#include "opaque/server.h"
#include <sodium.h>
#include <cstring>

extern "C" {
    // Client exports
    int opaque_client_create(const uint8_t* server_public_key, size_t key_length, void** handle);
    void opaque_client_destroy(void* handle);
    int opaque_client_state_create(void** handle);
    void opaque_client_state_destroy(void* handle);
    int opaque_client_create_registration_request(void* client_handle, const uint8_t* password, size_t password_length, void* state_handle, uint8_t* request_out, size_t request_length);
    int opaque_client_finalize_registration(void* client_handle, const uint8_t* response, size_t response_length, void* state_handle, uint8_t* record_out, size_t record_length);
    int opaque_client_generate_ke1(void* client_handle, const uint8_t* password, size_t password_length, void* state_handle, uint8_t* ke1_out, size_t ke1_length);
    int opaque_client_generate_ke3(void* client_handle, const uint8_t* ke2, size_t ke2_length, void* state_handle, uint8_t* ke3_out, size_t ke3_length);
    int opaque_client_finish(void* client_handle, void* state_handle, uint8_t* session_key_out, size_t session_key_length);

    // Server exports
    struct opaque_server_handle_t;
    struct server_state_handle_t;
    struct server_keypair_handle_t;
    struct credential_store_handle_t;

    int opaque_server_keypair_generate(server_keypair_handle_t** handle);
    void opaque_server_keypair_destroy(server_keypair_handle_t* handle);
    int opaque_server_keypair_get_public_key(server_keypair_handle_t* handle, uint8_t* public_key, size_t key_buffer_size);
    int opaque_server_create(server_keypair_handle_t* keypair_handle, opaque_server_handle_t** handle);
    void opaque_server_destroy(opaque_server_handle_t* handle);
    int opaque_server_state_create(server_state_handle_t** handle);
    void opaque_server_state_destroy(server_state_handle_t* handle);
    int opaque_server_create_registration_response(opaque_server_handle_t* server_handle, const uint8_t* request_data, size_t request_length, uint8_t* response_data, size_t response_buffer_size, uint8_t* credentials_data, size_t credentials_buffer_size);
    int opaque_server_generate_ke2(opaque_server_handle_t* server_handle, const uint8_t* ke1_data, size_t ke1_length, const uint8_t* credentials_data, size_t credentials_length, uint8_t* ke2_data, size_t ke2_buffer_size, server_state_handle_t* state_handle);
    int opaque_server_finish(opaque_server_handle_t* server_handle, const uint8_t* ke3_data, size_t ke3_length, server_state_handle_t* state_handle, uint8_t* session_key, size_t session_key_buffer_size);
    int opaque_credential_store_create(credential_store_handle_t** handle);
    void opaque_credential_store_destroy(credential_store_handle_t* handle);
    int opaque_credential_store_store(credential_store_handle_t* store_handle, const uint8_t* user_id, size_t user_id_length, const uint8_t* credentials_data, size_t credentials_length);
    int opaque_credential_store_retrieve(credential_store_handle_t* store_handle, const uint8_t* user_id, size_t user_id_length, uint8_t* credentials_data, size_t credentials_buffer_size);
}

using namespace ecliptix::security::opaque;

TEST_CASE("OPAQUE Protocol Complete Flow", "[opaque][protocol]") {
    REQUIRE(sodium_init() >= 0); // 0 = success, 1 = already initialized

    const char* password = "super_secret_password";
    const char* user_id = "test_user";

    // Step 1: Generate server keypair
    server_keypair_handle_t* server_keypair = nullptr;
    REQUIRE(opaque_server_keypair_generate(&server_keypair) == static_cast<int>(Result::Success));
    REQUIRE(server_keypair != nullptr);

    // Get server public key
    uint8_t server_public_key[PUBLIC_KEY_LENGTH];
    REQUIRE(opaque_server_keypair_get_public_key(server_keypair, server_public_key, PUBLIC_KEY_LENGTH) == static_cast<int>(Result::Success));

    // Step 2: Create server and client
    opaque_server_handle_t* server = nullptr;
    REQUIRE(opaque_server_create(server_keypair, &server) == static_cast<int>(Result::Success));
    REQUIRE(server != nullptr);

    void* client = nullptr;
    REQUIRE(opaque_client_create(server_public_key, PUBLIC_KEY_LENGTH, &client) == static_cast<int>(Result::Success));
    REQUIRE(client != nullptr);

    // Step 3: REGISTRATION FLOW
    void* client_state = nullptr;
    REQUIRE(opaque_client_state_create(&client_state) == static_cast<int>(Result::Success));

    // 3a. Client creates registration request
    uint8_t registration_request[REGISTRATION_REQUEST_LENGTH];
    REQUIRE(opaque_client_create_registration_request(
        client, reinterpret_cast<const uint8_t*>(password), strlen(password),
        client_state, registration_request, REGISTRATION_REQUEST_LENGTH) == static_cast<int>(Result::Success));

    // 3b. Server creates registration response
    uint8_t registration_response[REGISTRATION_RESPONSE_LENGTH];
    uint8_t server_credentials[ENVELOPE_LENGTH + PRIVATE_KEY_LENGTH];
    REQUIRE(opaque_server_create_registration_response(
        server, registration_request, REGISTRATION_REQUEST_LENGTH,
        registration_response, REGISTRATION_RESPONSE_LENGTH,
        server_credentials, ENVELOPE_LENGTH + PRIVATE_KEY_LENGTH) == static_cast<int>(Result::Success));

    // 3c. Client finalizes registration
    uint8_t registration_record[ENVELOPE_LENGTH + PUBLIC_KEY_LENGTH];
    REQUIRE(opaque_client_finalize_registration(
        client, registration_response, REGISTRATION_RESPONSE_LENGTH,
        client_state, registration_record, ENVELOPE_LENGTH + PUBLIC_KEY_LENGTH) == static_cast<int>(Result::Success));

    // 3d. Store credentials in server store
    credential_store_handle_t* credential_store = nullptr;
    REQUIRE(opaque_credential_store_create(&credential_store) == static_cast<int>(Result::Success));

    // Create proper server credentials from client record
    uint8_t stored_credentials[ENVELOPE_LENGTH + PRIVATE_KEY_LENGTH];
    std::memcpy(stored_credentials, registration_record, ENVELOPE_LENGTH);
    // Add masking key from server credentials
    std::memcpy(stored_credentials + ENVELOPE_LENGTH, server_credentials + ENVELOPE_LENGTH, PRIVATE_KEY_LENGTH);

    REQUIRE(opaque_credential_store_store(
        credential_store, reinterpret_cast<const uint8_t*>(user_id), strlen(user_id),
        stored_credentials, ENVELOPE_LENGTH + PRIVATE_KEY_LENGTH) == static_cast<int>(Result::Success));

    // Clean up registration state
    opaque_client_state_destroy(client_state);

    SECTION("Authentication with correct password") {
        // Step 4: AUTHENTICATION FLOW
        void* auth_client_state = nullptr;
        REQUIRE(opaque_client_state_create(&auth_client_state) == static_cast<int>(Result::Success));

        server_state_handle_t* server_state = nullptr;
        REQUIRE(opaque_server_state_create(&server_state) == static_cast<int>(Result::Success));

        // 4a. Client generates KE1
        uint8_t ke1[KE1_LENGTH];
        REQUIRE(opaque_client_generate_ke1(
            client, reinterpret_cast<const uint8_t*>(password), strlen(password),
            auth_client_state, ke1, KE1_LENGTH) == static_cast<int>(Result::Success));

        // 4b. Server retrieves credentials and generates KE2
        uint8_t retrieved_credentials[ENVELOPE_LENGTH + PRIVATE_KEY_LENGTH];
        REQUIRE(opaque_credential_store_retrieve(
            credential_store, reinterpret_cast<const uint8_t*>(user_id), strlen(user_id),
            retrieved_credentials, ENVELOPE_LENGTH + PRIVATE_KEY_LENGTH) == static_cast<int>(Result::Success));

        uint8_t ke2[KE2_LENGTH];
        REQUIRE(opaque_server_generate_ke2(
            server, ke1, KE1_LENGTH,
            retrieved_credentials, ENVELOPE_LENGTH + PRIVATE_KEY_LENGTH,
            ke2, KE2_LENGTH, server_state) == static_cast<int>(Result::Success));

        // 4c. Client generates KE3
        uint8_t ke3[KE3_LENGTH];
        REQUIRE(opaque_client_generate_ke3(
            client, ke2, KE2_LENGTH,
            auth_client_state, ke3, KE3_LENGTH) == static_cast<int>(Result::Success));

        // 4d. Server finishes and gets session key
        uint8_t server_session_key[HASH_LENGTH];
        REQUIRE(opaque_server_finish(
            server, ke3, KE3_LENGTH, server_state,
            server_session_key, HASH_LENGTH) == static_cast<int>(Result::Success));

        // 4e. Client finishes and gets session key
        uint8_t client_session_key[HASH_LENGTH];
        REQUIRE(opaque_client_finish(
            client, auth_client_state,
            client_session_key, HASH_LENGTH) == static_cast<int>(Result::Success));

        // 4f. Verify session keys match
        REQUIRE(std::memcmp(client_session_key, server_session_key, HASH_LENGTH) == 0);

        // Clean up
        opaque_client_state_destroy(auth_client_state);
        opaque_server_state_destroy(server_state);
    }

    SECTION("Authentication with wrong password fails") {
        void* auth_client_state = nullptr;
        REQUIRE(opaque_client_state_create(&auth_client_state) == static_cast<int>(Result::Success));

        server_state_handle_t* server_state = nullptr;
        REQUIRE(opaque_server_state_create(&server_state) == static_cast<int>(Result::Success));

        // Use wrong password
        const char* wrong_password = "wrong_password";
        uint8_t ke1[KE1_LENGTH];
        REQUIRE(opaque_client_generate_ke1(
            client, reinterpret_cast<const uint8_t*>(wrong_password), strlen(wrong_password),
            auth_client_state, ke1, KE1_LENGTH) == static_cast<int>(Result::Success));

        uint8_t retrieved_credentials[ENVELOPE_LENGTH + PRIVATE_KEY_LENGTH];
        REQUIRE(opaque_credential_store_retrieve(
            credential_store, reinterpret_cast<const uint8_t*>(user_id), strlen(user_id),
            retrieved_credentials, ENVELOPE_LENGTH + PRIVATE_KEY_LENGTH) == static_cast<int>(Result::Success));

        uint8_t ke2[KE2_LENGTH];
        REQUIRE(opaque_server_generate_ke2(
            server, ke1, KE1_LENGTH,
            retrieved_credentials, ENVELOPE_LENGTH + PRIVATE_KEY_LENGTH,
            ke2, KE2_LENGTH, server_state) == static_cast<int>(Result::Success));

        // Client should fail to generate KE3 with wrong password
        uint8_t ke3[KE3_LENGTH];
        int result = opaque_client_generate_ke3(
            client, ke2, KE2_LENGTH,
            auth_client_state, ke3, KE3_LENGTH);

        // Either KE3 generation fails, or server rejects KE3
        if (result == static_cast<int>(Result::Success)) {
            uint8_t server_session_key[HASH_LENGTH];
            REQUIRE(opaque_server_finish(
                server, ke3, KE3_LENGTH, server_state,
                server_session_key, HASH_LENGTH) == static_cast<int>(Result::AuthenticationError));
        } else {
            REQUIRE(result == static_cast<int>(Result::AuthenticationError));
        }

        // Clean up
        opaque_client_state_destroy(auth_client_state);
        opaque_server_state_destroy(server_state);
    }

    // Final cleanup
    opaque_credential_store_destroy(credential_store);
    opaque_client_destroy(client);
    opaque_server_destroy(server);
    opaque_server_keypair_destroy(server_keypair);
}

TEST_CASE("Input Validation", "[opaque][validation]") {
    REQUIRE(sodium_init() >= 0);

    SECTION("Client creation with invalid public key") {
        uint8_t invalid_key[PUBLIC_KEY_LENGTH] = {0}; // All zeros - invalid curve point
        void* client = nullptr;
        int result = opaque_client_create(invalid_key, PUBLIC_KEY_LENGTH, &client);
        // Should fail with either InvalidPublicKey or MemoryError due to constructor exception
        REQUIRE((result == static_cast<int>(Result::InvalidPublicKey) ||
                 result == static_cast<int>(Result::MemoryError)));
    }

    SECTION("Client creation with null pointer") {
        void* client = nullptr;
        REQUIRE(opaque_client_create(nullptr, PUBLIC_KEY_LENGTH, &client) == static_cast<int>(Result::InvalidInput));
    }

    SECTION("Client creation with wrong key length") {
        uint8_t key[PUBLIC_KEY_LENGTH];
        randombytes_buf(key, PUBLIC_KEY_LENGTH);
        void* client = nullptr;
        REQUIRE(opaque_client_create(key, PUBLIC_KEY_LENGTH - 1, &client) == static_cast<int>(Result::InvalidInput));
    }
}

TEST_CASE("Memory Safety", "[opaque][memory]") {
    REQUIRE(sodium_init() >= 0);

    // Generate valid server key
    server_keypair_handle_t* server_keypair = nullptr;
    REQUIRE(opaque_server_keypair_generate(&server_keypair) == static_cast<int>(Result::Success));

    uint8_t server_public_key[PUBLIC_KEY_LENGTH];
    REQUIRE(opaque_server_keypair_get_public_key(server_keypair, server_public_key, PUBLIC_KEY_LENGTH) == static_cast<int>(Result::Success));

    SECTION("Multiple client creation and destruction") {
        std::vector<void*> clients;

        // Create multiple clients
        for (int i = 0; i < 10; ++i) {
            void* client = nullptr;
            REQUIRE(opaque_client_create(server_public_key, PUBLIC_KEY_LENGTH, &client) == static_cast<int>(Result::Success));
            clients.push_back(client);
        }

        // Destroy all clients
        for (void* client : clients) {
            opaque_client_destroy(client);
        }
    }

    opaque_server_keypair_destroy(server_keypair);
}