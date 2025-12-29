#include <catch2/catch_test_macros.hpp>
#include "opaque/opaque.h"
#include "opaque/initiator.h"
#include "opaque/responder.h"
#include <sodium.h>
#include <cstring>

extern "C" {
    int opaque_client_create(const uint8_t* server_public_key, size_t key_length, void** handle);
    void opaque_client_destroy(void* handle);
    int opaque_client_state_create(void** handle);
    void opaque_client_state_destroy(void* handle);
    int opaque_client_create_registration_request(void* client_handle, const uint8_t* secure_key, size_t secure_key_length, void* state_handle, uint8_t* request_out, size_t request_length);
    int opaque_client_finalize_registration(void* client_handle, const uint8_t* response, size_t response_length, void* state_handle, uint8_t* record_out, size_t record_length);
    int opaque_client_generate_ke1(void* client_handle, const uint8_t* secure_key, size_t secure_key_length, void* state_handle, uint8_t* ke1_out, size_t ke1_length);
    int opaque_client_generate_ke3(void* client_handle, const uint8_t* ke2, size_t ke2_length, void* state_handle, uint8_t* ke3_out, size_t ke3_length);
    int opaque_client_finish(void* client_handle, void* state_handle, uint8_t* session_key_out, size_t session_key_length, uint8_t* master_key_out, size_t master_key_length);

    struct opaque_server_handle_t;
    struct server_state_handle_t;
    struct server_keypair_handle_t;
    int opaque_server_keypair_generate(server_keypair_handle_t** handle);
    void opaque_server_keypair_destroy(server_keypair_handle_t* handle);
    int opaque_server_keypair_get_public_key(server_keypair_handle_t* handle, uint8_t* public_key, size_t key_buffer_size);
    int opaque_server_create(server_keypair_handle_t* keypair_handle, opaque_server_handle_t** handle);
    void opaque_server_destroy(opaque_server_handle_t* handle);
    int opaque_server_state_create(server_state_handle_t** handle);
    void opaque_server_state_destroy(server_state_handle_t* handle);
    int opaque_server_create_registration_response(opaque_server_handle_t* server_handle, const uint8_t* request_data, size_t request_length, const uint8_t* account_id, size_t account_id_length, uint8_t* response_data, size_t response_buffer_size);
    int opaque_server_build_credentials(const uint8_t* registration_record, size_t record_length, uint8_t* credentials_out, size_t credentials_out_length);
    int opaque_server_generate_ke2(opaque_server_handle_t* server_handle, const uint8_t* ke1_data, size_t ke1_length, const uint8_t* account_id, size_t account_id_length, const uint8_t* credentials_data, size_t credentials_length, uint8_t* ke2_data, size_t ke2_buffer_size, server_state_handle_t* state_handle);
    int opaque_server_finish(opaque_server_handle_t* server_handle, const uint8_t* ke3_data, size_t ke3_length, server_state_handle_t* state_handle, uint8_t* session_key, size_t session_key_buffer_size, uint8_t* master_key, size_t master_key_buffer_size);
}

using namespace ecliptix::security::opaque;

namespace {
constexpr char kSecureKey[] = "ecliptix_test_password_v1";
constexpr char kInvalidSecureKey[] = "ecliptix_invalid_password_v1";
constexpr char kSimSecureKey[] = "ecliptix_sim_password_v1";
constexpr char kSimInvalidSecureKey[] = "ecliptix_sim_wrong_password_v1";
constexpr uint8_t kAccountId[16] = {
    0x4f, 0x8c, 0x2d, 0xa1,
    0x91, 0x73, 0x4f, 0x2a,
    0xb6, 0x11, 0x22, 0x9d,
    0x3c, 0xf0, 0x7a, 0x5e
};
constexpr uint8_t kTamperMask = 0x01;
constexpr size_t kTamperKe2Index = KE2_LENGTH - 1;
constexpr size_t kTamperKe3Index = 0;
constexpr int kClientIterations = 10;
constexpr uint8_t kInvalidKeyValue = 0;
constexpr int kAuthErrorCode = static_cast<int>(Result::AuthenticationError);

void ExpectAuthError(int result, const char* context) {
    INFO(context);
    INFO("Expected AuthenticationError (-5) for wrong password");
    REQUIRE(result == kAuthErrorCode);
}
}

TEST_CASE("Ecliptix OPAQUE Protocol Complete Flow", "[opaque][protocol]") {
    REQUIRE(sodium_init() >= 0);

    const char* secure_key = kSecureKey;

    server_keypair_handle_t* server_keypair = nullptr;
    REQUIRE(opaque_server_keypair_generate(&server_keypair) == static_cast<int>(Result::Success));
    REQUIRE(server_keypair != nullptr);

    uint8_t server_public_key[PUBLIC_KEY_LENGTH];
    REQUIRE(opaque_server_keypair_get_public_key(server_keypair, server_public_key, PUBLIC_KEY_LENGTH) == static_cast<int>(Result::Success));

    opaque_server_handle_t* server = nullptr;
    REQUIRE(opaque_server_create(server_keypair, &server) == static_cast<int>(Result::Success));
    REQUIRE(server != nullptr);

    void* client = nullptr;
    REQUIRE(opaque_client_create(server_public_key, PUBLIC_KEY_LENGTH, &client) == static_cast<int>(Result::Success));
    REQUIRE(client != nullptr);

    void* client_state = nullptr;
    REQUIRE(opaque_client_state_create(&client_state) == static_cast<int>(Result::Success));

    uint8_t registration_request[REGISTRATION_REQUEST_LENGTH];
    REQUIRE(opaque_client_create_registration_request(
        client, reinterpret_cast<const uint8_t*>(secure_key), strlen(secure_key),
        client_state, registration_request, REGISTRATION_REQUEST_LENGTH) == static_cast<int>(Result::Success));

    uint8_t registration_response[REGISTRATION_RESPONSE_LENGTH];
    REQUIRE(opaque_server_create_registration_response(
        server, registration_request, REGISTRATION_REQUEST_LENGTH,
        kAccountId, sizeof(kAccountId),
        registration_response, REGISTRATION_RESPONSE_LENGTH) == static_cast<int>(Result::Success));

    uint8_t registration_record[REGISTRATION_RECORD_LENGTH];
    REQUIRE(opaque_client_finalize_registration(
        client, registration_response, REGISTRATION_RESPONSE_LENGTH,
        client_state, registration_record, REGISTRATION_RECORD_LENGTH) == static_cast<int>(Result::Success));

    uint8_t stored_credentials[RESPONDER_CREDENTIALS_LENGTH];
    REQUIRE(opaque_server_build_credentials(
        registration_record, REGISTRATION_RECORD_LENGTH,
        stored_credentials, RESPONDER_CREDENTIALS_LENGTH) == static_cast<int>(Result::Success));

    opaque_client_state_destroy(client_state);

    SECTION("Ecliptix authentication with correct secure key") {
        void* auth_client_state = nullptr;
        REQUIRE(opaque_client_state_create(&auth_client_state) == static_cast<int>(Result::Success));

        server_state_handle_t* server_state = nullptr;
        REQUIRE(opaque_server_state_create(&server_state) == static_cast<int>(Result::Success));

        uint8_t ke1[KE1_LENGTH];
        REQUIRE(opaque_client_generate_ke1(
            client, reinterpret_cast<const uint8_t*>(secure_key), strlen(secure_key),
            auth_client_state, ke1, KE1_LENGTH) == static_cast<int>(Result::Success));


        uint8_t ke2[KE2_LENGTH];
        REQUIRE(opaque_server_generate_ke2(
            server, ke1, KE1_LENGTH,
            kAccountId, sizeof(kAccountId),
            stored_credentials, RESPONDER_CREDENTIALS_LENGTH,
            ke2, KE2_LENGTH, server_state) == static_cast<int>(Result::Success));

        uint8_t ke3[KE3_LENGTH];
        REQUIRE(opaque_client_generate_ke3(
            client, ke2, KE2_LENGTH,
            auth_client_state, ke3, KE3_LENGTH) == static_cast<int>(Result::Success));

        uint8_t server_session_key[HASH_LENGTH];
        uint8_t server_master_key[MASTER_KEY_LENGTH];
        REQUIRE(opaque_server_finish(
            server, ke3, KE3_LENGTH, server_state,
            server_session_key, HASH_LENGTH,
            server_master_key, MASTER_KEY_LENGTH) == static_cast<int>(Result::Success));

        uint8_t client_session_key[HASH_LENGTH];
        uint8_t recovered_master_key[MASTER_KEY_LENGTH];
        REQUIRE(opaque_client_finish(
            client, auth_client_state,
            client_session_key, HASH_LENGTH,
            recovered_master_key, MASTER_KEY_LENGTH) == static_cast<int>(Result::Success));

        REQUIRE(std::memcmp(client_session_key, server_session_key, HASH_LENGTH) == 0);
        REQUIRE(std::memcmp(recovered_master_key, server_master_key, MASTER_KEY_LENGTH) == 0);

        opaque_client_state_destroy(auth_client_state);
        opaque_server_state_destroy(server_state);
    }

    SECTION("Ecliptix authentication with invalid secure key fails") {
        void* auth_client_state = nullptr;
        REQUIRE(opaque_client_state_create(&auth_client_state) == static_cast<int>(Result::Success));

        server_state_handle_t* server_state = nullptr;
        REQUIRE(opaque_server_state_create(&server_state) == static_cast<int>(Result::Success));

        const char* invalid_secure_key = kInvalidSecureKey;
        uint8_t ke1[KE1_LENGTH];
        REQUIRE(opaque_client_generate_ke1(
            client, reinterpret_cast<const uint8_t*>(invalid_secure_key), strlen(invalid_secure_key),
            auth_client_state, ke1, KE1_LENGTH) == static_cast<int>(Result::Success));


        uint8_t ke2[KE2_LENGTH];
        REQUIRE(opaque_server_generate_ke2(
            server, ke1, KE1_LENGTH,
            kAccountId, sizeof(kAccountId),
            stored_credentials, RESPONDER_CREDENTIALS_LENGTH,
            ke2, KE2_LENGTH, server_state) == static_cast<int>(Result::Success));

        uint8_t ke3[KE3_LENGTH];
        int result = opaque_client_generate_ke3(
            client, ke2, KE2_LENGTH,
            auth_client_state, ke3, KE3_LENGTH);

        if (result == static_cast<int>(Result::Success)) {
            uint8_t server_session_key[HASH_LENGTH];
            uint8_t server_master_key[MASTER_KEY_LENGTH];
            int finish_result = opaque_server_finish(
                server, ke3, KE3_LENGTH, server_state,
                server_session_key, HASH_LENGTH,
                server_master_key, MASTER_KEY_LENGTH);
            ExpectAuthError(finish_result, "wrong password: server finish");
        } else {
            ExpectAuthError(result, "wrong password: client generate ke3");
        }

        opaque_client_state_destroy(auth_client_state);
        opaque_server_state_destroy(server_state);
    }

    SECTION("Ecliptix authentication fails with tampered responder MAC") {
        void* auth_client_state = nullptr;
        REQUIRE(opaque_client_state_create(&auth_client_state) == static_cast<int>(Result::Success));

        server_state_handle_t* server_state = nullptr;
        REQUIRE(opaque_server_state_create(&server_state) == static_cast<int>(Result::Success));

        uint8_t ke1[KE1_LENGTH];
        REQUIRE(opaque_client_generate_ke1(
            client, reinterpret_cast<const uint8_t*>(secure_key), strlen(secure_key),
            auth_client_state, ke1, KE1_LENGTH) == static_cast<int>(Result::Success));

        uint8_t ke2[KE2_LENGTH];
        REQUIRE(opaque_server_generate_ke2(
            server, ke1, KE1_LENGTH,
            kAccountId, sizeof(kAccountId),
            stored_credentials, RESPONDER_CREDENTIALS_LENGTH,
            ke2, KE2_LENGTH, server_state) == static_cast<int>(Result::Success));

        ke2[kTamperKe2Index] ^= kTamperMask;

        uint8_t ke3[KE3_LENGTH];
        int result = opaque_client_generate_ke3(
            client, ke2, KE2_LENGTH,
            auth_client_state, ke3, KE3_LENGTH);
        REQUIRE(result == static_cast<int>(Result::AuthenticationError));

        opaque_client_state_destroy(auth_client_state);
        opaque_server_state_destroy(server_state);
    }


    opaque_client_destroy(client);
    opaque_server_destroy(server);
    opaque_server_keypair_destroy(server_keypair);
}

TEST_CASE("Ecliptix OPAQUE C++ Client/Server Simulation", "[opaque][cpp][protocol]") {
    REQUIRE(sodium_init() >= 0);

    const char* secure_key = kSimSecureKey;

    using namespace ecliptix::security::opaque::initiator;
    using namespace ecliptix::security::opaque::responder;

    ResponderKeyPair server_keypair;
    REQUIRE(ResponderKeyPair::generate(server_keypair) == Result::Success);

    OpaqueResponder server(server_keypair);
    ResponderPublicKey server_public_key(server_keypair.public_key.data(), server_keypair.public_key.size());
    OpaqueInitiator client(server_public_key);

    InitiatorState registration_state;
    RegistrationRequest registration_request;
    REQUIRE(OpaqueInitiator::create_registration_request(
        reinterpret_cast<const uint8_t*>(secure_key), strlen(secure_key),
        registration_request, registration_state) == Result::Success);

    RegistrationResponse registration_response;
    REQUIRE(server.create_registration_response(
        registration_request.data.data(), registration_request.data.size(),
        kAccountId, sizeof(kAccountId),
        registration_response) == Result::Success);

    RegistrationRecord registration_record;
    REQUIRE(client.finalize_registration(
        registration_response.data.data(), registration_response.data.size(),
        registration_state, registration_record) == Result::Success);

    REQUIRE(registration_record.envelope.size() == ENVELOPE_LENGTH);
    REQUIRE(registration_record.initiator_public_key.size() == PUBLIC_KEY_LENGTH);
    secure_bytes record_buffer(REGISTRATION_RECORD_LENGTH);
    std::memcpy(record_buffer.data(), registration_record.envelope.data(), registration_record.envelope.size());
    std::memcpy(record_buffer.data() + ENVELOPE_LENGTH,
                registration_record.initiator_public_key.data(),
                registration_record.initiator_public_key.size());

    ResponderCredentials credentials;
    REQUIRE(build_credentials(
        record_buffer.data(), record_buffer.size(),
        credentials) == Result::Success);

    const auto build_ke1_data = [](const KE1& ke1) {
        secure_bytes ke1_data(KE1_LENGTH);
        size_t offset = 0;
        std::memcpy(ke1_data.data() + offset, ke1.credential_request.data(), ke1.credential_request.size());
        offset += ke1.credential_request.size();
        std::memcpy(ke1_data.data() + offset, ke1.initiator_public_key.data(), ke1.initiator_public_key.size());
        offset += ke1.initiator_public_key.size();
        std::memcpy(ke1_data.data() + offset, ke1.initiator_nonce.data(), ke1.initiator_nonce.size());
        return ke1_data;
    };

    const auto build_ke2_data = [](const KE2& ke2) {
        secure_bytes ke2_data(KE2_LENGTH);
        size_t offset = 0;
        std::memcpy(ke2_data.data() + offset, ke2.responder_nonce.data(), ke2.responder_nonce.size());
        offset += ke2.responder_nonce.size();
        std::memcpy(ke2_data.data() + offset, ke2.responder_public_key.data(), ke2.responder_public_key.size());
        offset += ke2.responder_public_key.size();
        std::memcpy(ke2_data.data() + offset, ke2.credential_response.data(), ke2.credential_response.size());
        offset += ke2.credential_response.size();
        std::memcpy(ke2_data.data() + offset, ke2.responder_mac.data(), ke2.responder_mac.size());
        return ke2_data;
    };

    SECTION("Ecliptix C++ simulation happy path") {
        InitiatorState auth_state;
        KE1 ke1;
        REQUIRE(OpaqueInitiator::generate_ke1(
            reinterpret_cast<const uint8_t*>(secure_key), strlen(secure_key),
            ke1, auth_state) == Result::Success);

        secure_bytes ke1_data = build_ke1_data(ke1);

        ResponderState server_state;
        KE2 ke2;
        REQUIRE(server.generate_ke2(
            ke1_data.data(), ke1_data.size(),
            kAccountId, sizeof(kAccountId),
            credentials, ke2, server_state) == Result::Success);

        secure_bytes ke2_data = build_ke2_data(ke2);

        KE3 ke3;
        REQUIRE(client.generate_ke3(
            ke2_data.data(), ke2_data.size(),
            auth_state, ke3) == Result::Success);

        secure_bytes server_session_key;
        secure_bytes server_master_key;
        REQUIRE(server.responder_finish(
            ke3.initiator_mac.data(), ke3.initiator_mac.size(),
            server_state, server_session_key, server_master_key) == Result::Success);

        secure_bytes client_session_key;
        secure_bytes client_master_key;
        REQUIRE(OpaqueInitiator::initiator_finish(auth_state, client_session_key, client_master_key) == Result::Success);

        REQUIRE(client_session_key == server_session_key);
        REQUIRE(client_master_key == server_master_key);
        REQUIRE(client_master_key.size() == MASTER_KEY_LENGTH);
        REQUIRE(server_state.handshake_complete);
        REQUIRE(auth_state.session_key.empty());
        REQUIRE(auth_state.master_key.empty());
        REQUIRE(server_state.session_key.empty());
        REQUIRE(server_state.master_key.empty());
    }

    SECTION("Ecliptix C++ simulation fails with wrong secure key") {
        const char* invalid_secure_key = kSimInvalidSecureKey;
        InitiatorState auth_state;
        KE1 ke1;
        REQUIRE(OpaqueInitiator::generate_ke1(
            reinterpret_cast<const uint8_t*>(invalid_secure_key), strlen(invalid_secure_key),
            ke1, auth_state) == Result::Success);

        secure_bytes ke1_data = build_ke1_data(ke1);

        ResponderState server_state;
        KE2 ke2;
        REQUIRE(server.generate_ke2(
            ke1_data.data(), ke1_data.size(),
            kAccountId, sizeof(kAccountId),
            credentials, ke2, server_state) == Result::Success);

        secure_bytes ke2_data = build_ke2_data(ke2);

        KE3 ke3;
        INFO("Expected AuthenticationError for wrong password");
        REQUIRE(client.generate_ke3(
            ke2_data.data(), ke2_data.size(),
            auth_state, ke3) == Result::AuthenticationError);
        REQUIRE_FALSE(server_state.handshake_complete);
    }

    SECTION("Ecliptix C++ simulation fails with tampered KE2") {
        InitiatorState auth_state;
        KE1 ke1;
        REQUIRE(OpaqueInitiator::generate_ke1(
            reinterpret_cast<const uint8_t*>(secure_key), strlen(secure_key),
            ke1, auth_state) == Result::Success);

        secure_bytes ke1_data = build_ke1_data(ke1);

        ResponderState server_state;
        KE2 ke2;
        REQUIRE(server.generate_ke2(
            ke1_data.data(), ke1_data.size(),
            kAccountId, sizeof(kAccountId),
            credentials, ke2, server_state) == Result::Success);

        secure_bytes ke2_data = build_ke2_data(ke2);
        ke2_data[kTamperKe2Index] ^= kTamperMask;

        KE3 ke3;
        REQUIRE(client.generate_ke3(
            ke2_data.data(), ke2_data.size(),
            auth_state, ke3) == Result::AuthenticationError);
        REQUIRE_FALSE(server_state.handshake_complete);
        REQUIRE(auth_state.session_key.empty());
        REQUIRE(auth_state.master_key.empty());
    }

    SECTION("Ecliptix C++ simulation fails with tampered KE3") {
        InitiatorState auth_state;
        KE1 ke1;
        REQUIRE(OpaqueInitiator::generate_ke1(
            reinterpret_cast<const uint8_t*>(secure_key), strlen(secure_key),
            ke1, auth_state) == Result::Success);

        secure_bytes ke1_data = build_ke1_data(ke1);

        ResponderState server_state;
        KE2 ke2;
        REQUIRE(server.generate_ke2(
            ke1_data.data(), ke1_data.size(),
            kAccountId, sizeof(kAccountId),
            credentials, ke2, server_state) == Result::Success);

        secure_bytes ke2_data = build_ke2_data(ke2);

        KE3 ke3;
        REQUIRE(client.generate_ke3(
            ke2_data.data(), ke2_data.size(),
            auth_state, ke3) == Result::Success);

        ke3.initiator_mac[kTamperKe3Index] ^= kTamperMask;

        secure_bytes server_session_key;
        secure_bytes server_master_key;
        REQUIRE(server.responder_finish(
            ke3.initiator_mac.data(), ke3.initiator_mac.size(),
            server_state, server_session_key, server_master_key) == Result::AuthenticationError);
        REQUIRE_FALSE(server_state.handshake_complete);
        REQUIRE(server_state.session_key.empty());
        REQUIRE(server_state.master_key.empty());
    }
}

TEST_CASE("Ecliptix OPAQUE Input Validation", "[opaque][validation]") {
    REQUIRE(sodium_init() >= 0);

    SECTION("Ecliptix client creation with invalid public key") {
        uint8_t invalid_key[PUBLIC_KEY_LENGTH] = {kInvalidKeyValue};
        void* client = nullptr;
        int result = opaque_client_create(invalid_key, PUBLIC_KEY_LENGTH, &client);
        REQUIRE((result == static_cast<int>(Result::InvalidPublicKey) ||
                 result == static_cast<int>(Result::MemoryError)));
    }

    SECTION("Ecliptix client creation with null pointer") {
        void* client = nullptr;
        REQUIRE(opaque_client_create(nullptr, PUBLIC_KEY_LENGTH, &client) == static_cast<int>(Result::InvalidInput));
    }

    SECTION("Ecliptix client creation with wrong key length") {
        uint8_t key[PUBLIC_KEY_LENGTH];
        randombytes_buf(key, PUBLIC_KEY_LENGTH);
        void* client = nullptr;
        REQUIRE(opaque_client_create(key, PUBLIC_KEY_LENGTH - 1, &client) == static_cast<int>(Result::InvalidInput));
    }
}

TEST_CASE("Ecliptix OPAQUE Memory Safety", "[opaque][memory]") {
    REQUIRE(sodium_init() >= 0);

    server_keypair_handle_t* server_keypair = nullptr;
    REQUIRE(opaque_server_keypair_generate(&server_keypair) == static_cast<int>(Result::Success));

    uint8_t server_public_key[PUBLIC_KEY_LENGTH];
    REQUIRE(opaque_server_keypair_get_public_key(server_keypair, server_public_key, PUBLIC_KEY_LENGTH) == static_cast<int>(Result::Success));

    SECTION("Ecliptix multiple client creation and destruction") {
        std::vector<void*> clients;

        for (int i = 0; i < kClientIterations; ++i) {
            void* client = nullptr;
            REQUIRE(opaque_client_create(server_public_key, PUBLIC_KEY_LENGTH, &client) == static_cast<int>(Result::Success));
            clients.push_back(client);
        }

        for (void* client : clients) {
            opaque_client_destroy(client);
        }
    }

    opaque_server_keypair_destroy(server_keypair);
}
