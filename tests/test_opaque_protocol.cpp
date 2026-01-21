#include <catch2/catch_test_macros.hpp>
#include "opaque/opaque.h"
#include "opaque/initiator.h"
#include "opaque/responder.h"
#include "opaque/protocol.h"
#include "opaque/pq.h"
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
    int opaque_client_create_default(void** handle);

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
    int opaque_server_create_default(opaque_server_handle_t** handle);
    int opaque_server_derive_keypair_from_seed(const uint8_t* seed, size_t seed_len, uint8_t* private_key, size_t private_key_buffer_len, uint8_t* public_key, size_t public_key_buffer_len);
    int opaque_server_create_with_keys(const uint8_t* private_key, size_t private_key_len, const uint8_t* public_key, size_t public_key_len, opaque_server_handle_t** handle);

    size_t opaque_get_ke1_length();
    size_t opaque_get_ke2_length();
    size_t opaque_get_registration_record_length();
    size_t opaque_get_kem_public_key_length();
    size_t opaque_get_kem_ciphertext_length();
    size_t opaque_server_get_ke2_length();
    size_t opaque_server_get_registration_record_length();
    size_t opaque_server_get_credentials_length();
}

using namespace ecliptix::security::opaque;

constexpr size_t KE1_SIZE = KE1_LENGTH;
constexpr size_t KE2_SIZE = KE2_LENGTH;
constexpr size_t RECORD_SIZE = REGISTRATION_RECORD_LENGTH;
constexpr size_t CREDENTIALS_SIZE = RESPONDER_CREDENTIALS_LENGTH;

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

    Result BuildKe1Data(const initiator::KE1& ke1, secure_bytes& ke1_data) {
        ke1_data.resize(KE1_LENGTH);
        return protocol::write_ke1(
            ke1.credential_request.data(), ke1.credential_request.size(),
            ke1.initiator_public_key.data(), ke1.initiator_public_key.size(),
            ke1.initiator_nonce.data(), ke1.initiator_nonce.size(),
            ke1.pq_ephemeral_public_key.data(), ke1.pq_ephemeral_public_key.size(),
            ke1_data.data(), ke1_data.size());
    }

    Result BuildKe2Data(const responder::KE2& ke2, secure_bytes& ke2_data) {
        ke2_data.resize(KE2_LENGTH);
        return protocol::write_ke2(
            ke2.responder_nonce.data(), ke2.responder_nonce.size(),
            ke2.responder_public_key.data(), ke2.responder_public_key.size(),
            ke2.credential_response.data(), ke2.credential_response.size(),
            ke2.responder_mac.data(), ke2.responder_mac.size(),
            ke2.kem_ciphertext.data(), ke2.kem_ciphertext.size(),
            ke2_data.data(), ke2_data.size());
    }

    Result BuildRegistrationRecordBuffer(const initiator::RegistrationRecord& record, secure_bytes& record_buffer) {
        record_buffer.resize(REGISTRATION_RECORD_LENGTH);
        return protocol::write_registration_record(
            record.envelope.data(), record.envelope.size(),
            record.initiator_public_key.data(), record.initiator_public_key.size(),
            record_buffer.data(), record_buffer.size());
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

    uint8_t registration_record[RECORD_SIZE];
    REQUIRE(opaque_client_finalize_registration(
        client, registration_response, REGISTRATION_RESPONSE_LENGTH,
        client_state, registration_record, RECORD_SIZE) == static_cast<int>(Result::Success));

    uint8_t stored_credentials[CREDENTIALS_SIZE];
    REQUIRE(opaque_server_build_credentials(
        registration_record, RECORD_SIZE,
        stored_credentials, CREDENTIALS_SIZE) == static_cast<int>(Result::Success));

    opaque_client_state_destroy(client_state);

    SECTION("Ecliptix authentication with correct secure key") {
        void* auth_client_state = nullptr;
        REQUIRE(opaque_client_state_create(&auth_client_state) == static_cast<int>(Result::Success));

        server_state_handle_t* server_state = nullptr;
        REQUIRE(opaque_server_state_create(&server_state) == static_cast<int>(Result::Success));

        uint8_t ke1[KE1_SIZE];
        REQUIRE(opaque_client_generate_ke1(
            client, reinterpret_cast<const uint8_t*>(secure_key), strlen(secure_key),
            auth_client_state, ke1, KE1_SIZE) == static_cast<int>(Result::Success));

        uint8_t ke2[KE2_SIZE];
        REQUIRE(opaque_server_generate_ke2(
            server, ke1, KE1_SIZE,
            kAccountId, sizeof(kAccountId),
            stored_credentials, CREDENTIALS_SIZE,
            ke2, KE2_SIZE, server_state) == static_cast<int>(Result::Success));

        uint8_t ke3[KE3_LENGTH];
        REQUIRE(opaque_client_generate_ke3(
            client, ke2, KE2_SIZE,
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
        uint8_t ke1[KE1_SIZE];
        REQUIRE(opaque_client_generate_ke1(
            client, reinterpret_cast<const uint8_t*>(invalid_secure_key), strlen(invalid_secure_key),
            auth_client_state, ke1, KE1_SIZE) == static_cast<int>(Result::Success));

        uint8_t ke2[KE2_SIZE];
        REQUIRE(opaque_server_generate_ke2(
            server, ke1, KE1_SIZE,
            kAccountId, sizeof(kAccountId),
            stored_credentials, CREDENTIALS_SIZE,
            ke2, KE2_SIZE, server_state) == static_cast<int>(Result::Success));

        uint8_t ke3[KE3_LENGTH];
        int result = opaque_client_generate_ke3(
            client, ke2, KE2_SIZE,
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

        uint8_t ke1[KE1_SIZE];
        REQUIRE(opaque_client_generate_ke1(
            client, reinterpret_cast<const uint8_t*>(secure_key), strlen(secure_key),
            auth_client_state, ke1, KE1_SIZE) == static_cast<int>(Result::Success));

        uint8_t ke2[KE2_SIZE];
        REQUIRE(opaque_server_generate_ke2(
            server, ke1, KE1_SIZE,
            kAccountId, sizeof(kAccountId),
            stored_credentials, CREDENTIALS_SIZE,
            ke2, KE2_SIZE, server_state) == static_cast<int>(Result::Success));

        ke2[kTamperKe2Index] ^= kTamperMask;

        uint8_t ke3[KE3_LENGTH];
        int result = opaque_client_generate_ke3(
            client, ke2, KE2_SIZE,
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
    secure_bytes record_buffer;
    REQUIRE(BuildRegistrationRecordBuffer(registration_record, record_buffer) == Result::Success);

    ResponderCredentials credentials;
    REQUIRE(build_credentials(
        record_buffer.data(), record_buffer.size(),
        credentials) == Result::Success);

    SECTION("Ecliptix C++ simulation happy path") {
        InitiatorState auth_state;
        KE1 ke1;
        REQUIRE(OpaqueInitiator::generate_ke1(
            reinterpret_cast<const uint8_t*>(secure_key), strlen(secure_key),
            ke1, auth_state) == Result::Success);

        secure_bytes ke1_data;
        REQUIRE(BuildKe1Data(ke1, ke1_data) == Result::Success);

        ResponderState server_state;
        KE2 ke2;
        REQUIRE(server.generate_ke2(
            ke1_data.data(), ke1_data.size(),
            kAccountId, sizeof(kAccountId),
            credentials, ke2, server_state) == Result::Success);

        secure_bytes ke2_data;
        REQUIRE(BuildKe2Data(ke2, ke2_data) == Result::Success);

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

        secure_bytes ke1_data;
        REQUIRE(BuildKe1Data(ke1, ke1_data) == Result::Success);

        ResponderState server_state;
        KE2 ke2;
        REQUIRE(server.generate_ke2(
            ke1_data.data(), ke1_data.size(),
            kAccountId, sizeof(kAccountId),
            credentials, ke2, server_state) == Result::Success);

        secure_bytes ke2_data;
        REQUIRE(BuildKe2Data(ke2, ke2_data) == Result::Success);

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

        secure_bytes ke1_data;
        REQUIRE(BuildKe1Data(ke1, ke1_data) == Result::Success);

        ResponderState server_state;
        KE2 ke2;
        REQUIRE(server.generate_ke2(
            ke1_data.data(), ke1_data.size(),
            kAccountId, sizeof(kAccountId),
            credentials, ke2, server_state) == Result::Success);

        secure_bytes ke2_data;
        REQUIRE(BuildKe2Data(ke2, ke2_data) == Result::Success);
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

        secure_bytes ke1_data;
        REQUIRE(BuildKe1Data(ke1, ke1_data) == Result::Success);

        ResponderState server_state;
        KE2 ke2;
        REQUIRE(server.generate_ke2(
            ke1_data.data(), ke1_data.size(),
            kAccountId, sizeof(kAccountId),
            credentials, ke2, server_state) == Result::Success);

        secure_bytes ke2_data;
        REQUIRE(BuildKe2Data(ke2, ke2_data) == Result::Success);

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

TEST_CASE("Ecliptix OPAQUE Crypto Validation", "[opaque][crypto][validation]") {
    REQUIRE(sodium_init() >= 0);

    SECTION("HKDF expand rejects null info with nonzero length") {
        uint8_t prk[crypto_auth_hmacsha512_BYTES];
        randombytes_buf(prk, sizeof(prk));
        uint8_t okm[32];
        REQUIRE(crypto::key_derivation_expand(prk, sizeof(prk), nullptr, 1, okm, sizeof(okm)) == Result::InvalidInput);
    }

    SECTION("Envelope encryption rejects wrong key length") {
        uint8_t key[crypto_secretbox_KEYBYTES];
        uint8_t nonce[NONCE_LENGTH];
        uint8_t plaintext[32];
        uint8_t ciphertext[sizeof(plaintext)];
        uint8_t auth_tag[crypto_secretbox_MACBYTES];
        uint8_t decrypted[sizeof(plaintext)];
        randombytes_buf(key, sizeof(key));
        randombytes_buf(nonce, sizeof(nonce));
        randombytes_buf(plaintext, sizeof(plaintext));

        REQUIRE(crypto::encrypt_envelope(key, sizeof(key) - 1,
                                         plaintext, sizeof(plaintext),
                                         nonce, ciphertext, auth_tag) == Result::InvalidInput);
        REQUIRE(crypto::decrypt_envelope(key, sizeof(key) - 1,
                                         ciphertext, sizeof(ciphertext),
                                         nonce, auth_tag, decrypted) == Result::InvalidInput);

        REQUIRE(crypto::encrypt_envelope(key, sizeof(key),
                                         plaintext, sizeof(plaintext),
                                         nonce, ciphertext, auth_tag) == Result::Success);
        REQUIRE(crypto::decrypt_envelope(key, sizeof(key),
                                         ciphertext, sizeof(ciphertext),
                                         nonce, auth_tag, decrypted) == Result::Success);
        REQUIRE(std::memcmp(plaintext, decrypted, sizeof(plaintext)) == 0);
    }
}

TEST_CASE("Ecliptix OPAQUE C++ Keypair Validation", "[opaque][cpp][validation]") {
    REQUIRE(sodium_init() >= 0);

    using namespace ecliptix::security::opaque::responder;

    ResponderKeyPair keypair;
    REQUIRE(ResponderKeyPair::generate(keypair) == Result::Success);

    SECTION("Mismatched public key throws") {
        ResponderKeyPair bad = keypair;
        bad.public_key[0] ^= kTamperMask;
        REQUIRE_THROWS(OpaqueResponder(bad));
    }

    SECTION("Invalid private key length throws") {
        ResponderKeyPair bad = keypair;
        bad.private_key.resize(PRIVATE_KEY_LENGTH - 1);
        REQUIRE_THROWS(OpaqueResponder(bad));
    }

    SECTION("Zero private key throws") {
        ResponderKeyPair bad = keypair;
        sodium_memzero(bad.private_key.data(), bad.private_key.size());
        REQUIRE_THROWS(OpaqueResponder(bad));
    }
}

TEST_CASE("Ecliptix OPAQUE Allocator Edge Cases", "[opaque][memory]") {
    SecureAllocator<uint8_t> allocator;
    uint8_t *ptr = nullptr;
    REQUIRE_NOTHROW(ptr = allocator.allocate(0));
    REQUIRE(ptr == nullptr);
    REQUIRE_NOTHROW(allocator.deallocate(ptr, 0));
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

TEST_CASE("Ecliptix OPAQUE Registration Input Validation", "[opaque][validation][registration]") {
    REQUIRE(sodium_init() >= 0);

    server_keypair_handle_t* server_keypair = nullptr;
    REQUIRE(opaque_server_keypair_generate(&server_keypair) == static_cast<int>(Result::Success));

    uint8_t server_public_key[PUBLIC_KEY_LENGTH];
    REQUIRE(opaque_server_keypair_get_public_key(server_keypair, server_public_key, PUBLIC_KEY_LENGTH) == static_cast<int>(Result::Success));

    opaque_server_handle_t* server = nullptr;
    REQUIRE(opaque_server_create(server_keypair, &server) == static_cast<int>(Result::Success));

    void* client = nullptr;
    REQUIRE(opaque_client_create(server_public_key, PUBLIC_KEY_LENGTH, &client) == static_cast<int>(Result::Success));

    SECTION("Registration response with empty account ID fails") {
        void* state = nullptr;
        REQUIRE(opaque_client_state_create(&state) == static_cast<int>(Result::Success));

        uint8_t request[REGISTRATION_REQUEST_LENGTH];
        REQUIRE(opaque_client_create_registration_request(
            client, reinterpret_cast<const uint8_t*>(kSecureKey), strlen(kSecureKey),
            state, request, REGISTRATION_REQUEST_LENGTH) == static_cast<int>(Result::Success));

        uint8_t response[REGISTRATION_RESPONSE_LENGTH];
        int result = opaque_server_create_registration_response(
            server, request, REGISTRATION_REQUEST_LENGTH,
            kAccountId, 0,
            response, REGISTRATION_RESPONSE_LENGTH);
        REQUIRE(result == static_cast<int>(Result::InvalidInput));

        opaque_client_state_destroy(state);
    }

    SECTION("Finalize registration rejects wrong response length") {
        void* state = nullptr;
        REQUIRE(opaque_client_state_create(&state) == static_cast<int>(Result::Success));

        uint8_t request[REGISTRATION_REQUEST_LENGTH];
        REQUIRE(opaque_client_create_registration_request(
            client, reinterpret_cast<const uint8_t*>(kSecureKey), strlen(kSecureKey),
            state, request, REGISTRATION_REQUEST_LENGTH) == static_cast<int>(Result::Success));

        uint8_t response[REGISTRATION_RESPONSE_LENGTH];
        REQUIRE(opaque_server_create_registration_response(
            server, request, REGISTRATION_REQUEST_LENGTH,
            kAccountId, sizeof(kAccountId),
            response, REGISTRATION_RESPONSE_LENGTH) == static_cast<int>(Result::Success));

        uint8_t record[RECORD_SIZE];
        int result = opaque_client_finalize_registration(
            client, response, REGISTRATION_RESPONSE_LENGTH - 1,
            state, record, RECORD_SIZE);
        REQUIRE(result == static_cast<int>(Result::InvalidInput));

        opaque_client_state_destroy(state);
    }

    SECTION("Finalize registration rejects undersized record buffer") {
        void* state = nullptr;
        REQUIRE(opaque_client_state_create(&state) == static_cast<int>(Result::Success));

        uint8_t request[REGISTRATION_REQUEST_LENGTH];
        REQUIRE(opaque_client_create_registration_request(
            client, reinterpret_cast<const uint8_t*>(kSecureKey), strlen(kSecureKey),
            state, request, REGISTRATION_REQUEST_LENGTH) == static_cast<int>(Result::Success));

        uint8_t response[REGISTRATION_RESPONSE_LENGTH];
        REQUIRE(opaque_server_create_registration_response(
            server, request, REGISTRATION_REQUEST_LENGTH,
            kAccountId, sizeof(kAccountId),
            response, REGISTRATION_RESPONSE_LENGTH) == static_cast<int>(Result::Success));

        std::vector<uint8_t> record(RECORD_SIZE - 1);
        int result = opaque_client_finalize_registration(
            client, response, REGISTRATION_RESPONSE_LENGTH,
            state, record.data(), record.size());
        REQUIRE(result == static_cast<int>(Result::InvalidInput));

        opaque_client_state_destroy(state);
    }

    SECTION("Registration record rejects oversized buffer") {
        void* state = nullptr;
        REQUIRE(opaque_client_state_create(&state) == static_cast<int>(Result::Success));

        uint8_t request[REGISTRATION_REQUEST_LENGTH];
        REQUIRE(opaque_client_create_registration_request(
            client, reinterpret_cast<const uint8_t*>(kSecureKey), strlen(kSecureKey),
            state, request, REGISTRATION_REQUEST_LENGTH) == static_cast<int>(Result::Success));

        uint8_t response[REGISTRATION_RESPONSE_LENGTH];
        REQUIRE(opaque_server_create_registration_response(
            server, request, REGISTRATION_REQUEST_LENGTH,
            kAccountId, sizeof(kAccountId),
            response, REGISTRATION_RESPONSE_LENGTH) == static_cast<int>(Result::Success));

        std::vector<uint8_t> record(RECORD_SIZE);
        REQUIRE(opaque_client_finalize_registration(
            client, response, REGISTRATION_RESPONSE_LENGTH,
            state, record.data(), record.size()) == static_cast<int>(Result::Success));

        std::vector<uint8_t> oversized_record(RECORD_SIZE + 1);
        std::memcpy(oversized_record.data(), record.data(), record.size());
        oversized_record.back() = kTamperMask;

        std::vector<uint8_t> creds(CREDENTIALS_SIZE);
        int result = opaque_server_build_credentials(
            oversized_record.data(), oversized_record.size(),
            creds.data(), creds.size());
        REQUIRE(result == static_cast<int>(Result::InvalidInput));

        opaque_client_state_destroy(state);
    }

    opaque_client_destroy(client);
    opaque_server_destroy(server);
    opaque_server_keypair_destroy(server_keypair);
}

TEST_CASE("Ecliptix OPAQUE Registration Tampering", "[opaque][tamper][registration]") {
    REQUIRE(sodium_init() >= 0);

    server_keypair_handle_t* server_keypair = nullptr;
    REQUIRE(opaque_server_keypair_generate(&server_keypair) == static_cast<int>(Result::Success));

    uint8_t server_public_key[PUBLIC_KEY_LENGTH];
    REQUIRE(opaque_server_keypair_get_public_key(server_keypair, server_public_key, PUBLIC_KEY_LENGTH) == static_cast<int>(Result::Success));

    opaque_server_handle_t* server = nullptr;
    REQUIRE(opaque_server_create(server_keypair, &server) == static_cast<int>(Result::Success));

    void* client = nullptr;
    REQUIRE(opaque_client_create(server_public_key, PUBLIC_KEY_LENGTH, &client) == static_cast<int>(Result::Success));

    SECTION("Tampered responder public key in registration response fails finalization") {
        void* state = nullptr;
        REQUIRE(opaque_client_state_create(&state) == static_cast<int>(Result::Success));

        uint8_t request[REGISTRATION_REQUEST_LENGTH];
        REQUIRE(opaque_client_create_registration_request(
            client, reinterpret_cast<const uint8_t*>(kSecureKey), strlen(kSecureKey),
            state, request, REGISTRATION_REQUEST_LENGTH) == static_cast<int>(Result::Success));

        uint8_t response[REGISTRATION_RESPONSE_LENGTH];
        REQUIRE(opaque_server_create_registration_response(
            server, request, REGISTRATION_REQUEST_LENGTH,
            kAccountId, sizeof(kAccountId),
            response, REGISTRATION_RESPONSE_LENGTH) == static_cast<int>(Result::Success));

        std::vector<uint8_t> tampered_response(response, response + REGISTRATION_RESPONSE_LENGTH);
        tampered_response[crypto_core_ristretto255_BYTES + 3] ^= kTamperMask;

        std::vector<uint8_t> record(RECORD_SIZE);
        int result = opaque_client_finalize_registration(
            client, tampered_response.data(), tampered_response.size(),
            state, record.data(), record.size());
        REQUIRE((result == static_cast<int>(Result::AuthenticationError) ||
                 result == static_cast<int>(Result::InvalidPublicKey)));

        opaque_client_state_destroy(state);
    }

    SECTION("Tampered initiator public key in registration record is rejected") {
        void* state = nullptr;
        REQUIRE(opaque_client_state_create(&state) == static_cast<int>(Result::Success));

        uint8_t request[REGISTRATION_REQUEST_LENGTH];
        REQUIRE(opaque_client_create_registration_request(
            client, reinterpret_cast<const uint8_t*>(kSecureKey), strlen(kSecureKey),
            state, request, REGISTRATION_REQUEST_LENGTH) == static_cast<int>(Result::Success));

        uint8_t response[REGISTRATION_RESPONSE_LENGTH];
        REQUIRE(opaque_server_create_registration_response(
            server, request, REGISTRATION_REQUEST_LENGTH,
            kAccountId, sizeof(kAccountId),
            response, REGISTRATION_RESPONSE_LENGTH) == static_cast<int>(Result::Success));

        std::vector<uint8_t> record(RECORD_SIZE);
        REQUIRE(opaque_client_finalize_registration(
            client, response, REGISTRATION_RESPONSE_LENGTH,
            state, record.data(), record.size()) == static_cast<int>(Result::Success));

        std::vector<uint8_t> tampered_record = record;
        std::memset(tampered_record.data() + ENVELOPE_LENGTH, 0, PUBLIC_KEY_LENGTH);

        std::vector<uint8_t> creds(CREDENTIALS_SIZE);
        int result = opaque_server_build_credentials(
            tampered_record.data(), tampered_record.size(),
            creds.data(), creds.size());
        REQUIRE(result == static_cast<int>(Result::InvalidPublicKey));

        opaque_client_state_destroy(state);
    }

    SECTION("Tampered registration envelope fails authentication") {
        void* reg_state = nullptr;
        REQUIRE(opaque_client_state_create(&reg_state) == static_cast<int>(Result::Success));

        uint8_t request[REGISTRATION_REQUEST_LENGTH];
        REQUIRE(opaque_client_create_registration_request(
            client, reinterpret_cast<const uint8_t*>(kSecureKey), strlen(kSecureKey),
            reg_state, request, REGISTRATION_REQUEST_LENGTH) == static_cast<int>(Result::Success));

        uint8_t response[REGISTRATION_RESPONSE_LENGTH];
        REQUIRE(opaque_server_create_registration_response(
            server, request, REGISTRATION_REQUEST_LENGTH,
            kAccountId, sizeof(kAccountId),
            response, REGISTRATION_RESPONSE_LENGTH) == static_cast<int>(Result::Success));

        std::vector<uint8_t> record(RECORD_SIZE);
        REQUIRE(opaque_client_finalize_registration(
            client, response, REGISTRATION_RESPONSE_LENGTH,
            reg_state, record.data(), record.size()) == static_cast<int>(Result::Success));

        std::vector<uint8_t> tampered_record = record;
        tampered_record[0] ^= kTamperMask;

        std::vector<uint8_t> creds(CREDENTIALS_SIZE);
        REQUIRE(opaque_server_build_credentials(
            tampered_record.data(), tampered_record.size(),
            creds.data(), creds.size()) == static_cast<int>(Result::Success));

        void* auth_state = nullptr;
        REQUIRE(opaque_client_state_create(&auth_state) == static_cast<int>(Result::Success));

        server_state_handle_t* server_state = nullptr;
        REQUIRE(opaque_server_state_create(&server_state) == static_cast<int>(Result::Success));

        std::vector<uint8_t> ke1(KE1_SIZE);
        REQUIRE(opaque_client_generate_ke1(
            client, reinterpret_cast<const uint8_t*>(kSecureKey), strlen(kSecureKey),
            auth_state, ke1.data(), KE1_SIZE) == static_cast<int>(Result::Success));

        std::vector<uint8_t> ke2(KE2_SIZE);
        REQUIRE(opaque_server_generate_ke2(
            server, ke1.data(), KE1_SIZE,
            kAccountId, sizeof(kAccountId),
            creds.data(), CREDENTIALS_SIZE,
            ke2.data(), KE2_SIZE, server_state) == static_cast<int>(Result::Success));

        uint8_t ke3[KE3_LENGTH];
        int ke3_result = opaque_client_generate_ke3(
            client, ke2.data(), KE2_SIZE,
            auth_state, ke3, KE3_LENGTH);

        if (ke3_result == static_cast<int>(Result::Success)) {
            uint8_t session_key[HASH_LENGTH];
            uint8_t master_key[MASTER_KEY_LENGTH];
            int finish_result = opaque_server_finish(
                server, ke3, KE3_LENGTH, server_state,
                session_key, HASH_LENGTH,
                master_key, MASTER_KEY_LENGTH);
            REQUIRE(finish_result == static_cast<int>(Result::AuthenticationError));
        } else {
            REQUIRE(ke3_result == static_cast<int>(Result::AuthenticationError));
        }

        opaque_client_state_destroy(auth_state);
        opaque_server_state_destroy(server_state);
        opaque_client_state_destroy(reg_state);
    }

    opaque_client_destroy(client);
    opaque_server_destroy(server);
    opaque_server_keypair_destroy(server_keypair);
}

TEST_CASE("Ecliptix OPAQUE Interop Key APIs", "[opaque][interop][keys]") {
    REQUIRE(sodium_init() >= 0);

    SECTION("Default key APIs follow build configuration") {
#if defined(ECLIPTIX_OPAQUE_ENABLE_INSECURE_TEST_KEYS)
        void* client = nullptr;
        REQUIRE(opaque_client_create_default(&client) == static_cast<int>(Result::Success));
        REQUIRE(client != nullptr);
        opaque_client_destroy(client);

        opaque_server_handle_t* server = nullptr;
        REQUIRE(opaque_server_create_default(&server) == static_cast<int>(Result::Success));
        REQUIRE(server != nullptr);
        opaque_server_destroy(server);
#else
        void* client = reinterpret_cast<void*>(0x1);
        REQUIRE(opaque_client_create_default(&client) == static_cast<int>(Result::InvalidInput));
        REQUIRE(client == nullptr);

        opaque_server_handle_t* server = reinterpret_cast<opaque_server_handle_t*>(0x1);
        REQUIRE(opaque_server_create_default(&server) == static_cast<int>(Result::InvalidInput));
        REQUIRE(server == nullptr);
#endif
    }

    SECTION("Keypair derivation from seed is deterministic") {
        uint8_t seed1[32] = {
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
            0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20
        };
        uint8_t seed2[32] = {
            0x20, 0x1f, 0x1e, 0x1d, 0x1c, 0x1b, 0x1a, 0x19,
            0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11,
            0x10, 0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09,
            0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01
        };

        uint8_t pk1[PUBLIC_KEY_LENGTH];
        uint8_t sk1[PRIVATE_KEY_LENGTH];
        uint8_t pk2[PUBLIC_KEY_LENGTH];
        uint8_t sk2[PRIVATE_KEY_LENGTH];
        uint8_t pk3[PUBLIC_KEY_LENGTH];
        uint8_t sk3[PRIVATE_KEY_LENGTH];

        REQUIRE(opaque_server_derive_keypair_from_seed(
            seed1, sizeof(seed1), sk1, sizeof(sk1), pk1, sizeof(pk1)) == static_cast<int>(Result::Success));
        REQUIRE(opaque_server_derive_keypair_from_seed(
            seed1, sizeof(seed1), sk2, sizeof(sk2), pk2, sizeof(pk2)) == static_cast<int>(Result::Success));
        REQUIRE(std::memcmp(sk1, sk2, PRIVATE_KEY_LENGTH) == 0);
        REQUIRE(std::memcmp(pk1, pk2, PUBLIC_KEY_LENGTH) == 0);

        REQUIRE(opaque_server_derive_keypair_from_seed(
            seed2, sizeof(seed2), sk3, sizeof(sk3), pk3, sizeof(pk3)) == static_cast<int>(Result::Success));
        REQUIRE(std::memcmp(sk1, sk3, PRIVATE_KEY_LENGTH) != 0);
        REQUIRE(std::memcmp(pk1, pk3, PUBLIC_KEY_LENGTH) != 0);
    }

    SECTION("Create server with derived keys succeeds") {
        uint8_t seed[32] = {
            0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
            0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f, 0x50,
            0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58,
            0x59, 0x5a, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35
        };

        uint8_t pk[PUBLIC_KEY_LENGTH];
        uint8_t sk[PRIVATE_KEY_LENGTH];
        REQUIRE(opaque_server_derive_keypair_from_seed(
            seed, sizeof(seed), sk, sizeof(sk), pk, sizeof(pk)) == static_cast<int>(Result::Success));

        opaque_server_handle_t* server = nullptr;
        REQUIRE(opaque_server_create_with_keys(
            sk, sizeof(sk), pk, sizeof(pk), &server) == static_cast<int>(Result::Success));
        REQUIRE(server != nullptr);
        opaque_server_destroy(server);
    }

    SECTION("Create server with mismatched public key fails") {
        uint8_t seed[32] = {
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11,
            0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
            0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
            0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0, 0x01
        };

        uint8_t pk[PUBLIC_KEY_LENGTH];
        uint8_t sk[PRIVATE_KEY_LENGTH];
        REQUIRE(opaque_server_derive_keypair_from_seed(
            seed, sizeof(seed), sk, sizeof(sk), pk, sizeof(pk)) == static_cast<int>(Result::Success));

        uint8_t bad_pk[PUBLIC_KEY_LENGTH];
        std::memcpy(bad_pk, pk, sizeof(bad_pk));
        bad_pk[0] ^= kTamperMask;

        opaque_server_handle_t* server = nullptr;
        int result = opaque_server_create_with_keys(
            sk, sizeof(sk), bad_pk, sizeof(bad_pk), &server);
        REQUIRE(result == static_cast<int>(Result::InvalidPublicKey));
        REQUIRE(server == nullptr);
    }

    SECTION("Keypair derivation rejects invalid inputs") {
        uint8_t seed[1] = {0x01};
        uint8_t pk[PUBLIC_KEY_LENGTH];
        uint8_t sk[PRIVATE_KEY_LENGTH];

        REQUIRE(opaque_server_derive_keypair_from_seed(
            nullptr, sizeof(seed), sk, sizeof(sk), pk, sizeof(pk)) == static_cast<int>(Result::InvalidInput));
        REQUIRE(opaque_server_derive_keypair_from_seed(
            seed, 0, sk, sizeof(sk), pk, sizeof(pk)) == static_cast<int>(Result::InvalidInput));
        REQUIRE(opaque_server_derive_keypair_from_seed(
            seed, sizeof(seed), sk, sizeof(sk) - 1, pk, sizeof(pk)) == static_cast<int>(Result::InvalidInput));
        REQUIRE(opaque_server_derive_keypair_from_seed(
            seed, sizeof(seed), sk, sizeof(sk), pk, sizeof(pk) - 1) == static_cast<int>(Result::InvalidInput));
    }
}

TEST_CASE("ML-KEM-768 Unit Tests", "[opaque][pq][kem]") {
    REQUIRE(sodium_init() >= 0);

    SECTION("ML-KEM-768 keypair generation") {
        uint8_t public_key[pq_constants::KEM_PUBLIC_KEY_LENGTH];
        uint8_t secret_key[pq_constants::KEM_SECRET_KEY_LENGTH];

        Result result = pq::kem::keypair_generate(public_key, secret_key);
        REQUIRE(result == Result::Success);

        bool pk_nonzero = false, sk_nonzero = false;
        for (size_t i = 0; i < pq_constants::KEM_PUBLIC_KEY_LENGTH; ++i) {
            if (public_key[i] != 0) { pk_nonzero = true; break; }
        }
        for (size_t i = 0; i < pq_constants::KEM_SECRET_KEY_LENGTH; ++i) {
            if (secret_key[i] != 0) { sk_nonzero = true; break; }
        }
        REQUIRE(pk_nonzero);
        REQUIRE(sk_nonzero);

        sodium_memzero(secret_key, sizeof(secret_key));
    }

    SECTION("ML-KEM-768 encapsulation and decapsulation") {
        uint8_t public_key[pq_constants::KEM_PUBLIC_KEY_LENGTH];
        uint8_t secret_key[pq_constants::KEM_SECRET_KEY_LENGTH];
        REQUIRE(pq::kem::keypair_generate(public_key, secret_key) == Result::Success);

        uint8_t ciphertext[pq_constants::KEM_CIPHERTEXT_LENGTH];
        uint8_t shared_secret_enc[pq_constants::KEM_SHARED_SECRET_LENGTH];
        REQUIRE(pq::kem::encapsulate(public_key, ciphertext, shared_secret_enc) == Result::Success);

        uint8_t shared_secret_dec[pq_constants::KEM_SHARED_SECRET_LENGTH];
        REQUIRE(pq::kem::decapsulate(secret_key, ciphertext, shared_secret_dec) == Result::Success);

        REQUIRE(std::memcmp(shared_secret_enc, shared_secret_dec, pq_constants::KEM_SHARED_SECRET_LENGTH) == 0);

        sodium_memzero(secret_key, sizeof(secret_key));
        sodium_memzero(shared_secret_enc, sizeof(shared_secret_enc));
        sodium_memzero(shared_secret_dec, sizeof(shared_secret_dec));
    }

    SECTION("ML-KEM-768 decapsulation fails with tampered ciphertext") {
        uint8_t public_key[pq_constants::KEM_PUBLIC_KEY_LENGTH];
        uint8_t secret_key[pq_constants::KEM_SECRET_KEY_LENGTH];
        REQUIRE(pq::kem::keypair_generate(public_key, secret_key) == Result::Success);

        uint8_t ciphertext[pq_constants::KEM_CIPHERTEXT_LENGTH];
        uint8_t shared_secret_enc[pq_constants::KEM_SHARED_SECRET_LENGTH];
        REQUIRE(pq::kem::encapsulate(public_key, ciphertext, shared_secret_enc) == Result::Success);

        ciphertext[0] ^= 0x01;

        uint8_t shared_secret_dec[pq_constants::KEM_SHARED_SECRET_LENGTH];

        Result result = pq::kem::decapsulate(secret_key, ciphertext, shared_secret_dec);
        if (result == Result::Success) {

            REQUIRE(std::memcmp(shared_secret_enc, shared_secret_dec, pq_constants::KEM_SHARED_SECRET_LENGTH) != 0);
        }

        sodium_memzero(secret_key, sizeof(secret_key));
        sodium_memzero(shared_secret_enc, sizeof(shared_secret_enc));
        sodium_memzero(shared_secret_dec, sizeof(shared_secret_dec));
    }
}

TEST_CASE("PQ Key Combiner Test", "[opaque][pq][combiner]") {
    REQUIRE(sodium_init() >= 0);

    uint8_t classical_ikm[96];
    uint8_t pq_shared_secret[pq_constants::KEM_SHARED_SECRET_LENGTH];
    uint8_t transcript_hash[crypto_hash_sha512_BYTES];
    randombytes_buf(classical_ikm, sizeof(classical_ikm));
    randombytes_buf(pq_shared_secret, sizeof(pq_shared_secret));
    randombytes_buf(transcript_hash, sizeof(transcript_hash));

    uint8_t output1[crypto_auth_hmacsha512_BYTES];
    uint8_t output2[crypto_auth_hmacsha512_BYTES];

    Result result1 = pq::combine_key_material(classical_ikm, sizeof(classical_ikm),
                                               pq_shared_secret, sizeof(pq_shared_secret),
                                               transcript_hash, sizeof(transcript_hash),
                                               output1);
    Result result2 = pq::combine_key_material(classical_ikm, sizeof(classical_ikm),
                                               pq_shared_secret, sizeof(pq_shared_secret),
                                               transcript_hash, sizeof(transcript_hash),
                                               output2);
    REQUIRE(result1 == Result::Success);
    REQUIRE(result2 == Result::Success);
    REQUIRE(std::memcmp(output1, output2, sizeof(output1)) == 0);

    pq_shared_secret[0] ^= 0x01;
    Result result3 = pq::combine_key_material(classical_ikm, sizeof(classical_ikm),
                                               pq_shared_secret, sizeof(pq_shared_secret),
                                               transcript_hash, sizeof(transcript_hash),
                                               output2);
    REQUIRE(result3 == Result::Success);
    REQUIRE(std::memcmp(output1, output2, sizeof(output1)) != 0);
}

TEST_CASE("PQ OPAQUE Protocol Complete Flow", "[opaque][pq][protocol]") {
    REQUIRE(sodium_init() >= 0);

    const char* secure_key = kSecureKey;

    REQUIRE(opaque_get_ke1_length() == KE1_SIZE);
    REQUIRE(opaque_get_ke2_length() == KE2_SIZE);
    REQUIRE(opaque_get_registration_record_length() == RECORD_SIZE);

    server_keypair_handle_t* server_keypair = nullptr;
    REQUIRE(opaque_server_keypair_generate(&server_keypair) == static_cast<int>(Result::Success));

    uint8_t server_public_key[PUBLIC_KEY_LENGTH];
    REQUIRE(opaque_server_keypair_get_public_key(server_keypair, server_public_key, PUBLIC_KEY_LENGTH) == static_cast<int>(Result::Success));

    opaque_server_handle_t* server = nullptr;
    REQUIRE(opaque_server_create(server_keypair, &server) == static_cast<int>(Result::Success));

    void* client = nullptr;
    REQUIRE(opaque_client_create(server_public_key, PUBLIC_KEY_LENGTH, &client) == static_cast<int>(Result::Success));

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

    std::vector<uint8_t> pq_registration_record(RECORD_SIZE);
    REQUIRE(opaque_client_finalize_registration(
        client, registration_response, REGISTRATION_RESPONSE_LENGTH,
        client_state, pq_registration_record.data(),
        RECORD_SIZE) == static_cast<int>(Result::Success));

    std::vector<uint8_t> pq_credentials(CREDENTIALS_SIZE);
    REQUIRE(opaque_server_build_credentials(
        pq_registration_record.data(), RECORD_SIZE,
        pq_credentials.data(), CREDENTIALS_SIZE) == static_cast<int>(Result::Success));

    opaque_client_state_destroy(client_state);

    SECTION("PQ authentication with correct secure key") {
        void* auth_client_state = nullptr;
        REQUIRE(opaque_client_state_create(&auth_client_state) == static_cast<int>(Result::Success));

        server_state_handle_t* server_state = nullptr;
        REQUIRE(opaque_server_state_create(&server_state) == static_cast<int>(Result::Success));

        std::vector<uint8_t> pq_ke1(KE1_SIZE);
        REQUIRE(opaque_client_generate_ke1(
            client, reinterpret_cast<const uint8_t*>(secure_key), strlen(secure_key),
            auth_client_state, pq_ke1.data(),
            KE1_SIZE) == static_cast<int>(Result::Success));

        std::vector<uint8_t> pq_ke2(KE2_SIZE);
        REQUIRE(opaque_server_generate_ke2(
            server, pq_ke1.data(), KE1_SIZE,
            kAccountId, sizeof(kAccountId),
            pq_credentials.data(), CREDENTIALS_SIZE,
            pq_ke2.data(), KE2_SIZE,
            server_state) == static_cast<int>(Result::Success));

        uint8_t ke3[KE3_LENGTH];
        REQUIRE(opaque_client_generate_ke3(
            client, pq_ke2.data(), KE2_SIZE,
            auth_client_state, ke3, KE3_LENGTH) == static_cast<int>(Result::Success));

        uint8_t server_session_key[HASH_LENGTH];
        uint8_t server_master_key[MASTER_KEY_LENGTH];
        REQUIRE(opaque_server_finish(
            server, ke3, KE3_LENGTH, server_state,
            server_session_key, HASH_LENGTH,
            server_master_key, MASTER_KEY_LENGTH) == static_cast<int>(Result::Success));

        uint8_t client_session_key[HASH_LENGTH];
        uint8_t client_master_key[MASTER_KEY_LENGTH];
        REQUIRE(opaque_client_finish(
            client, auth_client_state,
            client_session_key, HASH_LENGTH,
            client_master_key, MASTER_KEY_LENGTH) == static_cast<int>(Result::Success));

        REQUIRE(std::memcmp(client_session_key, server_session_key, HASH_LENGTH) == 0);
        REQUIRE(std::memcmp(client_master_key, server_master_key, MASTER_KEY_LENGTH) == 0);

        opaque_client_state_destroy(auth_client_state);
        opaque_server_state_destroy(server_state);
    }

    SECTION("PQ authentication with wrong secure key fails") {
        void* auth_client_state = nullptr;
        REQUIRE(opaque_client_state_create(&auth_client_state) == static_cast<int>(Result::Success));

        server_state_handle_t* server_state = nullptr;
        REQUIRE(opaque_server_state_create(&server_state) == static_cast<int>(Result::Success));

        const char* invalid_secure_key = kInvalidSecureKey;
        std::vector<uint8_t> pq_ke1(KE1_SIZE);
        REQUIRE(opaque_client_generate_ke1(
            client, reinterpret_cast<const uint8_t*>(invalid_secure_key), strlen(invalid_secure_key),
            auth_client_state, pq_ke1.data(),
            KE1_SIZE) == static_cast<int>(Result::Success));

        std::vector<uint8_t> pq_ke2(KE2_SIZE);
        REQUIRE(opaque_server_generate_ke2(
            server, pq_ke1.data(), KE1_SIZE,
            kAccountId, sizeof(kAccountId),
            pq_credentials.data(), CREDENTIALS_SIZE,
            pq_ke2.data(), KE2_SIZE,
            server_state) == static_cast<int>(Result::Success));

        uint8_t ke3[KE3_LENGTH];
        int result = opaque_client_generate_ke3(
            client, pq_ke2.data(), KE2_SIZE,
            auth_client_state, ke3, KE3_LENGTH);

        if (result == static_cast<int>(Result::Success)) {
            uint8_t server_session_key[HASH_LENGTH];
            uint8_t server_master_key[MASTER_KEY_LENGTH];
            int finish_result = opaque_server_finish(
                server, ke3, KE3_LENGTH, server_state,
                server_session_key, HASH_LENGTH,
                server_master_key, MASTER_KEY_LENGTH);
            ExpectAuthError(finish_result, "pq wrong password: server finish");
        } else {
            ExpectAuthError(result, "pq wrong password: client generate ke3");
        }

        opaque_client_state_destroy(auth_client_state);
        opaque_server_state_destroy(server_state);
    }

    SECTION("PQ authentication fails with tampered KE2 KEM ciphertext") {
        void* auth_client_state = nullptr;
        REQUIRE(opaque_client_state_create(&auth_client_state) == static_cast<int>(Result::Success));

        server_state_handle_t* server_state = nullptr;
        REQUIRE(opaque_server_state_create(&server_state) == static_cast<int>(Result::Success));

        std::vector<uint8_t> pq_ke1(KE1_SIZE);
        REQUIRE(opaque_client_generate_ke1(
            client, reinterpret_cast<const uint8_t*>(secure_key), strlen(secure_key),
            auth_client_state, pq_ke1.data(),
            KE1_SIZE) == static_cast<int>(Result::Success));

        std::vector<uint8_t> pq_ke2(KE2_SIZE);
        REQUIRE(opaque_server_generate_ke2(
            server, pq_ke1.data(), KE1_SIZE,
            kAccountId, sizeof(kAccountId),
            pq_credentials.data(), CREDENTIALS_SIZE,
            pq_ke2.data(), KE2_SIZE,
            server_state) == static_cast<int>(Result::Success));

        size_t kem_ct_offset = KE2_SIZE - pq_constants::KEM_CIPHERTEXT_LENGTH;
        pq_ke2[kem_ct_offset] ^= 0x01;

        uint8_t ke3[KE3_LENGTH];
        int result = opaque_client_generate_ke3(
            client, pq_ke2.data(), KE2_SIZE,
            auth_client_state, ke3, KE3_LENGTH);

        REQUIRE(result == static_cast<int>(Result::AuthenticationError));

        opaque_client_state_destroy(auth_client_state);
        opaque_server_state_destroy(server_state);
    }

    opaque_client_destroy(client);
    opaque_server_destroy(server);
    opaque_server_keypair_destroy(server_keypair);
}

TEST_CASE("PQ OPAQUE C++ Client/Server Simulation", "[opaque][pq][cpp][protocol]") {
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

    RegistrationRecord pq_record;
    REQUIRE(client.finalize_registration(
        registration_response.data.data(), registration_response.data.size(),
        registration_state, pq_record) == Result::Success);

    REQUIRE(pq_record.envelope.size() == ENVELOPE_LENGTH);
    REQUIRE(pq_record.initiator_public_key.size() == PUBLIC_KEY_LENGTH);

    secure_bytes pq_record_buffer;
    REQUIRE(BuildRegistrationRecordBuffer(pq_record, pq_record_buffer) == Result::Success);

    ResponderCredentials pq_credentials;
    REQUIRE(build_credentials(
        pq_record_buffer.data(), pq_record_buffer.size(),
        pq_credentials) == Result::Success);

    SECTION("PQ C++ simulation happy path") {
        InitiatorState auth_state;
        KE1 ke1;
        REQUIRE(OpaqueInitiator::generate_ke1(
            reinterpret_cast<const uint8_t*>(secure_key), strlen(secure_key),
            ke1, auth_state) == Result::Success);

        REQUIRE(auth_state.pq_ephemeral_public_key.size() == pq_constants::KEM_PUBLIC_KEY_LENGTH);
        REQUIRE(auth_state.pq_ephemeral_secret_key.size() == pq_constants::KEM_SECRET_KEY_LENGTH);
        REQUIRE(ke1.pq_ephemeral_public_key.size() == pq_constants::KEM_PUBLIC_KEY_LENGTH);

        secure_bytes ke1_data;
        REQUIRE(BuildKe1Data(ke1, ke1_data) == Result::Success);

        ResponderState server_state;
        KE2 ke2;
        REQUIRE(server.generate_ke2(
            ke1_data.data(), ke1_data.size(),
            kAccountId, sizeof(kAccountId),
            pq_credentials, ke2, server_state) == Result::Success);

        REQUIRE(ke2.kem_ciphertext.size() == pq_constants::KEM_CIPHERTEXT_LENGTH);
        REQUIRE(server_state.pq_shared_secret.size() == pq_constants::KEM_SHARED_SECRET_LENGTH);

        secure_bytes ke2_data;
        REQUIRE(BuildKe2Data(ke2, ke2_data) == Result::Success);

        KE3 ke3;
        REQUIRE(client.generate_ke3(
            ke2_data.data(), ke2_data.size(),
            auth_state, ke3) == Result::Success);

        REQUIRE(auth_state.pq_shared_secret.size() == pq_constants::KEM_SHARED_SECRET_LENGTH);

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
    }

    SECTION("PQ C++ simulation fails with wrong secure key") {
        const char* invalid_secure_key = kSimInvalidSecureKey;
        InitiatorState auth_state;
        KE1 ke1;
        REQUIRE(OpaqueInitiator::generate_ke1(
            reinterpret_cast<const uint8_t*>(invalid_secure_key), strlen(invalid_secure_key),
            ke1, auth_state) == Result::Success);

        secure_bytes ke1_data;
        REQUIRE(BuildKe1Data(ke1, ke1_data) == Result::Success);

        ResponderState server_state;
        KE2 ke2;
        REQUIRE(server.generate_ke2(
            ke1_data.data(), ke1_data.size(),
            kAccountId, sizeof(kAccountId),
            pq_credentials, ke2, server_state) == Result::Success);

        secure_bytes ke2_data;
        REQUIRE(BuildKe2Data(ke2, ke2_data) == Result::Success);

        KE3 ke3;
        INFO("Expected AuthenticationError for wrong password in pq mode");
        REQUIRE(client.generate_ke3(
            ke2_data.data(), ke2_data.size(),
            auth_state, ke3) == Result::AuthenticationError);
    }
}

TEST_CASE("ML-KEM-768 Advanced Unit Tests", "[opaque][pq][kem][unit]") {
    REQUIRE(sodium_init() >= 0);

    SECTION("Multiple keypair generation produces different keys") {
        uint8_t pk1[pq_constants::KEM_PUBLIC_KEY_LENGTH];
        uint8_t sk1[pq_constants::KEM_SECRET_KEY_LENGTH];
        uint8_t pk2[pq_constants::KEM_PUBLIC_KEY_LENGTH];
        uint8_t sk2[pq_constants::KEM_SECRET_KEY_LENGTH];

        REQUIRE(pq::kem::keypair_generate(pk1, sk1) == Result::Success);
        REQUIRE(pq::kem::keypair_generate(pk2, sk2) == Result::Success);

        REQUIRE(std::memcmp(pk1, pk2, pq_constants::KEM_PUBLIC_KEY_LENGTH) != 0);
        REQUIRE(std::memcmp(sk1, sk2, pq_constants::KEM_SECRET_KEY_LENGTH) != 0);

        sodium_memzero(sk1, sizeof(sk1));
        sodium_memzero(sk2, sizeof(sk2));
    }

    SECTION("Encapsulation with same public key produces different ciphertexts") {
        uint8_t pk[pq_constants::KEM_PUBLIC_KEY_LENGTH];
        uint8_t sk[pq_constants::KEM_SECRET_KEY_LENGTH];
        REQUIRE(pq::kem::keypair_generate(pk, sk) == Result::Success);

        uint8_t ct1[pq_constants::KEM_CIPHERTEXT_LENGTH];
        uint8_t ss1[pq_constants::KEM_SHARED_SECRET_LENGTH];
        uint8_t ct2[pq_constants::KEM_CIPHERTEXT_LENGTH];
        uint8_t ss2[pq_constants::KEM_SHARED_SECRET_LENGTH];

        REQUIRE(pq::kem::encapsulate(pk, ct1, ss1) == Result::Success);
        REQUIRE(pq::kem::encapsulate(pk, ct2, ss2) == Result::Success);

        REQUIRE(std::memcmp(ct1, ct2, pq_constants::KEM_CIPHERTEXT_LENGTH) != 0);

        REQUIRE(std::memcmp(ss1, ss2, pq_constants::KEM_SHARED_SECRET_LENGTH) != 0);

        uint8_t ss1_dec[pq_constants::KEM_SHARED_SECRET_LENGTH];
        uint8_t ss2_dec[pq_constants::KEM_SHARED_SECRET_LENGTH];
        REQUIRE(pq::kem::decapsulate(sk, ct1, ss1_dec) == Result::Success);
        REQUIRE(pq::kem::decapsulate(sk, ct2, ss2_dec) == Result::Success);
        REQUIRE(std::memcmp(ss1, ss1_dec, pq_constants::KEM_SHARED_SECRET_LENGTH) == 0);
        REQUIRE(std::memcmp(ss2, ss2_dec, pq_constants::KEM_SHARED_SECRET_LENGTH) == 0);

        sodium_memzero(sk, sizeof(sk));
    }

    SECTION("Decapsulation with wrong secret key produces different shared secret") {
        uint8_t pk1[pq_constants::KEM_PUBLIC_KEY_LENGTH];
        uint8_t sk1[pq_constants::KEM_SECRET_KEY_LENGTH];
        uint8_t pk2[pq_constants::KEM_PUBLIC_KEY_LENGTH];
        uint8_t sk2[pq_constants::KEM_SECRET_KEY_LENGTH];

        REQUIRE(pq::kem::keypair_generate(pk1, sk1) == Result::Success);
        REQUIRE(pq::kem::keypair_generate(pk2, sk2) == Result::Success);

        uint8_t ct[pq_constants::KEM_CIPHERTEXT_LENGTH];
        uint8_t ss_enc[pq_constants::KEM_SHARED_SECRET_LENGTH];
        REQUIRE(pq::kem::encapsulate(pk1, ct, ss_enc) == Result::Success);

        uint8_t ss_dec[pq_constants::KEM_SHARED_SECRET_LENGTH];
        Result result = pq::kem::decapsulate(sk2, ct, ss_dec);
        if (result == Result::Success) {

            REQUIRE(std::memcmp(ss_enc, ss_dec, pq_constants::KEM_SHARED_SECRET_LENGTH) != 0);
        }

        sodium_memzero(sk1, sizeof(sk1));
        sodium_memzero(sk2, sizeof(sk2));
    }

    SECTION("Tampering at different ciphertext positions") {
        uint8_t pk[pq_constants::KEM_PUBLIC_KEY_LENGTH];
        uint8_t sk[pq_constants::KEM_SECRET_KEY_LENGTH];
        REQUIRE(pq::kem::keypair_generate(pk, sk) == Result::Success);

        uint8_t ct[pq_constants::KEM_CIPHERTEXT_LENGTH];
        uint8_t ss_enc[pq_constants::KEM_SHARED_SECRET_LENGTH];
        REQUIRE(pq::kem::encapsulate(pk, ct, ss_enc) == Result::Success);

        const size_t positions[] = {0, 100, 500, pq_constants::KEM_CIPHERTEXT_LENGTH / 2,
                                     pq_constants::KEM_CIPHERTEXT_LENGTH - 1};

        for (size_t pos : positions) {
            uint8_t ct_tampered[pq_constants::KEM_CIPHERTEXT_LENGTH];
            std::memcpy(ct_tampered, ct, pq_constants::KEM_CIPHERTEXT_LENGTH);
            ct_tampered[pos] ^= 0xFF;

            uint8_t ss_dec[pq_constants::KEM_SHARED_SECRET_LENGTH];
            Result result = pq::kem::decapsulate(sk, ct_tampered, ss_dec);
            if (result == Result::Success) {
                INFO("Tamper position: " << pos);
                REQUIRE(std::memcmp(ss_enc, ss_dec, pq_constants::KEM_SHARED_SECRET_LENGTH) != 0);
            }
        }

        sodium_memzero(sk, sizeof(sk));
    }
}

TEST_CASE("PQ Key Combiner Advanced Tests", "[opaque][pq][combiner][unit]") {
    REQUIRE(sodium_init() >= 0);

    SECTION("Key combiner produces valid PRK output") {
        uint8_t classical_ikm[96];
        uint8_t pq_ss[pq_constants::KEM_SHARED_SECRET_LENGTH];
        uint8_t transcript_hash[crypto_hash_sha512_BYTES];
        randombytes_buf(classical_ikm, sizeof(classical_ikm));
        randombytes_buf(pq_ss, sizeof(pq_ss));
        randombytes_buf(transcript_hash, sizeof(transcript_hash));

        uint8_t prk[crypto_auth_hmacsha512_BYTES];
        Result result = pq::combine_key_material(classical_ikm, sizeof(classical_ikm),
                                                  pq_ss, sizeof(pq_ss),
                                                  transcript_hash, sizeof(transcript_hash),
                                                  prk);
        REQUIRE(result == Result::Success);

        bool nonzero = false;
        for (size_t i = 0; i < sizeof(prk); ++i) {
            if (prk[i] != 0) { nonzero = true; break; }
        }
        REQUIRE(nonzero);
    }

    SECTION("Key combiner is deterministic") {
        uint8_t classical_ikm[96];
        uint8_t pq_ss[pq_constants::KEM_SHARED_SECRET_LENGTH];
        uint8_t transcript_hash[crypto_hash_sha512_BYTES];
        randombytes_buf(classical_ikm, sizeof(classical_ikm));
        randombytes_buf(pq_ss, sizeof(pq_ss));
        randombytes_buf(transcript_hash, sizeof(transcript_hash));

        uint8_t output1[crypto_auth_hmacsha512_BYTES];
        uint8_t output2[crypto_auth_hmacsha512_BYTES];
        uint8_t output3[crypto_auth_hmacsha512_BYTES];

        REQUIRE(pq::combine_key_material(classical_ikm, sizeof(classical_ikm),
                                          pq_ss, sizeof(pq_ss),
                                          transcript_hash, sizeof(transcript_hash),
                                          output1) == Result::Success);
        REQUIRE(pq::combine_key_material(classical_ikm, sizeof(classical_ikm),
                                          pq_ss, sizeof(pq_ss),
                                          transcript_hash, sizeof(transcript_hash),
                                          output2) == Result::Success);
        REQUIRE(pq::combine_key_material(classical_ikm, sizeof(classical_ikm),
                                          pq_ss, sizeof(pq_ss),
                                          transcript_hash, sizeof(transcript_hash),
                                          output3) == Result::Success);

        REQUIRE(std::memcmp(output1, output2, sizeof(output1)) == 0);
        REQUIRE(std::memcmp(output2, output3, sizeof(output2)) == 0);
    }

    SECTION("Key combiner sensitive to classical IKM changes") {
        uint8_t classical_ikm[96];
        uint8_t pq_ss[pq_constants::KEM_SHARED_SECRET_LENGTH];
        uint8_t transcript_hash[crypto_hash_sha512_BYTES];
        randombytes_buf(classical_ikm, sizeof(classical_ikm));
        randombytes_buf(pq_ss, sizeof(pq_ss));
        randombytes_buf(transcript_hash, sizeof(transcript_hash));

        uint8_t output1[crypto_auth_hmacsha512_BYTES];
        uint8_t output2[crypto_auth_hmacsha512_BYTES];

        REQUIRE(pq::combine_key_material(classical_ikm, sizeof(classical_ikm),
                                          pq_ss, sizeof(pq_ss),
                                          transcript_hash, sizeof(transcript_hash),
                                          output1) == Result::Success);

        classical_ikm[47] ^= 0x01;
        REQUIRE(pq::combine_key_material(classical_ikm, sizeof(classical_ikm),
                                          pq_ss, sizeof(pq_ss),
                                          transcript_hash, sizeof(transcript_hash),
                                          output2) == Result::Success);

        REQUIRE(std::memcmp(output1, output2, sizeof(output1)) != 0);
    }

    SECTION("Key combiner sensitive to PQ shared secret changes") {
        uint8_t classical_ikm[96];
        uint8_t pq_ss[pq_constants::KEM_SHARED_SECRET_LENGTH];
        uint8_t transcript_hash[crypto_hash_sha512_BYTES];
        randombytes_buf(classical_ikm, sizeof(classical_ikm));
        randombytes_buf(pq_ss, sizeof(pq_ss));
        randombytes_buf(transcript_hash, sizeof(transcript_hash));

        uint8_t output1[crypto_auth_hmacsha512_BYTES];
        uint8_t output2[crypto_auth_hmacsha512_BYTES];

        REQUIRE(pq::combine_key_material(classical_ikm, sizeof(classical_ikm),
                                          pq_ss, sizeof(pq_ss),
                                          transcript_hash, sizeof(transcript_hash),
                                          output1) == Result::Success);

        pq_ss[15] ^= 0x01;
        REQUIRE(pq::combine_key_material(classical_ikm, sizeof(classical_ikm),
                                          pq_ss, sizeof(pq_ss),
                                          transcript_hash, sizeof(transcript_hash),
                                          output2) == Result::Success);

        REQUIRE(std::memcmp(output1, output2, sizeof(output1)) != 0);
    }

    SECTION("Key combiner sensitive to transcript hash changes") {
        uint8_t classical_ikm[96];
        uint8_t pq_ss[pq_constants::KEM_SHARED_SECRET_LENGTH];
        uint8_t transcript_hash[crypto_hash_sha512_BYTES];
        randombytes_buf(classical_ikm, sizeof(classical_ikm));
        randombytes_buf(pq_ss, sizeof(pq_ss));
        randombytes_buf(transcript_hash, sizeof(transcript_hash));

        uint8_t output1[crypto_auth_hmacsha512_BYTES];
        uint8_t output2[crypto_auth_hmacsha512_BYTES];

        REQUIRE(pq::combine_key_material(classical_ikm, sizeof(classical_ikm),
                                          pq_ss, sizeof(pq_ss),
                                          transcript_hash, sizeof(transcript_hash),
                                          output1) == Result::Success);

        transcript_hash[31] ^= 0x01;
        REQUIRE(pq::combine_key_material(classical_ikm, sizeof(classical_ikm),
                                          pq_ss, sizeof(pq_ss),
                                          transcript_hash, sizeof(transcript_hash),
                                          output2) == Result::Success);

        REQUIRE(std::memcmp(output1, output2, sizeof(output1)) != 0);
    }
}

TEST_CASE("PQ Size Constants Verification", "[opaque][pq][constants]") {
    REQUIRE(sodium_init() >= 0);

    SECTION("C API size query functions match Kyber-enabled constants") {
        REQUIRE(opaque_get_ke1_length() == KE1_LENGTH);
        REQUIRE(opaque_get_ke2_length() == KE2_LENGTH);
        REQUIRE(opaque_get_registration_record_length() == REGISTRATION_RECORD_LENGTH);
        REQUIRE(opaque_get_kem_public_key_length() == pq_constants::KEM_PUBLIC_KEY_LENGTH);
        REQUIRE(opaque_get_kem_ciphertext_length() == pq_constants::KEM_CIPHERTEXT_LENGTH);
    }

    SECTION("Kyber-enabled sizes are correctly calculated") {
        REQUIRE(KE1_LENGTH == REGISTRATION_REQUEST_LENGTH + PUBLIC_KEY_LENGTH + NONCE_LENGTH +
                              pq_constants::KEM_PUBLIC_KEY_LENGTH);
        REQUIRE(KE2_LENGTH == NONCE_LENGTH + PUBLIC_KEY_LENGTH + CREDENTIAL_RESPONSE_LENGTH +
                              MAC_LENGTH + pq_constants::KEM_CIPHERTEXT_LENGTH);
        REQUIRE(KE3_LENGTH == MAC_LENGTH);
        REQUIRE(REGISTRATION_RECORD_LENGTH == ENVELOPE_LENGTH + PUBLIC_KEY_LENGTH);
        REQUIRE(pq_constants::COMBINED_IKM_LENGTH == 96 + pq_constants::KEM_SHARED_SECRET_LENGTH);
    }

    SECTION("ML-KEM-768 constants are correct") {
        REQUIRE(pq_constants::KEM_PUBLIC_KEY_LENGTH == 1184);
        REQUIRE(pq_constants::KEM_SECRET_KEY_LENGTH == 2400);
        REQUIRE(pq_constants::KEM_CIPHERTEXT_LENGTH == 1088);
        REQUIRE(pq_constants::KEM_SHARED_SECRET_LENGTH == 32);
    }
}

TEST_CASE("PQ Authentication Tampering Tests", "[opaque][pq][integration][tampering]") {
    REQUIRE(sodium_init() >= 0);

    const char* secure_key = kSecureKey;

    server_keypair_handle_t* server_keypair = nullptr;
    REQUIRE(opaque_server_keypair_generate(&server_keypair) == static_cast<int>(Result::Success));

    uint8_t server_public_key[PUBLIC_KEY_LENGTH];
    REQUIRE(opaque_server_keypair_get_public_key(server_keypair, server_public_key, PUBLIC_KEY_LENGTH) == static_cast<int>(Result::Success));

    opaque_server_handle_t* server = nullptr;
    REQUIRE(opaque_server_create(server_keypair, &server) == static_cast<int>(Result::Success));

    void* client = nullptr;
    REQUIRE(opaque_client_create(server_public_key, PUBLIC_KEY_LENGTH, &client) == static_cast<int>(Result::Success));

    void* reg_state = nullptr;
    REQUIRE(opaque_client_state_create(&reg_state) == static_cast<int>(Result::Success));

    uint8_t reg_request[REGISTRATION_REQUEST_LENGTH];
    REQUIRE(opaque_client_create_registration_request(
        client, reinterpret_cast<const uint8_t*>(secure_key), strlen(secure_key),
        reg_state, reg_request, REGISTRATION_REQUEST_LENGTH) == static_cast<int>(Result::Success));

    uint8_t reg_response[REGISTRATION_RESPONSE_LENGTH];
    REQUIRE(opaque_server_create_registration_response(
        server, reg_request, REGISTRATION_REQUEST_LENGTH,
        kAccountId, sizeof(kAccountId),
        reg_response, REGISTRATION_RESPONSE_LENGTH) == static_cast<int>(Result::Success));

    std::vector<uint8_t> pq_record(RECORD_SIZE);
    REQUIRE(opaque_client_finalize_registration(
        client, reg_response, REGISTRATION_RESPONSE_LENGTH,
        reg_state, pq_record.data(),
        RECORD_SIZE) == static_cast<int>(Result::Success));

    std::vector<uint8_t> pq_creds(CREDENTIALS_SIZE);
    REQUIRE(opaque_server_build_credentials(
        pq_record.data(), RECORD_SIZE,
        pq_creds.data(), CREDENTIALS_SIZE) == static_cast<int>(Result::Success));

    opaque_client_state_destroy(reg_state);

    SECTION("Tampered KE2 server MAC fails authentication") {
        void* auth_state = nullptr;
        REQUIRE(opaque_client_state_create(&auth_state) == static_cast<int>(Result::Success));

        server_state_handle_t* srv_state = nullptr;
        REQUIRE(opaque_server_state_create(&srv_state) == static_cast<int>(Result::Success));

        std::vector<uint8_t> ke1(KE1_SIZE);
        REQUIRE(opaque_client_generate_ke1(
            client, reinterpret_cast<const uint8_t*>(secure_key), strlen(secure_key),
            auth_state, ke1.data(), KE1_SIZE) == static_cast<int>(Result::Success));

        std::vector<uint8_t> ke2(KE2_SIZE);
        REQUIRE(opaque_server_generate_ke2(
            server, ke1.data(), KE1_SIZE,
            kAccountId, sizeof(kAccountId),
            pq_creds.data(), CREDENTIALS_SIZE,
            ke2.data(), KE2_SIZE, srv_state) == static_cast<int>(Result::Success));

        size_t mac_offset = NONCE_LENGTH + PUBLIC_KEY_LENGTH + CREDENTIAL_RESPONSE_LENGTH;
        ke2[mac_offset] ^= 0x01;

        uint8_t ke3[KE3_LENGTH];
        int result = opaque_client_generate_ke3(
            client, ke2.data(), KE2_SIZE,
            auth_state, ke3, KE3_LENGTH);

        REQUIRE(result == static_cast<int>(Result::AuthenticationError));

        opaque_client_state_destroy(auth_state);
        opaque_server_state_destroy(srv_state);
    }

    SECTION("Tampered KE2 responder nonce fails authentication") {
        void* auth_state = nullptr;
        REQUIRE(opaque_client_state_create(&auth_state) == static_cast<int>(Result::Success));

        server_state_handle_t* srv_state = nullptr;
        REQUIRE(opaque_server_state_create(&srv_state) == static_cast<int>(Result::Success));

        std::vector<uint8_t> ke1(KE1_SIZE);
        REQUIRE(opaque_client_generate_ke1(
            client, reinterpret_cast<const uint8_t*>(secure_key), strlen(secure_key),
            auth_state, ke1.data(), KE1_SIZE) == static_cast<int>(Result::Success));

        std::vector<uint8_t> ke2(KE2_SIZE);
        REQUIRE(opaque_server_generate_ke2(
            server, ke1.data(), KE1_SIZE,
            kAccountId, sizeof(kAccountId),
            pq_creds.data(), CREDENTIALS_SIZE,
            ke2.data(), KE2_SIZE, srv_state) == static_cast<int>(Result::Success));

        ke2[0] ^= 0x01;

        uint8_t ke3[KE3_LENGTH];
        int result = opaque_client_generate_ke3(
            client, ke2.data(), KE2_SIZE,
            auth_state, ke3, KE3_LENGTH);

        REQUIRE(result == static_cast<int>(Result::AuthenticationError));

        opaque_client_state_destroy(auth_state);
        opaque_server_state_destroy(srv_state);
    }

    SECTION("Tampered KE2 responder public key fails authentication") {
        void* auth_state = nullptr;
        REQUIRE(opaque_client_state_create(&auth_state) == static_cast<int>(Result::Success));

        server_state_handle_t* srv_state = nullptr;
        REQUIRE(opaque_server_state_create(&srv_state) == static_cast<int>(Result::Success));

        std::vector<uint8_t> ke1(KE1_SIZE);
        REQUIRE(opaque_client_generate_ke1(
            client, reinterpret_cast<const uint8_t*>(secure_key), strlen(secure_key),
            auth_state, ke1.data(), KE1_SIZE) == static_cast<int>(Result::Success));

        std::vector<uint8_t> ke2(KE2_SIZE);
        REQUIRE(opaque_server_generate_ke2(
            server, ke1.data(), KE1_SIZE,
            kAccountId, sizeof(kAccountId),
            pq_creds.data(), CREDENTIALS_SIZE,
            ke2.data(), KE2_SIZE, srv_state) == static_cast<int>(Result::Success));

        ke2[NONCE_LENGTH + 5] ^= 0x01;

        uint8_t ke3[KE3_LENGTH];
        int result = opaque_client_generate_ke3(
            client, ke2.data(), KE2_SIZE,
            auth_state, ke3, KE3_LENGTH);

        REQUIRE((result == static_cast<int>(Result::AuthenticationError) ||
                 result == static_cast<int>(Result::InvalidPublicKey)));

        opaque_client_state_destroy(auth_state);
        opaque_server_state_destroy(srv_state);
    }

    SECTION("Tampered KE2 credential response/envelope fails authentication") {
        void* auth_state = nullptr;
        REQUIRE(opaque_client_state_create(&auth_state) == static_cast<int>(Result::Success));

        server_state_handle_t* srv_state = nullptr;
        REQUIRE(opaque_server_state_create(&srv_state) == static_cast<int>(Result::Success));

        std::vector<uint8_t> ke1(KE1_SIZE);
        REQUIRE(opaque_client_generate_ke1(
            client, reinterpret_cast<const uint8_t*>(secure_key), strlen(secure_key),
            auth_state, ke1.data(), KE1_SIZE) == static_cast<int>(Result::Success));

        std::vector<uint8_t> ke2(KE2_SIZE);
        REQUIRE(opaque_server_generate_ke2(
            server, ke1.data(), KE1_SIZE,
            kAccountId, sizeof(kAccountId),
            pq_creds.data(), CREDENTIALS_SIZE,
            ke2.data(), KE2_SIZE, srv_state) == static_cast<int>(Result::Success));

        size_t cred_resp_offset = NONCE_LENGTH + PUBLIC_KEY_LENGTH;
        ke2[cred_resp_offset + 50] ^= 0x01;

        uint8_t ke3[KE3_LENGTH];
        int result = opaque_client_generate_ke3(
            client, ke2.data(), KE2_SIZE,
            auth_state, ke3, KE3_LENGTH);

        REQUIRE(result == static_cast<int>(Result::AuthenticationError));

        opaque_client_state_destroy(auth_state);
        opaque_server_state_destroy(srv_state);
    }

    SECTION("Tampered KE3 client MAC fails server verification") {
        void* auth_state = nullptr;
        REQUIRE(opaque_client_state_create(&auth_state) == static_cast<int>(Result::Success));

        server_state_handle_t* srv_state = nullptr;
        REQUIRE(opaque_server_state_create(&srv_state) == static_cast<int>(Result::Success));

        std::vector<uint8_t> ke1(KE1_SIZE);
        REQUIRE(opaque_client_generate_ke1(
            client, reinterpret_cast<const uint8_t*>(secure_key), strlen(secure_key),
            auth_state, ke1.data(), KE1_SIZE) == static_cast<int>(Result::Success));

        std::vector<uint8_t> ke2(KE2_SIZE);
        REQUIRE(opaque_server_generate_ke2(
            server, ke1.data(), KE1_SIZE,
            kAccountId, sizeof(kAccountId),
            pq_creds.data(), CREDENTIALS_SIZE,
            ke2.data(), KE2_SIZE, srv_state) == static_cast<int>(Result::Success));

        uint8_t ke3[KE3_LENGTH];
        REQUIRE(opaque_client_generate_ke3(
            client, ke2.data(), KE2_SIZE,
            auth_state, ke3, KE3_LENGTH) == static_cast<int>(Result::Success));

        ke3[0] ^= 0x01;

        uint8_t session_key[HASH_LENGTH];
        uint8_t master_key[MASTER_KEY_LENGTH];
        int result = opaque_server_finish(
            server, ke3, KE3_LENGTH, srv_state,
            session_key, HASH_LENGTH,
            master_key, MASTER_KEY_LENGTH);

        REQUIRE(result == static_cast<int>(Result::AuthenticationError));

        opaque_client_state_destroy(auth_state);
        opaque_server_state_destroy(srv_state);
    }

    SECTION("Tampered KE1 ephemeral KEM public key fails authentication") {
        void* auth_state = nullptr;
        REQUIRE(opaque_client_state_create(&auth_state) == static_cast<int>(Result::Success));

        server_state_handle_t* srv_state = nullptr;
        REQUIRE(opaque_server_state_create(&srv_state) == static_cast<int>(Result::Success));

        std::vector<uint8_t> ke1(KE1_SIZE);
        REQUIRE(opaque_client_generate_ke1(
            client, reinterpret_cast<const uint8_t*>(secure_key), strlen(secure_key),
            auth_state, ke1.data(), KE1_SIZE) == static_cast<int>(Result::Success));

        size_t kem_pk_offset = KE1_BASE_LENGTH;
        ke1[kem_pk_offset + 100] ^= 0xFF;

        std::vector<uint8_t> ke2(KE2_SIZE);
        int ke2_result = opaque_server_generate_ke2(
            server, ke1.data(), KE1_SIZE,
            kAccountId, sizeof(kAccountId),
            pq_creds.data(), CREDENTIALS_SIZE,
            ke2.data(), KE2_SIZE, srv_state);

        if (ke2_result == static_cast<int>(Result::Success)) {
            uint8_t ke3[KE3_LENGTH];
            int ke3_result = opaque_client_generate_ke3(
                client, ke2.data(), KE2_SIZE,
                auth_state, ke3, KE3_LENGTH);

            REQUIRE(ke3_result == static_cast<int>(Result::AuthenticationError));
        }

        opaque_client_state_destroy(auth_state);
        opaque_server_state_destroy(srv_state);
    }

    opaque_client_destroy(client);
    opaque_server_destroy(server);
    opaque_server_keypair_destroy(server_keypair);
}

TEST_CASE("PQ Input Validation Tests", "[opaque][pq][integration][validation]") {
    REQUIRE(sodium_init() >= 0);

    server_keypair_handle_t* server_keypair = nullptr;
    REQUIRE(opaque_server_keypair_generate(&server_keypair) == static_cast<int>(Result::Success));

    uint8_t server_public_key[PUBLIC_KEY_LENGTH];
    REQUIRE(opaque_server_keypair_get_public_key(server_keypair, server_public_key, PUBLIC_KEY_LENGTH) == static_cast<int>(Result::Success));

    opaque_server_handle_t* server = nullptr;
    REQUIRE(opaque_server_create(server_keypair, &server) == static_cast<int>(Result::Success));

    void* client = nullptr;
    REQUIRE(opaque_client_create(server_public_key, PUBLIC_KEY_LENGTH, &client) == static_cast<int>(Result::Success));

    SECTION("PQ registration with empty password fails") {
        void* state = nullptr;
        REQUIRE(opaque_client_state_create(&state) == static_cast<int>(Result::Success));

        uint8_t request[REGISTRATION_REQUEST_LENGTH];
        int result = opaque_client_create_registration_request(
            client, nullptr, 0,
            state, request, REGISTRATION_REQUEST_LENGTH);

        REQUIRE(result == static_cast<int>(Result::InvalidInput));

        opaque_client_state_destroy(state);
    }

    SECTION("PQ KE1 with empty password fails") {
        void* state = nullptr;
        REQUIRE(opaque_client_state_create(&state) == static_cast<int>(Result::Success));

        std::vector<uint8_t> ke1(KE1_SIZE);
        int result = opaque_client_generate_ke1(
            client, nullptr, 0,
            state, ke1.data(), KE1_SIZE);

        REQUIRE(result == static_cast<int>(Result::InvalidInput));

        opaque_client_state_destroy(state);
    }

    SECTION("PQ KE1 with undersized buffer fails") {
        void* state = nullptr;
        REQUIRE(opaque_client_state_create(&state) == static_cast<int>(Result::Success));

        const char* password = "test";
        std::vector<uint8_t> ke1(KE1_SIZE - 1);
        int result = opaque_client_generate_ke1(
            client, reinterpret_cast<const uint8_t*>(password), strlen(password),
            state, ke1.data(), ke1.size());

        REQUIRE(result == static_cast<int>(Result::InvalidInput));

        opaque_client_state_destroy(state);
    }

    SECTION("PQ KE2 generation with wrong KE1 size fails") {
        const char* password = "test_password";

        void* reg_state = nullptr;
        REQUIRE(opaque_client_state_create(&reg_state) == static_cast<int>(Result::Success));

        uint8_t reg_request[REGISTRATION_REQUEST_LENGTH];
        REQUIRE(opaque_client_create_registration_request(
            client, reinterpret_cast<const uint8_t*>(password), strlen(password),
            reg_state, reg_request, REGISTRATION_REQUEST_LENGTH) == static_cast<int>(Result::Success));

        uint8_t reg_response[REGISTRATION_RESPONSE_LENGTH];
        REQUIRE(opaque_server_create_registration_response(
            server, reg_request, REGISTRATION_REQUEST_LENGTH,
            kAccountId, sizeof(kAccountId),
            reg_response, REGISTRATION_RESPONSE_LENGTH) == static_cast<int>(Result::Success));

        std::vector<uint8_t> pq_record(RECORD_SIZE);
        REQUIRE(opaque_client_finalize_registration(
            client, reg_response, REGISTRATION_RESPONSE_LENGTH,
            reg_state, pq_record.data(),
            RECORD_SIZE) == static_cast<int>(Result::Success));

        std::vector<uint8_t> pq_creds(CREDENTIALS_SIZE);
        REQUIRE(opaque_server_build_credentials(
            pq_record.data(), RECORD_SIZE,
            pq_creds.data(), CREDENTIALS_SIZE) == static_cast<int>(Result::Success));

        opaque_client_state_destroy(reg_state);

        server_state_handle_t* srv_state = nullptr;
        REQUIRE(opaque_server_state_create(&srv_state) == static_cast<int>(Result::Success));

        const size_t base_ke1_length = REGISTRATION_REQUEST_LENGTH + PUBLIC_KEY_LENGTH + NONCE_LENGTH;
        std::vector<uint8_t> bad_ke1(base_ke1_length);
        std::vector<uint8_t> ke2(KE2_SIZE);

        int result = opaque_server_generate_ke2(
            server, bad_ke1.data(), bad_ke1.size(),
            kAccountId, sizeof(kAccountId),
            pq_creds.data(), CREDENTIALS_SIZE,
            ke2.data(), KE2_SIZE, srv_state);

        REQUIRE(result == static_cast<int>(Result::InvalidInput));

        opaque_server_state_destroy(srv_state);
    }

    SECTION("PQ credentials with wrong size fails") {
        std::vector<uint8_t> bad_record(RECORD_SIZE - 1);
        randombytes_buf(bad_record.data(), bad_record.size());

        const size_t pq_creds_len = ENVELOPE_LENGTH + PUBLIC_KEY_LENGTH;
        std::vector<uint8_t> pq_creds(pq_creds_len);

        int result = opaque_server_build_credentials(
            bad_record.data(), bad_record.size(),
            pq_creds.data(), pq_creds_len);

        REQUIRE(result == static_cast<int>(Result::InvalidInput));
    }

    opaque_client_destroy(client);
    opaque_server_destroy(server);
    opaque_server_keypair_destroy(server_keypair);
}

TEST_CASE("PQ Edge Cases Tests", "[opaque][pq][integration][edge]") {
    REQUIRE(sodium_init() >= 0);

    server_keypair_handle_t* server_keypair = nullptr;
    REQUIRE(opaque_server_keypair_generate(&server_keypair) == static_cast<int>(Result::Success));

    uint8_t server_public_key[PUBLIC_KEY_LENGTH];
    REQUIRE(opaque_server_keypair_get_public_key(server_keypair, server_public_key, PUBLIC_KEY_LENGTH) == static_cast<int>(Result::Success));

    opaque_server_handle_t* server = nullptr;
    REQUIRE(opaque_server_create(server_keypair, &server) == static_cast<int>(Result::Success));

    void* client = nullptr;
    REQUIRE(opaque_client_create(server_public_key, PUBLIC_KEY_LENGTH, &client) == static_cast<int>(Result::Success));

    SECTION("Very long password works correctly") {

        std::string long_password(1000, 'A');
        for (size_t i = 0; i < long_password.size(); ++i) {
            long_password[i] = static_cast<char>('A' + (i % 26));
        }

        void* reg_state = nullptr;
        REQUIRE(opaque_client_state_create(&reg_state) == static_cast<int>(Result::Success));

        uint8_t reg_request[REGISTRATION_REQUEST_LENGTH];
        REQUIRE(opaque_client_create_registration_request(
            client, reinterpret_cast<const uint8_t*>(long_password.data()), long_password.size(),
            reg_state, reg_request, REGISTRATION_REQUEST_LENGTH) == static_cast<int>(Result::Success));

        uint8_t reg_response[REGISTRATION_RESPONSE_LENGTH];
        REQUIRE(opaque_server_create_registration_response(
            server, reg_request, REGISTRATION_REQUEST_LENGTH,
            kAccountId, sizeof(kAccountId),
            reg_response, REGISTRATION_RESPONSE_LENGTH) == static_cast<int>(Result::Success));

        std::vector<uint8_t> pq_record(RECORD_SIZE);
        REQUIRE(opaque_client_finalize_registration(
            client, reg_response, REGISTRATION_RESPONSE_LENGTH,
            reg_state, pq_record.data(),
            RECORD_SIZE) == static_cast<int>(Result::Success));

        std::vector<uint8_t> pq_creds(CREDENTIALS_SIZE);
        REQUIRE(opaque_server_build_credentials(
            pq_record.data(), RECORD_SIZE,
            pq_creds.data(), CREDENTIALS_SIZE) == static_cast<int>(Result::Success));

        opaque_client_state_destroy(reg_state);

        void* auth_state = nullptr;
        REQUIRE(opaque_client_state_create(&auth_state) == static_cast<int>(Result::Success));

        server_state_handle_t* srv_state = nullptr;
        REQUIRE(opaque_server_state_create(&srv_state) == static_cast<int>(Result::Success));

        std::vector<uint8_t> ke1(KE1_SIZE);
        REQUIRE(opaque_client_generate_ke1(
            client, reinterpret_cast<const uint8_t*>(long_password.data()), long_password.size(),
            auth_state, ke1.data(), KE1_SIZE) == static_cast<int>(Result::Success));

        std::vector<uint8_t> ke2(KE2_SIZE);
        REQUIRE(opaque_server_generate_ke2(
            server, ke1.data(), KE1_SIZE,
            kAccountId, sizeof(kAccountId),
            pq_creds.data(), CREDENTIALS_SIZE,
            ke2.data(), KE2_SIZE, srv_state) == static_cast<int>(Result::Success));

        uint8_t ke3[KE3_LENGTH];
        REQUIRE(opaque_client_generate_ke3(
            client, ke2.data(), KE2_SIZE,
            auth_state, ke3, KE3_LENGTH) == static_cast<int>(Result::Success));

        uint8_t server_session_key[HASH_LENGTH];
        uint8_t server_master_key[MASTER_KEY_LENGTH];
        REQUIRE(opaque_server_finish(
            server, ke3, KE3_LENGTH, srv_state,
            server_session_key, HASH_LENGTH,
            server_master_key, MASTER_KEY_LENGTH) == static_cast<int>(Result::Success));

        uint8_t client_session_key[HASH_LENGTH];
        uint8_t client_master_key[MASTER_KEY_LENGTH];
        REQUIRE(opaque_client_finish(
            client, auth_state,
            client_session_key, HASH_LENGTH,
            client_master_key, MASTER_KEY_LENGTH) == static_cast<int>(Result::Success));

        REQUIRE(std::memcmp(client_session_key, server_session_key, HASH_LENGTH) == 0);

        opaque_client_state_destroy(auth_state);
        opaque_server_state_destroy(srv_state);
    }

    SECTION("Multiple re-authentications with same registration") {
        const char* password = "test_password_123";

        void* reg_state = nullptr;
        REQUIRE(opaque_client_state_create(&reg_state) == static_cast<int>(Result::Success));

        uint8_t reg_request[REGISTRATION_REQUEST_LENGTH];
        REQUIRE(opaque_client_create_registration_request(
            client, reinterpret_cast<const uint8_t*>(password), strlen(password),
            reg_state, reg_request, REGISTRATION_REQUEST_LENGTH) == static_cast<int>(Result::Success));

        uint8_t reg_response[REGISTRATION_RESPONSE_LENGTH];
        REQUIRE(opaque_server_create_registration_response(
            server, reg_request, REGISTRATION_REQUEST_LENGTH,
            kAccountId, sizeof(kAccountId),
            reg_response, REGISTRATION_RESPONSE_LENGTH) == static_cast<int>(Result::Success));

        std::vector<uint8_t> pq_record(RECORD_SIZE);
        REQUIRE(opaque_client_finalize_registration(
            client, reg_response, REGISTRATION_RESPONSE_LENGTH,
            reg_state, pq_record.data(),
            RECORD_SIZE) == static_cast<int>(Result::Success));

        std::vector<uint8_t> pq_creds(CREDENTIALS_SIZE);
        REQUIRE(opaque_server_build_credentials(
            pq_record.data(), RECORD_SIZE,
            pq_creds.data(), CREDENTIALS_SIZE) == static_cast<int>(Result::Success));

        opaque_client_state_destroy(reg_state);

        for (int i = 0; i < 5; ++i) {
            INFO("Authentication iteration: " << i);

            void* auth_state = nullptr;
            REQUIRE(opaque_client_state_create(&auth_state) == static_cast<int>(Result::Success));

            server_state_handle_t* srv_state = nullptr;
            REQUIRE(opaque_server_state_create(&srv_state) == static_cast<int>(Result::Success));

            std::vector<uint8_t> ke1(KE1_SIZE);
            REQUIRE(opaque_client_generate_ke1(
                client, reinterpret_cast<const uint8_t*>(password), strlen(password),
                auth_state, ke1.data(), KE1_SIZE) == static_cast<int>(Result::Success));

            std::vector<uint8_t> ke2(KE2_SIZE);
            REQUIRE(opaque_server_generate_ke2(
                server, ke1.data(), KE1_SIZE,
                kAccountId, sizeof(kAccountId),
                pq_creds.data(), CREDENTIALS_SIZE,
                ke2.data(), KE2_SIZE, srv_state) == static_cast<int>(Result::Success));

            uint8_t ke3[KE3_LENGTH];
            REQUIRE(opaque_client_generate_ke3(
                client, ke2.data(), KE2_SIZE,
                auth_state, ke3, KE3_LENGTH) == static_cast<int>(Result::Success));

            uint8_t session_key[HASH_LENGTH];
            uint8_t master_key[MASTER_KEY_LENGTH];
            REQUIRE(opaque_server_finish(
                server, ke3, KE3_LENGTH, srv_state,
                session_key, HASH_LENGTH,
                master_key, MASTER_KEY_LENGTH) == static_cast<int>(Result::Success));

            opaque_client_state_destroy(auth_state);
            opaque_server_state_destroy(srv_state);
        }
    }

    SECTION("Each authentication produces different session keys (forward secrecy)") {
        const char* password = "test_password_456";

        void* reg_state = nullptr;
        REQUIRE(opaque_client_state_create(&reg_state) == static_cast<int>(Result::Success));

        uint8_t reg_request[REGISTRATION_REQUEST_LENGTH];
        REQUIRE(opaque_client_create_registration_request(
            client, reinterpret_cast<const uint8_t*>(password), strlen(password),
            reg_state, reg_request, REGISTRATION_REQUEST_LENGTH) == static_cast<int>(Result::Success));

        uint8_t reg_response[REGISTRATION_RESPONSE_LENGTH];
        REQUIRE(opaque_server_create_registration_response(
            server, reg_request, REGISTRATION_REQUEST_LENGTH,
            kAccountId, sizeof(kAccountId),
            reg_response, REGISTRATION_RESPONSE_LENGTH) == static_cast<int>(Result::Success));

        std::vector<uint8_t> pq_record(RECORD_SIZE);
        REQUIRE(opaque_client_finalize_registration(
            client, reg_response, REGISTRATION_RESPONSE_LENGTH,
            reg_state, pq_record.data(),
            RECORD_SIZE) == static_cast<int>(Result::Success));

        std::vector<uint8_t> pq_creds(CREDENTIALS_SIZE);
        REQUIRE(opaque_server_build_credentials(
            pq_record.data(), RECORD_SIZE,
            pq_creds.data(), CREDENTIALS_SIZE) == static_cast<int>(Result::Success));

        opaque_client_state_destroy(reg_state);

        std::vector<std::vector<uint8_t>> session_keys;

        for (int i = 0; i < 3; ++i) {
            void* auth_state = nullptr;
            REQUIRE(opaque_client_state_create(&auth_state) == static_cast<int>(Result::Success));

            server_state_handle_t* srv_state = nullptr;
            REQUIRE(opaque_server_state_create(&srv_state) == static_cast<int>(Result::Success));

            std::vector<uint8_t> ke1(KE1_SIZE);
            REQUIRE(opaque_client_generate_ke1(
                client, reinterpret_cast<const uint8_t*>(password), strlen(password),
                auth_state, ke1.data(), KE1_SIZE) == static_cast<int>(Result::Success));

            std::vector<uint8_t> ke2(KE2_SIZE);
            REQUIRE(opaque_server_generate_ke2(
                server, ke1.data(), KE1_SIZE,
                kAccountId, sizeof(kAccountId),
                pq_creds.data(), CREDENTIALS_SIZE,
                ke2.data(), KE2_SIZE, srv_state) == static_cast<int>(Result::Success));

            uint8_t ke3[KE3_LENGTH];
            REQUIRE(opaque_client_generate_ke3(
                client, ke2.data(), KE2_SIZE,
                auth_state, ke3, KE3_LENGTH) == static_cast<int>(Result::Success));

            uint8_t session_key[HASH_LENGTH];
            uint8_t master_key[MASTER_KEY_LENGTH];
            REQUIRE(opaque_server_finish(
                server, ke3, KE3_LENGTH, srv_state,
                session_key, HASH_LENGTH,
                master_key, MASTER_KEY_LENGTH) == static_cast<int>(Result::Success));

            session_keys.emplace_back(session_key, session_key + HASH_LENGTH);

            opaque_client_state_destroy(auth_state);
            opaque_server_state_destroy(srv_state);
        }

        for (size_t i = 0; i < session_keys.size(); ++i) {
            for (size_t j = i + 1; j < session_keys.size(); ++j) {
                INFO("Comparing session keys " << i << " and " << j);
                REQUIRE(session_keys[i] != session_keys[j]);
            }
        }
    }

    SECTION("Authentication with wrong account ID fails") {
        const char* password = "test_password_789";

        void* reg_state = nullptr;
        REQUIRE(opaque_client_state_create(&reg_state) == static_cast<int>(Result::Success));

        uint8_t reg_request[REGISTRATION_REQUEST_LENGTH];
        REQUIRE(opaque_client_create_registration_request(
            client, reinterpret_cast<const uint8_t*>(password), strlen(password),
            reg_state, reg_request, REGISTRATION_REQUEST_LENGTH) == static_cast<int>(Result::Success));

        uint8_t reg_response[REGISTRATION_RESPONSE_LENGTH];
        REQUIRE(opaque_server_create_registration_response(
            server, reg_request, REGISTRATION_REQUEST_LENGTH,
            kAccountId, sizeof(kAccountId),
            reg_response, REGISTRATION_RESPONSE_LENGTH) == static_cast<int>(Result::Success));

        std::vector<uint8_t> pq_record(RECORD_SIZE);
        REQUIRE(opaque_client_finalize_registration(
            client, reg_response, REGISTRATION_RESPONSE_LENGTH,
            reg_state, pq_record.data(),
            RECORD_SIZE) == static_cast<int>(Result::Success));

        std::vector<uint8_t> pq_creds(CREDENTIALS_SIZE);
        REQUIRE(opaque_server_build_credentials(
            pq_record.data(), RECORD_SIZE,
            pq_creds.data(), CREDENTIALS_SIZE) == static_cast<int>(Result::Success));

        opaque_client_state_destroy(reg_state);

        uint8_t wrong_account_id[16] = {0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8,
                                         0xF7, 0xF6, 0xF5, 0xF4, 0xF3, 0xF2, 0xF1, 0xF0};

        void* auth_state = nullptr;
        REQUIRE(opaque_client_state_create(&auth_state) == static_cast<int>(Result::Success));

        server_state_handle_t* srv_state = nullptr;
        REQUIRE(opaque_server_state_create(&srv_state) == static_cast<int>(Result::Success));

        std::vector<uint8_t> ke1(KE1_SIZE);
        REQUIRE(opaque_client_generate_ke1(
            client, reinterpret_cast<const uint8_t*>(password), strlen(password),
            auth_state, ke1.data(), KE1_SIZE) == static_cast<int>(Result::Success));

        std::vector<uint8_t> ke2(KE2_SIZE);
        REQUIRE(opaque_server_generate_ke2(
            server, ke1.data(), KE1_SIZE,
            wrong_account_id, sizeof(wrong_account_id),
            pq_creds.data(), CREDENTIALS_SIZE,
            ke2.data(), KE2_SIZE, srv_state) == static_cast<int>(Result::Success));

        uint8_t ke3[KE3_LENGTH];
        int result = opaque_client_generate_ke3(
            client, ke2.data(), KE2_SIZE,
            auth_state, ke3, KE3_LENGTH);

        REQUIRE(result == static_cast<int>(Result::AuthenticationError));

        opaque_client_state_destroy(auth_state);
        opaque_server_state_destroy(srv_state);
    }

    opaque_client_destroy(client);
    opaque_server_destroy(server);
    opaque_server_keypair_destroy(server_keypair);
}

TEST_CASE("PQ C++ API Edge Cases", "[opaque][pq][cpp][edge]") {
    REQUIRE(sodium_init() >= 0);

    using namespace ecliptix::security::opaque::initiator;
    using namespace ecliptix::security::opaque::responder;

    ResponderKeyPair server_keypair;
    REQUIRE(ResponderKeyPair::generate(server_keypair) == Result::Success);

    OpaqueResponder server(server_keypair);
    ResponderPublicKey server_public_key(server_keypair.public_key.data(), server_keypair.public_key.size());
    OpaqueInitiator client(server_public_key);

    SECTION("Binary password with null bytes works") {

        uint8_t binary_password[] = {0x00, 0x01, 0x02, 0x00, 0xFF, 0xFE, 0x00, 0x10};

        InitiatorState reg_state;
        RegistrationRequest reg_request;
        REQUIRE(OpaqueInitiator::create_registration_request(
            binary_password, sizeof(binary_password),
            reg_request, reg_state) == Result::Success);

        RegistrationResponse reg_response;
        REQUIRE(server.create_registration_response(
            reg_request.data.data(), reg_request.data.size(),
            kAccountId, sizeof(kAccountId),
            reg_response) == Result::Success);

        RegistrationRecord pq_record;
        REQUIRE(client.finalize_registration(
            reg_response.data.data(), reg_response.data.size(),
            reg_state, pq_record) == Result::Success);

        secure_bytes record_buffer;
        REQUIRE(BuildRegistrationRecordBuffer(pq_record, record_buffer) == Result::Success);

        ResponderCredentials pq_creds;
        REQUIRE(build_credentials(
            record_buffer.data(), record_buffer.size(),
            pq_creds) == Result::Success);

        InitiatorState auth_state;
        KE1 ke1;
        REQUIRE(OpaqueInitiator::generate_ke1(
            binary_password, sizeof(binary_password),
            ke1, auth_state) == Result::Success);

        secure_bytes ke1_data;
        REQUIRE(BuildKe1Data(ke1, ke1_data) == Result::Success);

        ResponderState srv_state;
        KE2 ke2;
        REQUIRE(server.generate_ke2(
            ke1_data.data(), ke1_data.size(),
            kAccountId, sizeof(kAccountId),
            pq_creds, ke2, srv_state) == Result::Success);

        secure_bytes ke2_data;
        REQUIRE(BuildKe2Data(ke2, ke2_data) == Result::Success);

        KE3 ke3;
        REQUIRE(client.generate_ke3(
            ke2_data.data(), ke2_data.size(),
            auth_state, ke3) == Result::Success);

        secure_bytes server_session_key, server_master_key;
        REQUIRE(server.responder_finish(
            ke3.initiator_mac.data(), ke3.initiator_mac.size(),
            srv_state, server_session_key, server_master_key) == Result::Success);

        secure_bytes client_session_key, client_master_key;
        REQUIRE(OpaqueInitiator::initiator_finish(auth_state, client_session_key, client_master_key) == Result::Success);

        REQUIRE(client_session_key == server_session_key);
    }

    SECTION("Unicode password works") {

        const char* unicode_password = "пароль密码🔐";

        InitiatorState reg_state;
        RegistrationRequest reg_request;
        REQUIRE(OpaqueInitiator::create_registration_request(
            reinterpret_cast<const uint8_t*>(unicode_password), strlen(unicode_password),
            reg_request, reg_state) == Result::Success);

        RegistrationResponse reg_response;
        REQUIRE(server.create_registration_response(
            reg_request.data.data(), reg_request.data.size(),
            kAccountId, sizeof(kAccountId),
            reg_response) == Result::Success);

        RegistrationRecord pq_record;
        REQUIRE(client.finalize_registration(
            reg_response.data.data(), reg_response.data.size(),
            reg_state, pq_record) == Result::Success);

        REQUIRE(pq_record.envelope.size() == ENVELOPE_LENGTH);
    }
}
