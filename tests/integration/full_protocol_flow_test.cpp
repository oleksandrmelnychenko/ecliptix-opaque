#include <catch2/catch_all.hpp>
#include "opaque/client.h"
#include "opaque/server.h"
#include <string>

using namespace ecliptix::security::opaque;
using namespace ecliptix::security::opaque::client;
using namespace ecliptix::security::opaque::server;

TEST_CASE("Full OPAQUE Protocol Flow", "[integration][protocol][flow]") {
    SECTION("Complete registration and authentication cycle") {
        ServerKeyPair server_keypair;
        REQUIRE(ServerKeyPair::generate(server_keypair) == Result::Success);

        ServerPublicKey server_public_key(server_keypair.public_key.data(),
                                         server_keypair.public_key.size());
        REQUIRE(server_public_key.verify() == true);

        OpaqueServer server(server_keypair);
        OpaqueClient client(server_public_key);

        const std::string password = "user_secure_password_123";
        const std::string user_id = "user@example.com";

        ClientState client_state;
        RegistrationRequest reg_request;

        REQUIRE(client.create_registration_request(
            reinterpret_cast<const uint8_t*>(password.c_str()),
            password.length(),
            reg_request,
            client_state
        ) == Result::Success);

        RegistrationResponse reg_response;
        ServerCredentials server_credentials;

        REQUIRE(server.create_registration_response(
            reg_request.data.data(),
            reg_request.data.size(),
            reg_response,
            server_credentials
        ) == Result::Success);

        RegistrationRecord reg_record;
        REQUIRE(client.finalize_registration(
            reg_response.data.data(),
            reg_response.data.size(),
            client_state,
            reg_record
        ) == Result::Success);

        CredentialStore credential_store;
        REQUIRE(credential_store.store_credentials(
            reinterpret_cast<const uint8_t*>(user_id.c_str()),
            user_id.length(),
            server_credentials
        ) == Result::Success);

        ClientState auth_client_state;
        KE1 ke1;

        REQUIRE(client.generate_ke1(
            reinterpret_cast<const uint8_t*>(password.c_str()),
            password.length(),
            ke1,
            auth_client_state
        ) == Result::Success);

        ServerCredentials retrieved_credentials;
        REQUIRE(credential_store.retrieve_credentials(
            reinterpret_cast<const uint8_t*>(user_id.c_str()),
            user_id.length(),
            retrieved_credentials
        ) == Result::Success);

        secure_bytes ke1_data(KE1_LENGTH);
        size_t offset = 0;
        std::copy(ke1.client_nonce.begin(), ke1.client_nonce.end(),
                 ke1_data.begin() + offset);
        offset += NONCE_LENGTH;
        std::copy(ke1.client_public_key.begin(), ke1.client_public_key.end(),
                 ke1_data.begin() + offset);
        offset += PUBLIC_KEY_LENGTH;
        std::copy(ke1.credential_request.begin(), ke1.credential_request.end(),
                 ke1_data.begin() + offset);

        KE2 ke2;
        ServerState server_state;

        REQUIRE(server.generate_ke2(
            ke1_data.data(),
            ke1_data.size(),
            retrieved_credentials,
            ke2,
            server_state
        ) == Result::Success);

        secure_bytes ke2_data(KE2_LENGTH);
        offset = 0;
        std::copy(ke2.server_nonce.begin(), ke2.server_nonce.end(),
                 ke2_data.begin() + offset);
        offset += NONCE_LENGTH;
        std::copy(ke2.server_public_key.begin(), ke2.server_public_key.end(),
                 ke2_data.begin() + offset);
        offset += PUBLIC_KEY_LENGTH;
        std::copy(ke2.credential_response.begin(), ke2.credential_response.end(),
                 ke2_data.begin() + offset);
        offset += CREDENTIAL_RESPONSE_LENGTH;
        std::copy(ke2.server_mac.begin(), ke2.server_mac.end(),
                 ke2_data.begin() + offset);

        KE3 ke3;
        REQUIRE(client.generate_ke3(
            ke2_data.data(),
            ke2_data.size(),
            auth_client_state,
            ke3
        ) == Result::Success);

        secure_bytes client_session_key;
        REQUIRE(client.client_finish(auth_client_state, client_session_key) == Result::Success);

        secure_bytes server_session_key;
        REQUIRE(server.server_finish(
            ke3.client_mac.data(),
            ke3.client_mac.size(),
            server_state,
            server_session_key
        ) == Result::Success);

        REQUIRE(client_session_key.size() == server_session_key.size());
        bool keys_match = std::equal(client_session_key.begin(), client_session_key.end(),
                                   server_session_key.begin());
        REQUIRE(keys_match);
    }
}

TEST_CASE("Protocol Security Properties", "[integration][security][properties]") {
    SECTION("Different passwords produce different session keys") {
        ServerKeyPair server_keypair;
        REQUIRE(ServerKeyPair::generate(server_keypair) == Result::Success);

        ServerPublicKey server_public_key(server_keypair.public_key.data(),
                                         server_keypair.public_key.size());

        OpaqueServer server(server_keypair);
        OpaqueClient client(server_public_key);

        const std::string password1 = "password_one";
        const std::string password2 = "password_two";
        const std::string user_id = "test_user";

        secure_bytes session_key1, session_key2;

        auto run_protocol = [&](const std::string& password, secure_bytes& session_key) {
            ClientState client_state;
            RegistrationRequest reg_request;

            REQUIRE(client.create_registration_request(
                reinterpret_cast<const uint8_t*>(password.c_str()),
                password.length(),
                reg_request,
                client_state
            ) == Result::Success);

            RegistrationResponse reg_response;
            ServerCredentials server_credentials;

            REQUIRE(server.create_registration_response(
                reg_request.data.data(),
                reg_request.data.size(),
                reg_response,
                server_credentials
            ) == Result::Success);

            RegistrationRecord reg_record;
            REQUIRE(client.finalize_registration(
                reg_response.data.data(),
                reg_response.data.size(),
                client_state,
                reg_record
            ) == Result::Success);

            ClientState auth_state;
            KE1 ke1;

            REQUIRE(client.generate_ke1(
                reinterpret_cast<const uint8_t*>(password.c_str()),
                password.length(),
                ke1,
                auth_state
            ) == Result::Success);

            secure_bytes ke1_data(KE1_LENGTH);
            size_t offset = 0;
            std::copy(ke1.client_nonce.begin(), ke1.client_nonce.end(),
                     ke1_data.begin() + offset);
            offset += NONCE_LENGTH;
            std::copy(ke1.client_public_key.begin(), ke1.client_public_key.end(),
                     ke1_data.begin() + offset);
            offset += PUBLIC_KEY_LENGTH;
            std::copy(ke1.credential_request.begin(), ke1.credential_request.end(),
                     ke1_data.begin() + offset);

            KE2 ke2;
            ServerState server_state;

            REQUIRE(server.generate_ke2(
                ke1_data.data(),
                ke1_data.size(),
                server_credentials,
                ke2,
                server_state
            ) == Result::Success);

            secure_bytes ke2_data(KE2_LENGTH);
            offset = 0;
            std::copy(ke2.server_nonce.begin(), ke2.server_nonce.end(),
                     ke2_data.begin() + offset);
            offset += NONCE_LENGTH;
            std::copy(ke2.server_public_key.begin(), ke2.server_public_key.end(),
                     ke2_data.begin() + offset);
            offset += PUBLIC_KEY_LENGTH;
            std::copy(ke2.credential_response.begin(), ke2.credential_response.end(),
                     ke2_data.begin() + offset);
            offset += CREDENTIAL_RESPONSE_LENGTH;
            std::copy(ke2.server_mac.begin(), ke2.server_mac.end(),
                     ke2_data.begin() + offset);

            KE3 ke3;
            REQUIRE(client.generate_ke3(
                ke2_data.data(),
                ke2_data.size(),
                auth_state,
                ke3
            ) == Result::Success);

            REQUIRE(client.client_finish(auth_state, session_key) == Result::Success);

            secure_bytes server_session_key;
            REQUIRE(server.server_finish(
                ke3.client_mac.data(),
                ke3.client_mac.size(),
                server_state,
                server_session_key
            ) == Result::Success);

            REQUIRE(session_key.size() == server_session_key.size());
            bool keys_match = std::equal(session_key.begin(), session_key.end(),
                                       server_session_key.begin());
            REQUIRE(keys_match);
        };

        run_protocol(password1, session_key1);
        run_protocol(password2, session_key2);

        REQUIRE(session_key1.size() == session_key2.size());
        bool keys_different = !std::equal(session_key1.begin(), session_key1.end(),
                                         session_key2.begin());
        REQUIRE(keys_different);
    }
}

TEST_CASE("Protocol Error Handling", "[integration][error][handling]") {
    SECTION("Authentication fails with wrong password") {
        ServerKeyPair server_keypair;
        REQUIRE(ServerKeyPair::generate(server_keypair) == Result::Success);

        ServerPublicKey server_public_key(server_keypair.public_key.data(),
                                         server_keypair.public_key.size());

        OpaqueServer server(server_keypair);
        OpaqueClient client(server_public_key);

        const std::string correct_password = "correct_password";
        const std::string wrong_password = "wrong_password";

        ClientState reg_state;
        RegistrationRequest reg_request;

        REQUIRE(client.create_registration_request(
            reinterpret_cast<const uint8_t*>(correct_password.c_str()),
            correct_password.length(),
            reg_request,
            reg_state
        ) == Result::Success);

        RegistrationResponse reg_response;
        ServerCredentials server_credentials;

        REQUIRE(server.create_registration_response(
            reg_request.data.data(),
            reg_request.data.size(),
            reg_response,
            server_credentials
        ) == Result::Success);

        RegistrationRecord reg_record;
        REQUIRE(client.finalize_registration(
            reg_response.data.data(),
            reg_response.data.size(),
            reg_state,
            reg_record
        ) == Result::Success);

        ClientState auth_state;
        KE1 ke1;

        REQUIRE(client.generate_ke1(
            reinterpret_cast<const uint8_t*>(wrong_password.c_str()),
            wrong_password.length(),
            ke1,
            auth_state
        ) == Result::Success);

        secure_bytes ke1_data(KE1_LENGTH);
        size_t offset = 0;
        std::copy(ke1.client_nonce.begin(), ke1.client_nonce.end(),
                 ke1_data.begin() + offset);
        offset += NONCE_LENGTH;
        std::copy(ke1.client_public_key.begin(), ke1.client_public_key.end(),
                 ke1_data.begin() + offset);
        offset += PUBLIC_KEY_LENGTH;
        std::copy(ke1.credential_request.begin(), ke1.credential_request.end(),
                 ke1_data.begin() + offset);

        KE2 ke2;
        ServerState server_state;

        REQUIRE(server.generate_ke2(
            ke1_data.data(),
            ke1_data.size(),
            server_credentials,
            ke2,
            server_state
        ) == Result::Success);

        secure_bytes ke2_data(KE2_LENGTH);
        offset = 0;
        std::copy(ke2.server_nonce.begin(), ke2.server_nonce.end(),
                 ke2_data.begin() + offset);
        offset += NONCE_LENGTH;
        std::copy(ke2.server_public_key.begin(), ke2.server_public_key.end(),
                 ke2_data.begin() + offset);
        offset += PUBLIC_KEY_LENGTH;
        std::copy(ke2.credential_response.begin(), ke2.credential_response.end(),
                 ke2_data.begin() + offset);
        offset += CREDENTIAL_RESPONSE_LENGTH;
        std::copy(ke2.server_mac.begin(), ke2.server_mac.end(),
                 ke2_data.begin() + offset);

        KE3 ke3;
        Result ke3_result = client.generate_ke3(
            ke2_data.data(),
            ke2_data.size(),
            auth_state,
            ke3
        );

        REQUIRE((ke3_result == Result::AuthenticationError || ke3_result == Result::CryptoError));
    }
}