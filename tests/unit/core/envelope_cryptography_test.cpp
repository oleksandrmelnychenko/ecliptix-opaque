#include <catch2/catch_all.hpp>
#include "opaque/opaque.h"
#include <sodium.h>
#include <string>

using namespace ecliptix::security::opaque;

namespace {
    namespace envelope = ecliptix::security::opaque::envelope;
    namespace crypto = ecliptix::security::opaque::crypto;
}

TEST_CASE("Envelope Sealing Operation", "[envelope][core][encryption]") {
    SECTION("Seal envelope with valid parameters") {
        std::string password = "test_password_for_envelope";
        uint8_t randomized_password[crypto_hash_sha512_BYTES];
        crypto_hash_sha512(randomized_password,
                           reinterpret_cast<const uint8_t*>(password.c_str()),
                           password.length());

        uint8_t server_public_key[PUBLIC_KEY_LENGTH];
        uint8_t client_private_key[PRIVATE_KEY_LENGTH];
        uint8_t client_public_key[PUBLIC_KEY_LENGTH];

        crypto::random_bytes(client_private_key, PRIVATE_KEY_LENGTH);
        crypto::random_bytes(server_public_key, PUBLIC_KEY_LENGTH);
        crypto_scalarmult_ristretto255_base(client_public_key, client_private_key);

        Envelope env;
        REQUIRE(envelope::seal(
            randomized_password, sizeof(randomized_password),
            server_public_key,
            client_private_key,
            client_public_key,
            env
        ) == Result::Success);

        REQUIRE(env.nonce.size() == NONCE_LENGTH);
        REQUIRE(env.auth_tag.size() == MAC_LENGTH);
    }

    SECTION("Invalid parameters for sealing") {
        uint8_t randomized_password[crypto_hash_sha512_BYTES];
        uint8_t server_public_key[PUBLIC_KEY_LENGTH];
        uint8_t client_private_key[PRIVATE_KEY_LENGTH];
        uint8_t client_public_key[PUBLIC_KEY_LENGTH];
        Envelope env;

        REQUIRE(envelope::seal(
            nullptr, sizeof(randomized_password),
            server_public_key, client_private_key, client_public_key, env
        ) == Result::InvalidInput);

        REQUIRE(envelope::seal(
            randomized_password, 0,
            server_public_key, client_private_key, client_public_key, env
        ) == Result::InvalidInput);

        REQUIRE(envelope::seal(
            randomized_password, sizeof(randomized_password),
            nullptr, client_private_key, client_public_key, env
        ) == Result::InvalidInput);
    }
}

TEST_CASE("Envelope Opening Operation", "[envelope][core][decryption]") {
    SECTION("Seal and open envelope successfully") {
        std::string password = "roundtrip_test_password";
        uint8_t randomized_password[crypto_hash_sha512_BYTES];
        crypto_hash_sha512(randomized_password,
                           reinterpret_cast<const uint8_t*>(password.c_str()),
                           password.length());

        uint8_t server_public_key[PUBLIC_KEY_LENGTH];
        uint8_t client_private_key[PRIVATE_KEY_LENGTH];
        uint8_t client_public_key[PUBLIC_KEY_LENGTH];

        crypto::random_bytes(server_public_key, PUBLIC_KEY_LENGTH);
        crypto::random_bytes(client_private_key, PRIVATE_KEY_LENGTH);
        crypto_scalarmult_ristretto255_base(client_public_key, client_private_key);

        Envelope env;
        REQUIRE(envelope::seal(
            randomized_password, sizeof(randomized_password),
            server_public_key,
            client_private_key,
            client_public_key,
            env
        ) == Result::Success);

        uint8_t recovered_server_key[PUBLIC_KEY_LENGTH];
        uint8_t recovered_client_key[PRIVATE_KEY_LENGTH];

        REQUIRE(envelope::open(
            randomized_password, sizeof(randomized_password),
            env,
            recovered_server_key,
            recovered_client_key
        ) == Result::Success);

        bool server_key_match = (crypto_verify_32(server_public_key, recovered_server_key) == 0);
        bool client_key_match = (crypto_verify_32(client_private_key, recovered_client_key) == 0);

        REQUIRE(server_key_match);
        REQUIRE(client_key_match);
    }

    SECTION("Opening with wrong password fails") {
        std::string correct_password = "correct_password";
        std::string wrong_password = "wrong_password";

        uint8_t correct_pwd_hash[crypto_hash_sha512_BYTES];
        uint8_t wrong_pwd_hash[crypto_hash_sha512_BYTES];

        crypto_hash_sha512(correct_pwd_hash,
                           reinterpret_cast<const uint8_t*>(correct_password.c_str()),
                           correct_password.length());
        crypto_hash_sha512(wrong_pwd_hash,
                           reinterpret_cast<const uint8_t*>(wrong_password.c_str()),
                           wrong_password.length());

        uint8_t server_public_key[PUBLIC_KEY_LENGTH];
        uint8_t client_private_key[PRIVATE_KEY_LENGTH];
        uint8_t client_public_key[PUBLIC_KEY_LENGTH];

        crypto::random_bytes(server_public_key, PUBLIC_KEY_LENGTH);
        crypto::random_bytes(client_private_key, PRIVATE_KEY_LENGTH);
        crypto_scalarmult_ristretto255_base(client_public_key, client_private_key);

        Envelope env;
        REQUIRE(envelope::seal(
            correct_pwd_hash, sizeof(correct_pwd_hash),
            server_public_key,
            client_private_key,
            client_public_key,
            env
        ) == Result::Success);

        uint8_t recovered_server_key[PUBLIC_KEY_LENGTH];
        uint8_t recovered_client_key[PRIVATE_KEY_LENGTH];

        REQUIRE(envelope::open(
            wrong_pwd_hash, sizeof(wrong_pwd_hash),
            env,
            recovered_server_key,
            recovered_client_key
        ) == Result::AuthenticationError);
    }
}

TEST_CASE("Envelope Credential Recovery", "[envelope][core][recovery]") {
    SECTION("Complete credential recovery flow") {
        std::string password = "credential_recovery_test";
        uint8_t randomized_password[crypto_hash_sha512_BYTES];
        crypto_hash_sha512(randomized_password,
                           reinterpret_cast<const uint8_t*>(password.c_str()),
                           password.length());

        uint8_t server_public_key[PUBLIC_KEY_LENGTH];
        uint8_t client_private_key[PRIVATE_KEY_LENGTH];
        uint8_t client_public_key[PUBLIC_KEY_LENGTH];

        crypto::random_bytes(server_public_key, PUBLIC_KEY_LENGTH);
        crypto::random_bytes(client_private_key, PRIVATE_KEY_LENGTH);
        crypto_scalarmult_ristretto255_base(client_public_key, client_private_key);

        Envelope env;
        REQUIRE(envelope::seal(
            randomized_password, sizeof(randomized_password),
            server_public_key,
            client_private_key,
            client_public_key,
            env
        ) == Result::Success);

        uint8_t recovered_server_key[PUBLIC_KEY_LENGTH];
        uint8_t recovered_client_private[PRIVATE_KEY_LENGTH];
        uint8_t recovered_client_public[PUBLIC_KEY_LENGTH];

        REQUIRE(envelope::recover_credentials(
            randomized_password, sizeof(randomized_password),
            env,
            recovered_server_key,
            recovered_client_private,
            recovered_client_public
        ) == Result::Success);

        bool server_key_match = (crypto_verify_32(server_public_key, recovered_server_key) == 0);
        bool client_private_match = (crypto_verify_32(client_private_key, recovered_client_private) == 0);
        bool client_public_match = (crypto_verify_32(client_public_key, recovered_client_public) == 0);

        REQUIRE(server_key_match);
        REQUIRE(client_private_match);
        REQUIRE(client_public_match);
    }

    SECTION("Invalid parameters for credential recovery") {
        uint8_t password[32];
        Envelope env;
        uint8_t server_key[PUBLIC_KEY_LENGTH];
        uint8_t client_private[PRIVATE_KEY_LENGTH];
        uint8_t client_public[PUBLIC_KEY_LENGTH];

        REQUIRE(envelope::recover_credentials(
            nullptr, sizeof(password), env,
            server_key, client_private, client_public
        ) == Result::InvalidInput);

        REQUIRE(envelope::recover_credentials(
            password, 0, env,
            server_key, client_private, client_public
        ) == Result::InvalidInput);

        REQUIRE(envelope::recover_credentials(
            password, sizeof(password), env,
            nullptr, client_private, client_public
        ) == Result::InvalidInput);
    }
}

TEST_CASE("Envelope Tampering Detection", "[envelope][core][security]") {
    SECTION("Detect nonce tampering") {
        std::string password = "tampering_test_password";
        uint8_t randomized_password[crypto_hash_sha512_BYTES];
        crypto_hash_sha512(randomized_password,
                           reinterpret_cast<const uint8_t*>(password.c_str()),
                           password.length());

        uint8_t server_public_key[PUBLIC_KEY_LENGTH];
        uint8_t client_private_key[PRIVATE_KEY_LENGTH];
        uint8_t client_public_key[PUBLIC_KEY_LENGTH];

        crypto::random_bytes(server_public_key, PUBLIC_KEY_LENGTH);
        crypto::random_bytes(client_private_key, PRIVATE_KEY_LENGTH);
        crypto_scalarmult_ristretto255_base(client_public_key, client_private_key);

        Envelope env;
        REQUIRE(envelope::seal(
            randomized_password, sizeof(randomized_password),
            server_public_key,
            client_private_key,
            client_public_key,
            env
        ) == Result::Success);

        env.nonce[0] ^= 0x01;

        uint8_t recovered_server_key[PUBLIC_KEY_LENGTH];
        uint8_t recovered_client_key[PRIVATE_KEY_LENGTH];

        REQUIRE(envelope::open(
            randomized_password, sizeof(randomized_password),
            env,
            recovered_server_key,
            recovered_client_key
        ) == Result::AuthenticationError);
    }

    SECTION("Detect auth tag tampering") {
        std::string password = "auth_tag_tampering_test";
        uint8_t randomized_password[crypto_hash_sha512_BYTES];
        crypto_hash_sha512(randomized_password,
                           reinterpret_cast<const uint8_t*>(password.c_str()),
                           password.length());

        uint8_t server_public_key[PUBLIC_KEY_LENGTH];
        uint8_t client_private_key[PRIVATE_KEY_LENGTH];
        uint8_t client_public_key[PUBLIC_KEY_LENGTH];

        crypto::random_bytes(server_public_key, PUBLIC_KEY_LENGTH);
        crypto::random_bytes(client_private_key, PRIVATE_KEY_LENGTH);
        crypto_scalarmult_ristretto255_base(client_public_key, client_private_key);

        Envelope env;
        REQUIRE(envelope::seal(
            randomized_password, sizeof(randomized_password),
            server_public_key,
            client_private_key,
            client_public_key,
            env
        ) == Result::Success);

        env.auth_tag[0] ^= 0x01;

        uint8_t recovered_server_key[PUBLIC_KEY_LENGTH];
        uint8_t recovered_client_key[PRIVATE_KEY_LENGTH];

        REQUIRE(envelope::open(
            randomized_password, sizeof(randomized_password),
            env,
            recovered_server_key,
            recovered_client_key
        ) == Result::AuthenticationError);
    }
}