#include <catch2/catch_all.hpp>
#include "opaque/opaque.h"
#include <sodium.h>
#include <algorithm>

using namespace ecliptix::security::opaque;

namespace {
    namespace crypto = ecliptix::security::opaque::crypto;
}

TEST_CASE("Cryptographic Initialization", "[crypto][core][initialization]") {
    SECTION("Library initialization succeeds") {
        REQUIRE(crypto::init() == true);
        REQUIRE(crypto::init() == true);
    }
}

TEST_CASE("Random Number Generation", "[crypto][core][randomness]") {
    SECTION("Generate random bytes of various sizes") {
        uint8_t buffer1[32] = {0};
        uint8_t buffer2[32] = {0};

        REQUIRE(crypto::random_bytes(buffer1, 32) == Result::Success);
        REQUIRE(crypto::random_bytes(buffer2, 32) == Result::Success);

        bool different = !std::equal(buffer1, buffer1 + 32, buffer2);
        REQUIRE(different);
    }

    SECTION("Zero length random generation") {
        uint8_t buffer[1] = {0xFF};
        REQUIRE(crypto::random_bytes(buffer, 0) == Result::Success);
        REQUIRE(buffer[0] == 0xFF);
    }

    SECTION("Invalid parameters") {
        REQUIRE(crypto::random_bytes(nullptr, 32) == Result::InvalidInput);
    }
}

TEST_CASE("Key Pair Derivation", "[crypto][core][keypair]") {
    SECTION("Derive key pair from seed") {
        uint8_t seed[PRIVATE_KEY_LENGTH];
        uint8_t private_key[PRIVATE_KEY_LENGTH];
        uint8_t public_key[PUBLIC_KEY_LENGTH];

        crypto::random_bytes(seed, PRIVATE_KEY_LENGTH);

        REQUIRE(crypto::derive_key_pair(seed, private_key, public_key) == Result::Success);

        bool seed_copied = std::equal(seed, seed + PRIVATE_KEY_LENGTH, private_key);
        REQUIRE(seed_copied);
    }

    SECTION("Invalid parameters for key derivation") {
        uint8_t seed[PRIVATE_KEY_LENGTH];
        uint8_t private_key[PRIVATE_KEY_LENGTH];
        uint8_t public_key[PUBLIC_KEY_LENGTH];

        REQUIRE(crypto::derive_key_pair(nullptr, private_key, public_key) == Result::InvalidInput);
        REQUIRE(crypto::derive_key_pair(seed, nullptr, public_key) == Result::InvalidInput);
        REQUIRE(crypto::derive_key_pair(seed, private_key, nullptr) == Result::InvalidInput);
    }
}

TEST_CASE("Scalar Multiplication", "[crypto][core][scalar_mult]") {
    SECTION("Scalar multiplication with base point") {
        uint8_t scalar[PRIVATE_KEY_LENGTH];
        uint8_t point1[PUBLIC_KEY_LENGTH];
        uint8_t point2[PUBLIC_KEY_LENGTH];
        uint8_t result[PUBLIC_KEY_LENGTH];

        crypto::random_bytes(scalar, PRIVATE_KEY_LENGTH);

        REQUIRE(crypto_scalarmult_ristretto255_base(point1, scalar) == 0);

        crypto::random_bytes(scalar, PRIVATE_KEY_LENGTH);
        REQUIRE(crypto_scalarmult_ristretto255_base(point2, scalar) == 0);

        REQUIRE(crypto::scalar_mult(scalar, point1, result) == Result::Success);
    }

    SECTION("Invalid parameters for scalar multiplication") {
        uint8_t scalar[PRIVATE_KEY_LENGTH];
        uint8_t point[PUBLIC_KEY_LENGTH];
        uint8_t result[PUBLIC_KEY_LENGTH];

        REQUIRE(crypto::scalar_mult(nullptr, point, result) == Result::InvalidInput);
        REQUIRE(crypto::scalar_mult(scalar, nullptr, result) == Result::InvalidInput);
        REQUIRE(crypto::scalar_mult(scalar, point, nullptr) == Result::InvalidInput);
    }
}

TEST_CASE("Hash to Scalar Conversion", "[crypto][core][hash_scalar]") {
    SECTION("Convert hash to scalar") {
        const std::string test_input = "test input for hashing";
        uint8_t scalar[crypto_core_ristretto255_SCALARBYTES];

        REQUIRE(crypto::hash_to_scalar(
            reinterpret_cast<const uint8_t*>(test_input.c_str()),
            test_input.length(),
            scalar
        ) == Result::Success);
    }

    SECTION("Zero length input") {
        uint8_t scalar[crypto_core_ristretto255_SCALARBYTES];
        REQUIRE(crypto::hash_to_scalar(nullptr, 0, scalar) == Result::InvalidInput);
    }
}

TEST_CASE("Hash to Group Element", "[crypto][core][hash_group]") {
    SECTION("Convert hash to group element") {
        const std::string test_input = "test input for group hashing";
        uint8_t point[crypto_core_ristretto255_BYTES];

        REQUIRE(crypto::hash_to_group(
            reinterpret_cast<const uint8_t*>(test_input.c_str()),
            test_input.length(),
            point
        ) == Result::Success);

        REQUIRE(crypto_core_ristretto255_is_valid_point(point) == 1);
    }
}

TEST_CASE("HMAC Operations", "[crypto][core][hmac]") {
    SECTION("Generate and verify HMAC") {
        const std::string key = "test_hmac_key";
        const std::string message = "test message for hmac";
        uint8_t mac[crypto_auth_hmacsha512_BYTES];

        REQUIRE(crypto::hmac(
            reinterpret_cast<const uint8_t*>(key.c_str()), key.length(),
            reinterpret_cast<const uint8_t*>(message.c_str()), message.length(),
            mac
        ) == Result::Success);

        REQUIRE(crypto::verify_hmac(
            reinterpret_cast<const uint8_t*>(key.c_str()), key.length(),
            reinterpret_cast<const uint8_t*>(message.c_str()), message.length(),
            mac
        ) == Result::Success);
    }

    SECTION("HMAC verification with wrong MAC fails") {
        const std::string key = "test_hmac_key";
        const std::string message = "test message for hmac";
        uint8_t mac[crypto_auth_hmacsha512_BYTES];
        uint8_t wrong_mac[crypto_auth_hmacsha512_BYTES] = {0};

        REQUIRE(crypto::hmac(
            reinterpret_cast<const uint8_t*>(key.c_str()), key.length(),
            reinterpret_cast<const uint8_t*>(message.c_str()), message.length(),
            mac
        ) == Result::Success);

        REQUIRE(crypto::verify_hmac(
            reinterpret_cast<const uint8_t*>(key.c_str()), key.length(),
            reinterpret_cast<const uint8_t*>(message.c_str()), message.length(),
            wrong_mac
        ) == Result::AuthenticationError);
    }
}

TEST_CASE("Key Derivation Functions", "[crypto][core][kdf]") {
    SECTION("KDF Extract operation") {
        const std::string salt = "test_salt";
        const std::string ikm = "input_key_material";
        uint8_t prk[crypto_auth_hmacsha512_BYTES];

        REQUIRE(crypto::kdf_extract(
            reinterpret_cast<const uint8_t*>(salt.c_str()), salt.length(),
            reinterpret_cast<const uint8_t*>(ikm.c_str()), ikm.length(),
            prk
        ) == Result::Success);
    }

    SECTION("KDF Expand operation") {
        uint8_t prk[crypto_auth_hmacsha512_BYTES];
        crypto::random_bytes(prk, sizeof(prk));

        const std::string info = "test_info";
        uint8_t okm[64];

        REQUIRE(crypto::kdf_expand(
            prk, sizeof(prk),
            reinterpret_cast<const uint8_t*>(info.c_str()), info.length(),
            okm, sizeof(okm)
        ) == Result::Success);
    }

    SECTION("KDF Expand with excessive output length") {
        uint8_t prk[crypto_auth_hmacsha512_BYTES];
        crypto::random_bytes(prk, sizeof(prk));

        uint8_t okm[255 * crypto_auth_hmacsha512_BYTES + 1];

        REQUIRE(crypto::kdf_expand(
            prk, sizeof(prk),
            nullptr, 0,
            okm, sizeof(okm)
        ) == Result::InvalidInput);
    }
}