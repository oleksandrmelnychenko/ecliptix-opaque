#include <catch2/catch_all.hpp>
#include "opaque/opaque.h"
#include <sodium.h>
#include <string>

using namespace ecliptix::security::opaque;

namespace {
    namespace oprf = ecliptix::security::opaque::oprf;
}

TEST_CASE("OPRF Hash to Group", "[oprf][core][hash_to_group]") {
    SECTION("Hash arbitrary input to group element") {
        const std::string test_input = "test_password_input";
        uint8_t group_element[crypto_core_ristretto255_BYTES];

        REQUIRE(oprf::hash_to_group(
            reinterpret_cast<const uint8_t*>(test_input.c_str()),
            test_input.length(),
            group_element
        ) == Result::Success);

        REQUIRE(crypto_core_ristretto255_is_valid_point(group_element) == 1);
    }

    SECTION("Different inputs produce different group elements") {
        const std::string input1 = "password1";
        const std::string input2 = "password2";
        uint8_t element1[crypto_core_ristretto255_BYTES];
        uint8_t element2[crypto_core_ristretto255_BYTES];

        REQUIRE(oprf::hash_to_group(
            reinterpret_cast<const uint8_t*>(input1.c_str()),
            input1.length(),
            element1
        ) == Result::Success);

        REQUIRE(oprf::hash_to_group(
            reinterpret_cast<const uint8_t*>(input2.c_str()),
            input2.length(),
            element2
        ) == Result::Success);

        bool elements_different = (crypto_verify_32(element1, element2) != 0);
        REQUIRE(elements_different);
    }

    SECTION("Invalid parameters") {
        uint8_t element[crypto_core_ristretto255_BYTES];

        REQUIRE(oprf::hash_to_group(nullptr, 10, element) == Result::InvalidInput);
        REQUIRE(oprf::hash_to_group(reinterpret_cast<const uint8_t*>("test"), 0, element) == Result::InvalidInput);
        REQUIRE(oprf::hash_to_group(reinterpret_cast<const uint8_t*>("test"), 4, nullptr) == Result::InvalidInput);
    }
}

TEST_CASE("OPRF Blinding Operation", "[oprf][core][blinding]") {
    SECTION("Blind operation produces valid output") {
        const std::string password = "user_password";
        uint8_t blinded_element[crypto_core_ristretto255_BYTES];
        uint8_t blind_scalar[crypto_core_ristretto255_SCALARBYTES];

        REQUIRE(oprf::blind(
            reinterpret_cast<const uint8_t*>(password.c_str()),
            password.length(),
            blinded_element,
            blind_scalar
        ) == Result::Success);

        REQUIRE(crypto_core_ristretto255_is_valid_point(blinded_element) == 1);
    }

    SECTION("Different passwords produce different blinded elements") {
        const std::string password1 = "password_one";
        const std::string password2 = "password_two";
        uint8_t blinded1[crypto_core_ristretto255_BYTES];
        uint8_t blinded2[crypto_core_ristretto255_BYTES];
        uint8_t blind1[crypto_core_ristretto255_SCALARBYTES];
        uint8_t blind2[crypto_core_ristretto255_SCALARBYTES];

        REQUIRE(oprf::blind(
            reinterpret_cast<const uint8_t*>(password1.c_str()),
            password1.length(),
            blinded1, blind1
        ) == Result::Success);

        REQUIRE(oprf::blind(
            reinterpret_cast<const uint8_t*>(password2.c_str()),
            password2.length(),
            blinded2, blind2
        ) == Result::Success);

        bool elements_different = (crypto_verify_32(blinded1, blinded2) != 0);
        bool scalars_different = (crypto_verify_32(blind1, blind2) != 0);

        REQUIRE(elements_different);
        REQUIRE(scalars_different);
    }
}

TEST_CASE("OPRF Evaluation Operation", "[oprf][core][evaluation]") {
    SECTION("Server evaluation of blinded element") {
        const std::string password = "test_password";
        uint8_t blinded_element[crypto_core_ristretto255_BYTES];
        uint8_t blind_scalar[crypto_core_ristretto255_SCALARBYTES];
        uint8_t server_private_key[crypto_core_ristretto255_SCALARBYTES];
        uint8_t evaluated_element[crypto_core_ristretto255_BYTES];

        crypto_core_ristretto255_scalar_random(server_private_key);

        REQUIRE(oprf::blind(
            reinterpret_cast<const uint8_t*>(password.c_str()),
            password.length(),
            blinded_element, blind_scalar
        ) == Result::Success);

        REQUIRE(oprf::evaluate(blinded_element, server_private_key, evaluated_element) == Result::Success);

        REQUIRE(crypto_core_ristretto255_is_valid_point(evaluated_element) == 1);
    }

    SECTION("Invalid parameters for evaluation") {
        uint8_t blinded_element[crypto_core_ristretto255_BYTES];
        uint8_t server_key[crypto_core_ristretto255_SCALARBYTES];
        uint8_t evaluated[crypto_core_ristretto255_BYTES];

        REQUIRE(oprf::evaluate(nullptr, server_key, evaluated) == Result::InvalidInput);
        REQUIRE(oprf::evaluate(blinded_element, nullptr, evaluated) == Result::InvalidInput);
        REQUIRE(oprf::evaluate(blinded_element, server_key, nullptr) == Result::InvalidInput);
    }
}

TEST_CASE("OPRF Finalization Operation", "[oprf][core][finalization]") {
    SECTION("Complete OPRF protocol flow") {
        const std::string password = "finalization_test_password";
        uint8_t blinded_element[crypto_core_ristretto255_BYTES];
        uint8_t blind_scalar[crypto_core_ristretto255_SCALARBYTES];
        uint8_t server_private_key[crypto_core_ristretto255_SCALARBYTES];
        uint8_t evaluated_element[crypto_core_ristretto255_BYTES];
        uint8_t oprf_output[crypto_hash_sha512_BYTES];

        crypto_core_ristretto255_scalar_random(server_private_key);

        REQUIRE(oprf::blind(
            reinterpret_cast<const uint8_t*>(password.c_str()),
            password.length(),
            blinded_element, blind_scalar
        ) == Result::Success);

        REQUIRE(oprf::evaluate(blinded_element, server_private_key, evaluated_element) == Result::Success);

        REQUIRE(oprf::finalize(
            reinterpret_cast<const uint8_t*>(password.c_str()),
            password.length(),
            blind_scalar,
            evaluated_element,
            oprf_output
        ) == Result::Success);
    }

    SECTION("Deterministic OPRF output") {
        const std::string password = "deterministic_test";
        uint8_t server_key[crypto_core_ristretto255_SCALARBYTES];
        uint8_t output1[crypto_hash_sha512_BYTES];
        uint8_t output2[crypto_hash_sha512_BYTES];

        for (size_t i = 0; i < crypto_core_ristretto255_SCALARBYTES; ++i) {
            server_key[i] = static_cast<uint8_t>(i);
        }

        for (int iteration = 0; iteration < 2; ++iteration) {
            uint8_t blinded[crypto_core_ristretto255_BYTES];
            uint8_t blind[crypto_core_ristretto255_SCALARBYTES];
            uint8_t evaluated[crypto_core_ristretto255_BYTES];

            REQUIRE(oprf::blind(
                reinterpret_cast<const uint8_t*>(password.c_str()),
                password.length(),
                blinded, blind
            ) == Result::Success);

            REQUIRE(oprf::evaluate(blinded, server_key, evaluated) == Result::Success);

            REQUIRE(oprf::finalize(
                reinterpret_cast<const uint8_t*>(password.c_str()),
                password.length(),
                blind, evaluated,
                iteration == 0 ? output1 : output2
            ) == Result::Success);
        }
    }

    SECTION("Invalid parameters for finalization") {
        const std::string password = "test";
        uint8_t blind[crypto_core_ristretto255_SCALARBYTES];
        uint8_t evaluated[crypto_core_ristretto255_BYTES];
        uint8_t output[crypto_hash_sha512_BYTES];

        REQUIRE(oprf::finalize(nullptr, password.length(), blind, evaluated, output) == Result::InvalidInput);
        REQUIRE(oprf::finalize(
            reinterpret_cast<const uint8_t*>(password.c_str()), 0,
            blind, evaluated, output
        ) == Result::InvalidInput);
        REQUIRE(oprf::finalize(
            reinterpret_cast<const uint8_t*>(password.c_str()), password.length(),
            nullptr, evaluated, output
        ) == Result::InvalidInput);
        REQUIRE(oprf::finalize(
            reinterpret_cast<const uint8_t*>(password.c_str()), password.length(),
            blind, nullptr, output
        ) == Result::InvalidInput);
        REQUIRE(oprf::finalize(
            reinterpret_cast<const uint8_t*>(password.c_str()), password.length(),
            blind, evaluated, nullptr
        ) == Result::InvalidInput);
    }
}