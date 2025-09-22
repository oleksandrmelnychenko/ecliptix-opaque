#include <catch2/catch_all.hpp>
#include "opaque/opaque.h"
#include <sodium.h>

using namespace ecliptix::security::opaque;

TEST_CASE("SecureBuffer - Construction and Basic Operations", "[memory][core]") {
    SECTION("Default construction with valid size") {
        SecureBuffer buffer(64);
        REQUIRE(buffer.size() == 64);
        REQUIRE(buffer.data() != nullptr);
    }

    SECTION("Zero size construction") {
        SecureBuffer buffer(0);
        REQUIRE(buffer.size() == 0);
        REQUIRE(buffer.data() == nullptr);
    }

    SECTION("Move construction preserves data") {
        SecureBuffer original(32);
        uint8_t* original_ptr = original.data();
        size_t original_size = original.size();

        SecureBuffer moved = std::move(original);

        REQUIRE(moved.data() == original_ptr);
        REQUIRE(moved.size() == original_size);
        REQUIRE(original.data() == nullptr);
        REQUIRE(original.size() == 0);
    }
}

TEST_CASE("SecureBuffer - Memory Protection States", "[memory][core][security]") {
    SECTION("Memory protection state transitions") {
        SecureBuffer buffer(64);

        buffer.make_readonly();

        buffer.make_readwrite();

        buffer.make_noaccess();

        buffer.make_readwrite();
    }
}

TEST_CASE("SecureAllocator - Allocation and Deallocation", "[memory][core]") {
    SECTION("Allocate and deallocate memory blocks") {
        SecureAllocator<uint8_t> allocator;

        uint8_t* ptr = allocator.allocate(128);
        REQUIRE(ptr != nullptr);

        for (size_t i = 0; i < 128; ++i) {
            ptr[i] = static_cast<uint8_t>(i & 0xFF);
        }

        allocator.deallocate(ptr, 128);
    }

    SECTION("Zero allocation returns non-null") {
        SecureAllocator<uint8_t> allocator;
        uint8_t* ptr = allocator.allocate(0);
        allocator.deallocate(ptr, 0);
    }
}

TEST_CASE("secure_vector - STL Container Operations", "[memory][core]") {
    SECTION("Basic container operations") {
        secure_vector<uint8_t> vec;

        vec.resize(32);
        REQUIRE(vec.size() == 32);

        for (size_t i = 0; i < vec.size(); ++i) {
            vec[i] = static_cast<uint8_t>(i);
        }

        for (size_t i = 0; i < vec.size(); ++i) {
            REQUIRE(vec[i] == static_cast<uint8_t>(i));
        }
    }

    SECTION("Copy construction and assignment") {
        secure_vector<uint8_t> original(16, 0xAA);
        secure_vector<uint8_t> copy = original;

        REQUIRE(copy.size() == original.size());
        for (size_t i = 0; i < copy.size(); ++i) {
            REQUIRE(copy[i] == 0xAA);
        }
    }
}

TEST_CASE("ServerPublicKey - Validation and Operations", "[memory][core][validation]") {
    SECTION("Default construction creates valid structure") {
        ServerPublicKey key;
        REQUIRE(key.key_data.size() == PUBLIC_KEY_LENGTH);
    }

    SECTION("Construction with valid key data") {
        uint8_t test_key[PUBLIC_KEY_LENGTH] = {0};
        randombytes_buf(test_key, PUBLIC_KEY_LENGTH);

        ServerPublicKey key(test_key, PUBLIC_KEY_LENGTH);
        REQUIRE(key.key_data.size() == PUBLIC_KEY_LENGTH);

        for (size_t i = 0; i < PUBLIC_KEY_LENGTH; ++i) {
            REQUIRE(key.key_data[i] == test_key[i]);
        }
    }
}

TEST_CASE("Envelope - Construction and Memory Layout", "[memory][core]") {
    SECTION("Default envelope structure") {
        Envelope envelope;
        REQUIRE(envelope.nonce.size() == NONCE_LENGTH);
        REQUIRE(envelope.auth_tag.size() == MAC_LENGTH);
    }

    SECTION("Custom auth tag size") {
        Envelope envelope(128);
        REQUIRE(envelope.nonce.size() == NONCE_LENGTH);
        REQUIRE(envelope.auth_tag.size() == 128);
    }
}

TEST_CASE("Memory Constants - Validation", "[memory][core][constants]") {
    SECTION("All memory constants are positive") {
        REQUIRE(OPRF_SEED_LENGTH > 0);
        REQUIRE(PRIVATE_KEY_LENGTH > 0);
        REQUIRE(PUBLIC_KEY_LENGTH > 0);
        REQUIRE(NONCE_LENGTH > 0);
        REQUIRE(MAC_LENGTH > 0);
        REQUIRE(HASH_LENGTH > 0);
        REQUIRE(ENVELOPE_LENGTH > 0);
    }

    SECTION("Memory constants have expected relationships") {
        REQUIRE(PRIVATE_KEY_LENGTH == PUBLIC_KEY_LENGTH);
        REQUIRE(ENVELOPE_LENGTH >= NONCE_LENGTH + MAC_LENGTH);
    }
}