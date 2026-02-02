#include "opaque/opaque.h"
#include <sodium.h>
#include <algorithm>

namespace ecliptix::security::opaque::envelope {
    Result seal(const uint8_t *randomized_password, size_t password_length,
                const uint8_t *responder_public_key,
                const uint8_t *initiator_private_key,
                const uint8_t *initiator_public_key,
                Envelope &envelope) {
        if (!randomized_password || password_length == 0 ||
            !responder_public_key || !initiator_private_key ||
            !initiator_public_key) [[unlikely]] {
            return Result::InvalidInput;
        }
        if (!crypto::init()) {
            return Result::CryptoError;
        }
        if (envelope.nonce.size() != NONCE_LENGTH) {
            return Result::InvalidInput;
        }
        randombytes_buf(envelope.nonce.data(), envelope.nonce.size());
        uint8_t auth_key[crypto_secretbox_KEYBYTES];
        crypto_hash_sha512_state state;
        crypto_hash_sha512_init(&state);
            crypto_hash_sha512_update(&state, reinterpret_cast<const uint8_t *>(labels::kEnvelopeContext),
                                      labels::kEnvelopeContextLength);
        crypto_hash_sha512_update(&state, responder_public_key, PUBLIC_KEY_LENGTH);
        crypto_hash_sha512_update(&state, randomized_password, password_length);
        uint8_t hash[crypto_hash_sha512_BYTES];
        crypto_hash_sha512_final(&state, hash);
        std::copy_n(hash, crypto_secretbox_KEYBYTES, auth_key);
        sodium_memzero(hash, sizeof(hash));

        constexpr size_t plaintext_length = PUBLIC_KEY_LENGTH + PRIVATE_KEY_LENGTH + PUBLIC_KEY_LENGTH;
        secure_bytes plaintext(plaintext_length);
        size_t offset = 0;
        std::copy_n(responder_public_key, PUBLIC_KEY_LENGTH,
                    plaintext.begin() + static_cast<std::ptrdiff_t>(offset));
        offset += PUBLIC_KEY_LENGTH;
        std::copy_n(initiator_private_key, PRIVATE_KEY_LENGTH,
                    plaintext.begin() + static_cast<std::ptrdiff_t>(offset));
        offset += PRIVATE_KEY_LENGTH;
        std::copy_n(initiator_public_key, PUBLIC_KEY_LENGTH,
                    plaintext.begin() + static_cast<std::ptrdiff_t>(offset));
        envelope.ciphertext.resize(plaintext_length);
        envelope.auth_tag.resize(crypto_secretbox_MACBYTES);
        crypto_secretbox_detached(envelope.ciphertext.data(), envelope.auth_tag.data(),
                                  plaintext.data(), plaintext.size(),
                                  envelope.nonce.data(), auth_key);
        sodium_memzero(auth_key, sizeof(auth_key));
        return Result::Success;
    }

    Result open(const Envelope &envelope,
                const uint8_t *randomized_password, size_t password_length,
                const uint8_t *known_responder_public_key,
                uint8_t *responder_public_key,
                uint8_t *initiator_private_key,
                uint8_t *initiator_public_key) {
        if (!randomized_password || password_length == 0 ||
            !known_responder_public_key || !responder_public_key ||
            !initiator_private_key || !initiator_public_key) {
            return Result::InvalidInput;
        }

        if (!crypto::init()) {
            return Result::CryptoError;
        }

        constexpr size_t plaintext_length = PUBLIC_KEY_LENGTH + PRIVATE_KEY_LENGTH + PUBLIC_KEY_LENGTH;
        if (envelope.nonce.size() != NONCE_LENGTH ||
            envelope.ciphertext.size() != plaintext_length ||
            envelope.auth_tag.size() != crypto_secretbox_MACBYTES) {
            return Result::InvalidInput;
        }

        auto result = Result::Success;
        uint8_t auth_key[crypto_secretbox_KEYBYTES] = {};
        crypto_hash_sha512_state state;
        crypto_hash_sha512_init(&state);
            crypto_hash_sha512_update(&state, reinterpret_cast<const uint8_t *>(labels::kEnvelopeContext),
                                      labels::kEnvelopeContextLength);
        crypto_hash_sha512_update(&state, known_responder_public_key, PUBLIC_KEY_LENGTH);
        crypto_hash_sha512_update(&state, randomized_password, password_length);
        uint8_t hash[crypto_hash_sha512_BYTES] = {};
        crypto_hash_sha512_final(&state, hash);
        std::copy_n(hash, crypto_secretbox_KEYBYTES, auth_key);
        secure_bytes plaintext(plaintext_length);
        size_t offset = 0;
        uint8_t derived_public_key[PUBLIC_KEY_LENGTH];
        if (crypto_secretbox_open_detached(plaintext.data(), envelope.ciphertext.data(),
                                           envelope.auth_tag.data(), envelope.ciphertext.size(),
                                           envelope.nonce.data(), auth_key) != 0) {
            result = Result::AuthenticationError;
            goto cleanup;
        }
        std::copy(plaintext.begin() + static_cast<std::ptrdiff_t>(offset),
                  plaintext.begin() + static_cast<std::ptrdiff_t>(offset + PUBLIC_KEY_LENGTH),
                  responder_public_key);
        offset += PUBLIC_KEY_LENGTH;
        std::copy(plaintext.begin() + static_cast<std::ptrdiff_t>(offset),
                  plaintext.begin() + static_cast<std::ptrdiff_t>(offset + PRIVATE_KEY_LENGTH),
                  initiator_private_key);
        offset += PRIVATE_KEY_LENGTH;
        std::copy(plaintext.begin() + static_cast<std::ptrdiff_t>(offset),
                  plaintext.begin() + static_cast<std::ptrdiff_t>(offset + PUBLIC_KEY_LENGTH),
                  initiator_public_key);
        if (crypto_scalarmult_ristretto255_base(derived_public_key, initiator_private_key) != 0) {
            result = Result::CryptoError;
            goto cleanup;
        }
        if (!std::equal(initiator_public_key, initiator_public_key + PUBLIC_KEY_LENGTH,
                        derived_public_key)) {
            result = Result::AuthenticationError;
        }
    cleanup:
        sodium_memzero(auth_key, sizeof(auth_key));
        sodium_memzero(hash, sizeof(hash));
        return result;
    }
}
