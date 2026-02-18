#include "opaque/opaque.h"
#include "opaque/secure_cleanup.h"
#include <sodium.h>
#include <algorithm>

namespace ecliptix::security::opaque::envelope {
    Result seal(const uint8_t *randomized_password, const size_t password_length,
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
                const uint8_t *randomized_password, const size_t password_length,
                const uint8_t *known_responder_public_key,
                uint8_t *responder_public_key,
                uint8_t *initiator_private_key,
                uint8_t *initiator_public_key) {
        if (!randomized_password || password_length == 0 ||
            !known_responder_public_key || !responder_public_key ||
            !initiator_private_key || !initiator_public_key) [[unlikely]] {
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

        SecureLocal<crypto_secretbox_KEYBYTES> auth_key;
        SecureLocal<crypto_hash_sha512_BYTES> hash;
        SecureLocal<PUBLIC_KEY_LENGTH> derived_public_key;
        secure_bytes plaintext(plaintext_length);

        auto cleanup_guard = make_cleanup([&] {
            sodium_memzero(plaintext.data(), plaintext.size());
        });

        crypto_hash_sha512_state state;
        crypto_hash_sha512_init(&state);
        crypto_hash_sha512_update(&state, reinterpret_cast<const uint8_t *>(labels::kEnvelopeContext),
                                  labels::kEnvelopeContextLength);
        crypto_hash_sha512_update(&state, known_responder_public_key, PUBLIC_KEY_LENGTH);
        crypto_hash_sha512_update(&state, randomized_password, password_length);
        crypto_hash_sha512_final(&state, hash);
        std::copy_n(hash.data(), crypto_secretbox_KEYBYTES, auth_key.data());

        if (crypto_secretbox_open_detached(plaintext.data(), envelope.ciphertext.data(),
                                           envelope.auth_tag.data(), envelope.ciphertext.size(),
                                           envelope.nonce.data(), auth_key) != 0) {
            return Result::AuthenticationError;
        }

        size_t offset = 0;
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
            return Result::CryptoError;
        }

        if (crypto_verify_32(initiator_public_key, derived_public_key) != 0) {
            return Result::AuthenticationError;
        }

        return Result::Success;
    }
}
