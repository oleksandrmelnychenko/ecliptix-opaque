#include "opaque/opaque.h"
#include <sodium.h>
#include <algorithm>
#include <cstring>

namespace ecliptix::security::opaque {
    namespace envelope {
        Result seal(const uint8_t *randomized_password, size_t password_length,
                    const uint8_t *responder_public_key,
                    const uint8_t *initiator_private_key,
                    const uint8_t *initiator_public_key,
                    const uint8_t *master_key,
                    Envelope &envelope) {
            if (!randomized_password || password_length == 0 ||
                !responder_public_key || !initiator_private_key ||
                !initiator_public_key || !master_key) [[unlikely]] {
                return Result::InvalidInput;
            }
            randombytes_buf(envelope.nonce.data(), envelope.nonce.size());
            uint8_t auth_key[crypto_secretbox_KEYBYTES];
            crypto_hash_sha512_state state;
            crypto_hash_sha512_init(&state);
            const char *context = "OPAQUE-Envelope";
            crypto_hash_sha512_update(&state, reinterpret_cast<const uint8_t *>(context), strlen(context));
            crypto_hash_sha512_update(&state, responder_public_key, PUBLIC_KEY_LENGTH);
            crypto_hash_sha512_update(&state, randomized_password, password_length);
            uint8_t hash[crypto_hash_sha512_BYTES];
            crypto_hash_sha512_final(&state, hash);
            std::copy_n(hash, crypto_secretbox_KEYBYTES, auth_key);
            secure_bytes plaintext(PUBLIC_KEY_LENGTH + PRIVATE_KEY_LENGTH + PUBLIC_KEY_LENGTH + MASTER_KEY_LENGTH);
            size_t offset = 0;
            std::copy_n(responder_public_key, PUBLIC_KEY_LENGTH,
                        plaintext.begin() + static_cast<std::ptrdiff_t>(offset));
            offset += PUBLIC_KEY_LENGTH;
            std::copy_n(initiator_private_key, PRIVATE_KEY_LENGTH,
                        plaintext.begin() + static_cast<std::ptrdiff_t>(offset));
            offset += PRIVATE_KEY_LENGTH;
            std::copy_n(initiator_public_key, PUBLIC_KEY_LENGTH,
                        plaintext.begin() + static_cast<std::ptrdiff_t>(offset));
            offset += PUBLIC_KEY_LENGTH;
            std::copy_n(master_key, MASTER_KEY_LENGTH,
                        plaintext.begin() + static_cast<std::ptrdiff_t>(offset));
            secure_bytes combined(plaintext.size() + crypto_secretbox_MACBYTES);
            crypto_secretbox_easy(combined.data(), plaintext.data(), plaintext.size(),
                                  envelope.nonce.data(), auth_key);
            envelope.ciphertext.resize(plaintext.size());
            envelope.auth_tag.resize(crypto_secretbox_MACBYTES);
            std::copy_n(combined.begin(), plaintext.size(),
                        envelope.ciphertext.begin());
            std::copy(combined.begin() + static_cast<std::ptrdiff_t>(plaintext.size()),
                      combined.begin() + static_cast<std::ptrdiff_t>(plaintext.size() + crypto_secretbox_MACBYTES),
                      envelope.auth_tag.begin());
            sodium_memzero(auth_key, sizeof(auth_key));
            return Result::Success;
        }

        Result open(const Envelope &envelope,
                    const uint8_t *randomized_password, size_t password_length,
                    const uint8_t *known_responder_public_key,
                    uint8_t *responder_public_key,
                    uint8_t *initiator_private_key,
                    uint8_t *initiator_public_key,
                    uint8_t *master_key) {
            if (!randomized_password || password_length == 0 ||
                !known_responder_public_key || !responder_public_key ||
                !initiator_private_key || !initiator_public_key || !master_key) {
                return Result::InvalidInput;
            }
            uint8_t auth_key[crypto_secretbox_KEYBYTES];
            crypto_hash_sha512_state state;
            crypto_hash_sha512_init(&state);
            const char *context = "OPAQUE-Envelope";
            crypto_hash_sha512_update(&state, reinterpret_cast<const uint8_t *>(context), strlen(context));
            crypto_hash_sha512_update(&state, known_responder_public_key, PUBLIC_KEY_LENGTH);
            crypto_hash_sha512_update(&state, randomized_password, password_length);
            uint8_t hash[crypto_hash_sha512_BYTES];
            crypto_hash_sha512_final(&state, hash);
            std::copy_n(hash, crypto_secretbox_KEYBYTES, auth_key);
            constexpr size_t plaintext_length = PUBLIC_KEY_LENGTH + PRIVATE_KEY_LENGTH + PUBLIC_KEY_LENGTH +
                                                MASTER_KEY_LENGTH;
            secure_bytes plaintext(plaintext_length);
            secure_bytes combined(envelope.ciphertext.size() + crypto_secretbox_MACBYTES);
            std::ranges::copy(envelope.ciphertext, combined.begin());
            std::ranges::copy(envelope.auth_tag,
                              combined.begin() + static_cast<std::ptrdiff_t>(envelope.ciphertext.size()));
            if (crypto_secretbox_open_easy(plaintext.data(), combined.data(), combined.size(),
                                           envelope.nonce.data(), auth_key) != 0) {
                return Result::AuthenticationError;
            }
            sodium_memzero(auth_key, sizeof(auth_key));
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
            offset += PUBLIC_KEY_LENGTH;
            std::copy(plaintext.begin() + static_cast<std::ptrdiff_t>(offset),
                      plaintext.begin() + static_cast<std::ptrdiff_t>(offset + MASTER_KEY_LENGTH),
                      master_key);
            uint8_t derived_public_key[PUBLIC_KEY_LENGTH];
            if (crypto_scalarmult_ristretto255_base(derived_public_key, initiator_private_key) != 0) {
                return Result::CryptoError;
            }
            if (!std::equal(initiator_public_key, initiator_public_key + PUBLIC_KEY_LENGTH,
                            derived_public_key)) {
                return Result::AuthenticationError;
            }
            return Result::Success;
        }
    }
}
