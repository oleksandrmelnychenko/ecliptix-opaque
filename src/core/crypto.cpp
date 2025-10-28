#include "opaque/opaque.h"
#include <sodium.h>
#include <algorithm>
#include <mutex>

namespace ecliptix::security::opaque {
    namespace crypto {
        bool init() {
            static std::once_flag init_flag;
            static bool init_success = false;

            std::call_once(init_flag, []() {
                init_success = (sodium_init() != -1);
            });

            return init_success;
        }

        Result random_bytes(uint8_t *buffer, size_t length) {
            if (!buffer || length == 0) [[unlikely]] {
                return Result::InvalidInput;
            }
            randombytes_buf(buffer, length);
            return Result::Success;
        }

        Result derive_key_pair(const uint8_t *seed, uint8_t *private_key, uint8_t *public_key) {
            if (!seed || !private_key || !public_key) [[unlikely]] {
                return Result::InvalidInput;
            }
            std::copy_n(seed, PRIVATE_KEY_LENGTH, private_key);
            if (crypto_scalarmult_ristretto255_base(public_key, private_key) != 0) [[unlikely]] {
                return Result::CryptoError;
            }
            return Result::Success;
        }

        Result scalar_mult(const uint8_t *scalar, const uint8_t *point, uint8_t *result) {
            if (!scalar || !point || !result) [[unlikely]] {
                return Result::InvalidInput;
            }
            if (crypto_scalarmult_ristretto255(result, scalar, point) != 0) [[unlikely]] {
                return Result::CryptoError;
            }
            return Result::Success;
        }

        Result hash_to_scalar(const uint8_t *input, const size_t input_length, uint8_t *scalar) {
            if (!input || input_length == 0 || !scalar) [[unlikely]] {
                return Result::InvalidInput;
            }
            uint8_t hash[crypto_hash_sha512_BYTES];
            crypto_hash_sha512(hash, input, input_length);
            crypto_core_ristretto255_scalar_reduce(scalar, hash);
            return Result::Success;
        }

        Result hash_to_group(const uint8_t *input, size_t input_length, uint8_t *point) {
            if (!input || input_length == 0 || !point) [[unlikely]] {
                return Result::InvalidInput;
            }
            uint8_t hash[crypto_hash_sha512_BYTES];
            crypto_hash_sha512(hash, input, input_length);
            if (crypto_core_ristretto255_from_hash(point, hash) != 0) [[unlikely]] {
                return Result::CryptoError;
            }
            return Result::Success;
        }

        Result hmac(const uint8_t *key, const size_t key_length,
                    const uint8_t *message, const size_t message_length,
                    uint8_t *mac) {
            if (!key || key_length == 0 || !message || message_length == 0 || !mac) [[unlikely]] {
                return Result::InvalidInput;
            }
            crypto_auth_hmacsha512_state state;
            if (crypto_auth_hmacsha512_init(&state, key, key_length) != 0) [[unlikely]] {
                return Result::CryptoError;
            }
            if (crypto_auth_hmacsha512_update(&state, message, message_length) != 0) [[unlikely]] {
                return Result::CryptoError;
            }
            if (crypto_auth_hmacsha512_final(&state, mac) != 0) [[unlikely]] {
                return Result::CryptoError;
            }
            return Result::Success;
        }

        Result verify_hmac(const uint8_t *key, size_t key_length,
                           const uint8_t *message, size_t message_length,
                           const uint8_t *mac) {
            if (!key || key_length == 0 || !message || message_length == 0 || !mac) [[unlikely]] {
                return Result::InvalidInput;
            }
            uint8_t computed_mac[crypto_auth_hmacsha512_BYTES];
            if (const Result result = hmac(key, key_length, message, message_length, computed_mac);
                result != Result::Success) [[unlikely]] {
                return result;
            }
            if (crypto_verify_64(mac, computed_mac) != 0) [[unlikely]] {
                return Result::AuthenticationError;
            }
            return Result::Success;
        }

        Result key_derivation_extract(const uint8_t *salt, size_t salt_length,
                                      const uint8_t *ikm, size_t ikm_length,
                                      uint8_t *prk) {
            if (!salt || salt_length == 0 || !ikm || ikm_length == 0 || !prk) [[unlikely]] {
                return Result::InvalidInput;
            }
            return hmac(salt, salt_length, ikm, ikm_length, prk);
        }

        Result key_derivation_expand(const uint8_t *prk, const size_t prk_length,
                                     const uint8_t *info, const size_t info_length,
                                     uint8_t *okm, const size_t okm_length) {
            if (!prk || prk_length == 0 || !okm || okm_length == 0) [[unlikely]] {
                return Result::InvalidInput;
            }
            constexpr size_t hash_length = crypto_auth_hmacsha512_BYTES;
            const size_t n = (okm_length + hash_length - 1) / hash_length;
            if (n > 255) [[unlikely]] {
                return Result::InvalidInput;
            }
            secure_bytes t_prev(hash_length);
            secure_bytes t_current(hash_length);
            for (size_t i = 1; i <= n; ++i) {
                secure_bytes input;
                if (i > 1) [[likely]] {
                    input.insert(input.end(), t_prev.begin(), t_prev.end());
                }
                if (info && info_length > 0) [[likely]] {
                    input.insert(input.end(), info, info + info_length);
                }
                auto counter = static_cast<uint8_t>(i);
                input.push_back(counter);
                if (const Result result = hmac(prk, prk_length, input.data(), input.size(), t_current.data());
                    result != Result::Success) [[unlikely]] {
                    return result;
                }
                const size_t copy_length = std::min(hash_length, okm_length - (i - 1) * hash_length);
                std::copy_n(t_current.begin(), static_cast<std::ptrdiff_t>(copy_length),
                            okm + (i - 1) * hash_length);
                t_prev = t_current;
            }
            return Result::Success;
        }

        Result encrypt_envelope(const uint8_t *key, const size_t key_length,
                                const uint8_t *plaintext, const size_t plaintext_length,
                                const uint8_t *nonce,
                                uint8_t *ciphertext, uint8_t *auth_tag) {
            if (!key || key_length == 0 || !plaintext || plaintext_length == 0 ||
                !nonce || !ciphertext || !auth_tag) [[unlikely]] {
                return Result::InvalidInput;
            }
            secure_bytes combined(plaintext_length + crypto_secretbox_MACBYTES);
            crypto_secretbox_easy(combined.data(), plaintext, plaintext_length, nonce, key);
            std::copy_n(combined.begin(), static_cast<std::ptrdiff_t>(plaintext_length), ciphertext);
            std::copy(combined.begin() + static_cast<std::ptrdiff_t>(plaintext_length), combined.end(), auth_tag);
            return Result::Success;
        }

        Result decrypt_envelope(const uint8_t *key, size_t key_length,
                                const uint8_t *ciphertext, size_t ciphertext_length,
                                const uint8_t *nonce,
                                const uint8_t *auth_tag,
                                uint8_t *plaintext) {
            if (!key || key_length == 0 || !ciphertext || ciphertext_length == 0 ||
                !nonce || !auth_tag || !plaintext) [[unlikely]] {
                return Result::InvalidInput;
            }
            secure_bytes combined(ciphertext_length + crypto_secretbox_MACBYTES);
            std::copy_n(ciphertext, ciphertext_length, combined.begin());
            std::copy_n(auth_tag, crypto_secretbox_MACBYTES,
                        combined.begin() + static_cast<std::ptrdiff_t>(ciphertext_length));
            if (crypto_secretbox_open_easy(plaintext, combined.data(), combined.size(), nonce, key) != 0) [[unlikely]] {
                return Result::AuthenticationError;
            }
            return Result::Success;
        }
    } // namespace crypto
} // namespace ecliptix::security::opaque
