#include "opaque/opaque.h"
#include <sodium.h>
#include <algorithm>
#include <mutex>

namespace ecliptix::security::opaque::crypto {
    namespace {
#ifndef OPAQUE_KSF_OPSLIMIT
        constexpr unsigned long long kKsfOpslimit = crypto_pwhash_OPSLIMIT_MODERATE;
#else
        constexpr unsigned long long kKsfOpslimit = OPAQUE_KSF_OPSLIMIT;
#endif

#ifndef OPAQUE_KSF_MEMLIMIT
        constexpr size_t kKsfMemlimit = crypto_pwhash_MEMLIMIT_MODERATE;
#else
        constexpr size_t kKsfMemlimit = OPAQUE_KSF_MEMLIMIT;
#endif
    }

    bool init() {
        static std::once_flag init_flag;
        static bool init_success = false;

        std::call_once(init_flag, [] {
            init_success = sodium_init() != -1;
        });

        return init_success;
    }

    Result random_bytes(uint8_t *buffer, size_t length) {
        if (!buffer || length == 0) [[unlikely]] {
            return Result::InvalidInput;
        }
        if (!init()) {
            return Result::CryptoError;
        }
        randombytes_buf(buffer, length);
        return Result::Success;
    }

    Result derive_key_pair(const uint8_t *seed, size_t seed_length,
                           uint8_t *private_key, uint8_t *public_key) {
        if (!seed || seed_length == 0 || !private_key || !public_key) [[unlikely]] {
            return Result::InvalidInput;
        }
        if (!init()) {
            return Result::CryptoError;
        }
        uint8_t hash[crypto_hash_sha512_BYTES];
        crypto_hash_sha512(hash, seed, seed_length);
        crypto_core_ristretto255_scalar_reduce(private_key, hash);
        if (sodium_is_zero(private_key, PRIVATE_KEY_LENGTH) == 1) {
            sodium_memzero(hash, sizeof(hash));
            return Result::InvalidInput;
        }
        sodium_memzero(hash, sizeof(hash));
        if (crypto_scalarmult_ristretto255_base(public_key, private_key) != 0) [[unlikely]] {
            return Result::CryptoError;
        }
        return Result::Success;
    }

    Result scalar_mult(const uint8_t *scalar, const uint8_t *point, uint8_t *result) {
        if (!scalar || !point || !result) [[unlikely]] {
            return Result::InvalidInput;
        }
        if (!init()) {
            return Result::CryptoError;
        }
        if (crypto_scalarmult_ristretto255(result, scalar, point) != 0) [[unlikely]] {
            return Result::CryptoError;
        }
        return Result::Success;
    }

    Result validate_ristretto_point(const uint8_t *point, size_t length) {
        if (!point || length != PUBLIC_KEY_LENGTH) [[unlikely]] {
            return Result::InvalidInput;
        }
        if (!init()) {
            return Result::CryptoError;
        }
        if (crypto_core_ristretto255_is_valid_point(point) != 1 ||
            util::is_all_zero(point, length)) {
            return Result::InvalidInput;
        }
        return Result::Success;
    }

    Result validate_public_key(const uint8_t *key, size_t length) {
        if (!key || length != PUBLIC_KEY_LENGTH) [[unlikely]] {
            return Result::InvalidInput;
        }
        if (!init()) {
            return Result::CryptoError;
        }
        if (crypto_core_ristretto255_is_valid_point(key) != 1 ||
            util::is_all_zero(key, length)) {
            return Result::InvalidPublicKey;
        }
        return Result::Success;
    }

    Result hash_to_scalar(const uint8_t *input, const size_t input_length, uint8_t *scalar) {
        if (!input || input_length == 0 || !scalar) [[unlikely]] {
            return Result::InvalidInput;
        }
        if (!init()) {
            return Result::CryptoError;
        }
        uint8_t hash[crypto_hash_sha512_BYTES];
        crypto_hash_sha512(hash, input, input_length);
        crypto_core_ristretto255_scalar_reduce(scalar, hash);
        sodium_memzero(hash, sizeof(hash));
        return Result::Success;
    }

    Result hash_to_group(const uint8_t *input, size_t input_length, uint8_t *point) {
        if (!input || input_length == 0 || !point) [[unlikely]] {
            return Result::InvalidInput;
        }
        if (!init()) {
            return Result::CryptoError;
        }
        uint8_t hash[crypto_hash_sha512_BYTES];
        crypto_hash_sha512(hash, input, input_length);
        if (crypto_core_ristretto255_from_hash(point, hash) != 0) [[unlikely]] {
            sodium_memzero(hash, sizeof(hash));
            return Result::CryptoError;
        }
        sodium_memzero(hash, sizeof(hash));
        return Result::Success;
    }

    Result hmac(const uint8_t *key, const size_t key_length,
                const uint8_t *message, const size_t message_length,
                uint8_t *mac) {
        if (!key || key_length == 0 || !message || message_length == 0 || !mac) [[unlikely]] {
            return Result::InvalidInput;
        }
        if (!init()) {
            return Result::CryptoError;
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

    Result derive_oprf_key(const uint8_t *relay_secret, const size_t relay_secret_length,
                           const uint8_t *account_id, const size_t account_id_length,
                           uint8_t *oprf_key) {
        if (!relay_secret || relay_secret_length == 0 ||
            !account_id || account_id_length == 0 || !oprf_key) [[unlikely]] {
            return Result::InvalidInput;
        }
        if (!init()) {
            return Result::CryptoError;
        }
        uint8_t oprf_seed_full[crypto_auth_hmacsha512_BYTES];
        if (const Result seed_result = hmac(relay_secret, relay_secret_length,
                                            reinterpret_cast<const uint8_t *>(labels::kOprfSeedInfo),
                                            labels::kOprfSeedInfoLength,
                                            oprf_seed_full);
            seed_result != Result::Success) [[unlikely]] {
            return seed_result;
        }
        uint8_t oprf_seed[OPRF_SEED_LENGTH];
        std::copy_n(oprf_seed_full, sizeof(oprf_seed), oprf_seed);
        sodium_memzero(oprf_seed_full, sizeof(oprf_seed_full));
        secure_bytes input(labels::kOprfKeyInfoLength + account_id_length + 1);
        std::copy_n(reinterpret_cast<const uint8_t *>(labels::kOprfKeyInfo),
                    labels::kOprfKeyInfoLength, input.begin());
        std::copy_n(account_id, account_id_length,
                    input.begin() + static_cast<std::ptrdiff_t>(labels::kOprfKeyInfoLength));
        uint8_t mac[crypto_auth_hmacsha512_BYTES];
        const size_t counter_offset = labels::kOprfKeyInfoLength + account_id_length;
        for (uint16_t counter = 0; counter < 255; ++counter) {
            input[counter_offset] = static_cast<uint8_t>(counter);
            if (const Result result = hmac(oprf_seed, sizeof(oprf_seed),
                                           input.data(), input.size(), mac);
                result != Result::Success) [[unlikely]] {
                sodium_memzero(mac, sizeof(mac));
                sodium_memzero(oprf_seed, sizeof(oprf_seed));
                return result;
            }
            crypto_core_ristretto255_scalar_reduce(oprf_key, mac);
            if (sodium_is_zero(oprf_key, PRIVATE_KEY_LENGTH) == 0) {
                sodium_memzero(mac, sizeof(mac));
                sodium_memzero(oprf_seed, sizeof(oprf_seed));
                return Result::Success;
            }
        }
        sodium_memzero(mac, sizeof(mac));
        sodium_memzero(oprf_seed, sizeof(oprf_seed));
        return Result::CryptoError;
    }

    Result derive_randomized_password(const uint8_t *oprf_output, const size_t oprf_output_length,
                                      const uint8_t *secure_key, const size_t secure_key_length,
                                      uint8_t *randomized_pwd, const size_t randomized_pwd_length) {
        if (!oprf_output || oprf_output_length == 0 ||
            !secure_key || secure_key_length == 0 ||
            !randomized_pwd || randomized_pwd_length == 0) [[unlikely]] {
            return Result::InvalidInput;
        }
        if (randomized_pwd_length < crypto_pwhash_BYTES_MIN ||
            randomized_pwd_length > crypto_pwhash_BYTES_MAX) [[unlikely]] {
            return Result::InvalidInput;
        }
        if (!init()) {
            return Result::CryptoError;
        }
        uint8_t rwd_input[crypto_hash_sha512_BYTES];
        crypto_hash_sha512_state rwd_state;
        crypto_hash_sha512_init(&rwd_state);
        crypto_hash_sha512_update(&rwd_state,
                                  reinterpret_cast<const uint8_t *>(labels::kKsfContext),
                                  labels::kKsfContextLength);
        crypto_hash_sha512_update(&rwd_state, oprf_output, oprf_output_length);
        crypto_hash_sha512_update(&rwd_state, secure_key, secure_key_length);
        crypto_hash_sha512_final(&rwd_state, rwd_input);

        uint8_t salt_full[crypto_hash_sha512_BYTES];
        crypto_hash_sha512_state salt_state;
        crypto_hash_sha512_init(&salt_state);
        crypto_hash_sha512_update(&salt_state,
                                  reinterpret_cast<const uint8_t *>(labels::kKsfSaltLabel),
                                  labels::kKsfSaltLabelLength);
        crypto_hash_sha512_update(&salt_state, oprf_output, oprf_output_length);
        crypto_hash_sha512_final(&salt_state, salt_full);

        uint8_t salt[crypto_pwhash_SALTBYTES];
        std::copy_n(salt_full, sizeof(salt), salt);

        if (crypto_pwhash(randomized_pwd, randomized_pwd_length,
                          reinterpret_cast<const char *>(rwd_input), sizeof(rwd_input),
                          salt, kKsfOpslimit, kKsfMemlimit,
                          crypto_pwhash_ALG_ARGON2ID13) != 0) [[unlikely]] {
            sodium_memzero(rwd_input, sizeof(rwd_input));
            sodium_memzero(salt_full, sizeof(salt_full));
            sodium_memzero(salt, sizeof(salt));
            return Result::CryptoError;
        }
        sodium_memzero(rwd_input, sizeof(rwd_input));
        sodium_memzero(salt_full, sizeof(salt_full));
        sodium_memzero(salt, sizeof(salt));
        return Result::Success;
    }

    Result verify_hmac(const uint8_t *key, size_t key_length,
                       const uint8_t *message, size_t message_length,
                       const uint8_t *mac) {
        if (!key || key_length == 0 || !message || message_length == 0 || !mac) [[unlikely]] {
            return Result::InvalidInput;
        }
        if (!init()) {
            return Result::CryptoError;
        }
        uint8_t computed_mac[crypto_auth_hmacsha512_BYTES];
        if (const Result result = hmac(key, key_length, message, message_length, computed_mac);
            result != Result::Success) [[unlikely]] {
            sodium_memzero(computed_mac, sizeof(computed_mac));
            return result;
        }
        if (crypto_verify_64(mac, computed_mac) != 0) [[unlikely]] {
            sodium_memzero(computed_mac, sizeof(computed_mac));
            return Result::AuthenticationError;
        }
        sodium_memzero(computed_mac, sizeof(computed_mac));
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
        if (info_length > 0 && !info) [[unlikely]] {
            return Result::InvalidInput;
        }
        constexpr size_t hash_length = crypto_auth_hmacsha512_BYTES;
        constexpr size_t kHkdfMaxBlocks = 255;
        const size_t n = (okm_length + hash_length - 1) / hash_length;
        if (n > kHkdfMaxBlocks) [[unlikely]] {
            return Result::InvalidInput;
        }
        secure_bytes t_prev(hash_length);
        secure_bytes t_current(hash_length);
        const size_t max_input_size = hash_length + info_length + 1;
        secure_bytes input;
        input.reserve(max_input_size);
        for (size_t i = 1; i <= n; ++i) {
            input.clear();
            if (i > 1) [[likely]] {
                input.insert(input.end(), t_prev.begin(), t_prev.end());
            }
            if (info && info_length > 0) [[likely]] {
                input.insert(input.end(), info, info + info_length);
            }
            input.push_back(static_cast<uint8_t>(i));
            if (const Result result = hmac(prk, prk_length, input.data(), input.size(), t_current.data());
                result != Result::Success) [[unlikely]] {
                return result;
            }
            const size_t copy_length = std::min(hash_length, okm_length - (i - 1) * hash_length);
            std::copy_n(t_current.begin(), static_cast<std::ptrdiff_t>(copy_length),
                        okm + (i - 1) * hash_length);
            std::swap(t_prev, t_current);
        }
        if (!t_prev.empty()) {
            sodium_memzero(t_prev.data(), t_prev.size());
        }
        if (!t_current.empty()) {
            sodium_memzero(t_current.data(), t_current.size());
        }
        if (!input.empty()) {
            sodium_memzero(input.data(), input.size());
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
        if (key_length != crypto_secretbox_KEYBYTES) [[unlikely]] {
            return Result::InvalidInput;
        }
        if (!init()) {
            return Result::CryptoError;
        }
        crypto_secretbox_detached(ciphertext, auth_tag, plaintext, plaintext_length, nonce, key);
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
        if (key_length != crypto_secretbox_KEYBYTES) [[unlikely]] {
            return Result::InvalidInput;
        }
        if (!init()) {
            return Result::CryptoError;
        }
        if (crypto_secretbox_open_detached(plaintext, ciphertext, auth_tag, ciphertext_length, nonce, key) != 0) [[unlikely]] {
            return Result::AuthenticationError;
        }
        return Result::Success;
    }
}
