#include "opaque/opaque.h"
#include <sodium.h>
#include <algorithm>


namespace ecliptix::security::opaque::oblivious_prf {
    static constexpr uint8_t CONTEXTSTRING[] = "OPAQUE-OPRF";
    static constexpr size_t CONTEXTSTRING_LEN = sizeof(CONTEXTSTRING) - 1;

    Result hash_to_group(const uint8_t *input, size_t input_length, uint8_t *point) {
        if (!input || input_length == 0 || !point) [[unlikely]] {
            return Result::InvalidInput;
        }
        secure_bytes full_input(CONTEXTSTRING_LEN + 1 + input_length);
        std::copy_n(CONTEXTSTRING, CONTEXTSTRING_LEN, full_input.begin());
        full_input[CONTEXTSTRING_LEN] = 0x00;
        std::copy_n(input, input_length, full_input.begin() + CONTEXTSTRING_LEN + 1);
        uint8_t hash[crypto_hash_sha512_BYTES];
        crypto_hash_sha512(hash, full_input.data(), full_input.size());
        if (crypto_core_ristretto255_from_hash(point, hash) != 0) [[unlikely]] {
            return Result::CryptoError;
        }
        return Result::Success;
    }

    Result blind(const uint8_t *input, size_t input_length,
                 uint8_t *blinded_element, uint8_t *blind_scalar) {
        if (!input || input_length == 0 || !blinded_element || !blind_scalar) [[unlikely]] {
            return Result::InvalidInput;
        }
        crypto_core_ristretto255_scalar_random(blind_scalar);
        uint8_t element[crypto_core_ristretto255_BYTES];
        if (const Result result = hash_to_group(input, input_length, element); result != Result::Success) [[unlikely]] {
            return result;
        }
        if (crypto_scalarmult_ristretto255(blinded_element, blind_scalar, element) != 0) [[unlikely]] {
            return Result::CryptoError;
        }
        return Result::Success;
    }

    Result evaluate(const uint8_t *blinded_element, const uint8_t *private_key,
                    uint8_t *evaluated_element) {
        if (!blinded_element || !private_key || !evaluated_element) [[unlikely]] {
            return Result::InvalidInput;
        }
        if (crypto_scalarmult_ristretto255(evaluated_element, private_key, blinded_element) != 0) [[unlikely]] {
            return Result::CryptoError;
        }
        return Result::Success;
    }

    Result finalize(const uint8_t *input, size_t input_length,
                    const uint8_t *blind_scalar,
                    const uint8_t *evaluated_element,
                    uint8_t *oprf_output) {
        if (!input || input_length == 0 || !blind_scalar ||
            !evaluated_element || !oprf_output) [[unlikely]] {
            return Result::InvalidInput;
        }
        uint8_t blind_scalar_inv[crypto_core_ristretto255_SCALARBYTES];
        if (crypto_core_ristretto255_scalar_invert(blind_scalar_inv, blind_scalar) != 0) [[unlikely]] {
            return Result::CryptoError;
        }
        uint8_t unblinded_element[crypto_core_ristretto255_BYTES];
        if (crypto_scalarmult_ristretto255(unblinded_element, blind_scalar_inv, evaluated_element) != 0) [[unlikely]] {
            return Result::CryptoError;
        }
        secure_bytes hash_input(CONTEXTSTRING_LEN + 1 + input_length + crypto_core_ristretto255_BYTES);
        size_t offset = 0;
        std::copy_n(CONTEXTSTRING, CONTEXTSTRING_LEN,
                  hash_input.begin() + static_cast<std::ptrdiff_t>(offset));
        offset += CONTEXTSTRING_LEN;
        hash_input[offset] = 0x01;
        offset += 1;
        std::copy_n(input, input_length, hash_input.begin() + static_cast<std::ptrdiff_t>(offset));
        offset += input_length;
        std::copy_n(unblinded_element, crypto_core_ristretto255_BYTES,
                  hash_input.begin() + static_cast<std::ptrdiff_t>(offset));
        crypto_hash_sha512(oprf_output, hash_input.data(), hash_input.size());
        return Result::Success;
    }

    class OPRFServer {
        secure_bytes private_key_;

    public:
        OPRFServer() : private_key_(crypto_core_ristretto255_SCALARBYTES) {
            crypto_core_ristretto255_scalar_random(private_key_.data());
        }

        explicit OPRFServer(const uint8_t *private_key)
            : private_key_(crypto_core_ristretto255_SCALARBYTES) {
            std::copy_n(private_key, crypto_core_ristretto255_SCALARBYTES,
                        private_key_.begin());
        }

        Result evaluate_request(const uint8_t *blinded_element, uint8_t *evaluated_element) const {
            return evaluate(blinded_element, private_key_.data(), evaluated_element);
        }

        [[nodiscard]] const secure_bytes &get_private_key() const {
            return private_key_;
        }
    };

    class OPRFClient {
        secure_bytes blind_scalar_;
        secure_bytes input_;

    public:
        Result create_request(const uint8_t *input, const size_t input_length,
                              uint8_t *blinded_element) {
            if (!input || input_length == 0 || !blinded_element) [[unlikely]] {
                return Result::InvalidInput;
            }
            input_.assign(input, input + input_length);
            blind_scalar_.resize(crypto_core_ristretto255_SCALARBYTES);
            return blind(input, input_length, blinded_element, blind_scalar_.data());
        }

        Result finalize_response(const uint8_t *evaluated_element, uint8_t *oprf_output) const {
            if (!evaluated_element || !oprf_output) [[unlikely]] {
                return Result::InvalidInput;
            }
            return finalize(input_.data(), input_.size(), blind_scalar_.data(),
                            evaluated_element, oprf_output);
        }
    };
} // namespace ecliptix::security::opaque::oblivious_prf
