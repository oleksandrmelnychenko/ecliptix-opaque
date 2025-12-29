#include "opaque/responder.h"
#include <sodium.h>
#include <algorithm>

namespace ecliptix::security::opaque::responder {
    namespace {
        namespace oblivious_prf = oblivious_prf;
        namespace crypto = crypto;
    }

    RegistrationResponse::RegistrationResponse() : data(REGISTRATION_RESPONSE_LENGTH) {
    }

    Result create_registration_response_impl(const uint8_t *registration_request, const size_t request_length,
                                             const secure_bytes &responder_private_key,
                                             const secure_bytes &responder_public_key,
                                             const uint8_t *account_id,
                                             const size_t account_id_length,
                                             RegistrationResponse &response) {
        if (!registration_request || request_length != REGISTRATION_REQUEST_LENGTH ||
            !account_id || account_id_length == 0) [[unlikely]] {
            return Result::InvalidInput;
        }
        if (!crypto::init()) {
            return Result::CryptoError;
        }

        const uint8_t *blinded_element = registration_request;
        bool all_zero = true;
        for (size_t i = 0; i < crypto_core_ristretto255_BYTES; ++i) {
            if (blinded_element[i] != 0) {
                all_zero = false;
                break;
            }
        }
        if (all_zero || crypto_core_ristretto255_is_valid_point(blinded_element) != 1) {
            return Result::InvalidInput;
        }
        uint8_t evaluated_element[crypto_core_ristretto255_BYTES];
        uint8_t oprf_key[PRIVATE_KEY_LENGTH] = {};
        Result result = crypto::derive_oprf_key(responder_private_key.data(), responder_private_key.size(),
                                                account_id, account_id_length, oprf_key);
        if (result != Result::Success) [[unlikely]] {
            sodium_memzero(oprf_key, sizeof(oprf_key));
            return result;
        }
        result = oblivious_prf::evaluate(blinded_element, oprf_key, evaluated_element);
        sodium_memzero(oprf_key, sizeof(oprf_key));
        if (result != Result::Success) [[unlikely]] {
            return result;
        }

        size_t offset = 0;
        std::copy_n(evaluated_element, crypto_core_ristretto255_BYTES,
                    response.data.begin() + static_cast<std::ptrdiff_t>(offset));
        offset += crypto_core_ristretto255_BYTES;
        std::ranges::copy(responder_public_key,
                          response.data.begin() + static_cast<std::ptrdiff_t>(offset));
        return Result::Success;
    }

    Result build_credentials(const uint8_t *registration_record, size_t record_length,
                             ResponderCredentials &credentials) {
        const size_t record_expected = REGISTRATION_RECORD_LENGTH;
        if (!registration_record || record_length < record_expected) {
            return Result::InvalidInput;
        }
        if (!crypto::init()) {
            return Result::CryptoError;
        }
        const uint8_t *initiator_public_key = registration_record + ENVELOPE_LENGTH;
        if (crypto_core_ristretto255_is_valid_point(initiator_public_key) != 1) {
            return Result::InvalidPublicKey;
        }
        bool all_zero = true;
        for (size_t i = 0; i < PUBLIC_KEY_LENGTH; ++i) {
            if (initiator_public_key[i] != 0) {
                all_zero = false;
                break;
            }
        }
        if (all_zero) {
            return Result::InvalidPublicKey;
        }

        credentials.envelope.assign(registration_record, registration_record + ENVELOPE_LENGTH);
        credentials.initiator_public_key.assign(initiator_public_key, initiator_public_key + PUBLIC_KEY_LENGTH);
        return Result::Success;
    }
}
