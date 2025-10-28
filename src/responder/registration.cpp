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

    Result create_registration_response_impl(const uint8_t *registration_request, size_t request_length,
                                             const secure_bytes &responder_private_key,
                                             const secure_bytes &responder_public_key,
                                             RegistrationResponse &response,
                                             ResponderCredentials &credentials) {
        (void) responder_private_key;
        if (!registration_request || request_length != REGISTRATION_REQUEST_LENGTH) [[unlikely]] {
            return Result::InvalidInput;
        }

        Result result = crypto::random_bytes(credentials.masking_key.data(), PRIVATE_KEY_LENGTH);
        if (result != Result::Success) [[unlikely]] {
            return result;
        }

        const uint8_t *blinded_element = registration_request;
        uint8_t evaluated_element[crypto_core_ristretto255_BYTES];
        result = oblivious_prf::evaluate(blinded_element, credentials.masking_key.data(), evaluated_element);
        if (result != Result::Success) [[unlikely]] {
            return result;
        }

        uint8_t masking_nonce[NONCE_LENGTH];
        result = crypto::random_bytes(masking_nonce, NONCE_LENGTH);
        if (result != Result::Success) [[unlikely]] {
            return result;
        }

        size_t offset = 0;
        std::copy_n(evaluated_element, crypto_core_ristretto255_BYTES,
                  response.data.begin() + static_cast<std::ptrdiff_t>(offset));
        offset += crypto_core_ristretto255_BYTES;
        std::ranges::copy(responder_public_key,
                          response.data.begin() + static_cast<std::ptrdiff_t>(offset));
        offset += PUBLIC_KEY_LENGTH;
        std::copy_n(masking_nonce, NONCE_LENGTH,
                  response.data.begin() + static_cast<std::ptrdiff_t>(offset));
        credentials.envelope.clear();
        return Result::Success;
    }
}
