#include "opaque/server.h"
#include <sodium.h>
#include <algorithm>
namespace ecliptix::security::opaque::server {
namespace {
    namespace oprf = ecliptix::security::opaque::oprf;
    namespace crypto = ecliptix::security::opaque::crypto;
}
RegistrationResponse::RegistrationResponse() : data(REGISTRATION_RESPONSE_LENGTH) {}
Result create_registration_response_impl(const uint8_t* registration_request, size_t request_length,
                                        const secure_bytes& server_private_key,
                                        const secure_bytes& server_public_key,
                                        RegistrationResponse& response,
                                        ServerCredentials& credentials) {
    (void)server_private_key;
    if (!registration_request || request_length != REGISTRATION_REQUEST_LENGTH) {
        return Result::InvalidInput;
    }
    // Generate OPRF private key first
    crypto::random_bytes(credentials.masking_key.data(), PRIVATE_KEY_LENGTH);

    const uint8_t* blinded_element = registration_request;
    uint8_t evaluated_element[crypto_core_ristretto255_BYTES];
    Result result = oprf::evaluate(blinded_element, credentials.masking_key.data(), evaluated_element);
    if (result != Result::Success) {
        return result;
    }
    uint8_t masking_nonce[NONCE_LENGTH];
    crypto::random_bytes(masking_nonce, NONCE_LENGTH);
    size_t offset = 0;
    std::copy(evaluated_element, evaluated_element + crypto_core_ristretto255_BYTES,
             response.data.begin() + offset);
    offset += crypto_core_ristretto255_BYTES;
    std::copy(server_public_key.begin(), server_public_key.end(),
             response.data.begin() + offset);
    offset += PUBLIC_KEY_LENGTH;
    std::copy(masking_nonce, masking_nonce + NONCE_LENGTH,
             response.data.begin() + offset);
    // Server doesn't create envelope - client will send it later for storage
    credentials.envelope.clear();
    return Result::Success;
}
}