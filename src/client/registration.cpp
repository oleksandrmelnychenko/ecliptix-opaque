#include "opaque/client.h"
#include <sodium.h>
#include <algorithm>
using namespace ecliptix::security::opaque;
namespace ecliptix::security::opaque::client {
RegistrationRequest::RegistrationRequest() : data(REGISTRATION_REQUEST_LENGTH) {}
RegistrationRecord::RegistrationRecord() : envelope(ENVELOPE_LENGTH), client_public_key(PUBLIC_KEY_LENGTH) {}
Result create_registration_request_impl(const uint8_t* password, size_t password_length,
                                       RegistrationRequest& request, ClientState& state) {
    if (!password || password_length == 0) {
        return Result::InvalidInput;
    }
    crypto::random_bytes(state.client_private_key.data(), PRIVATE_KEY_LENGTH);
    if (crypto_scalarmult_ristretto255_base(state.client_public_key.data(),
                                           state.client_private_key.data()) != 0) {
        return Result::CryptoError;
    }
    state.password.assign(password, password + password_length);
    return oprf::blind(password, password_length, request.data.data(),
                      state.client_private_key.data());
}
Result finalize_registration_impl(const uint8_t* registration_response, size_t response_length,
                                 ClientState& state, RegistrationRecord& record) {
    if (!registration_response || response_length != REGISTRATION_RESPONSE_LENGTH) {
        return Result::InvalidInput;
    }
    const uint8_t* evaluated_element = registration_response;
    const uint8_t* server_public_key = registration_response + crypto_core_ristretto255_BYTES;
    uint8_t oprf_output[crypto_hash_sha512_BYTES];
    Result result = oprf::finalize(state.password.data(), state.password.size(),
                                  state.client_private_key.data(),
                                  evaluated_element, oprf_output);
    if (result != Result::Success) {
        return result;
    }
    uint8_t randomized_pwd[crypto_hash_sha512_BYTES];
    crypto_hash_sha512_state hash_state;
    crypto_hash_sha512_init(&hash_state);
    crypto_hash_sha512_update(&hash_state, oprf_output, sizeof(oprf_output));
    crypto_hash_sha512_update(&hash_state, state.password.data(), state.password.size());
    crypto_hash_sha512_final(&hash_state, randomized_pwd);
    std::copy(server_public_key, server_public_key + PUBLIC_KEY_LENGTH,
             state.server_public_key.begin());
    Envelope env;
    result = envelope::seal(randomized_pwd, sizeof(randomized_pwd),
                           server_public_key,
                           state.client_private_key.data(),
                           state.client_public_key.data(),
                           env);
    if (result != Result::Success) {
        return result;
    }
    record.envelope.resize(NONCE_LENGTH + MAC_LENGTH);
    std::copy(env.nonce.begin(), env.nonce.end(), record.envelope.begin());
    std::copy(env.auth_tag.begin(), env.auth_tag.end(),
             record.envelope.begin() + NONCE_LENGTH);
    std::copy(state.client_public_key.begin(), state.client_public_key.end(),
             record.client_public_key.begin());
    sodium_memzero(randomized_pwd, sizeof(randomized_pwd));
    sodium_memzero(oprf_output, sizeof(oprf_output));
    return Result::Success;
}
}