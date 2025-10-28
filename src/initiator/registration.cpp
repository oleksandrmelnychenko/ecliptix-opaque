#include "opaque/initiator.h"
#include <sodium.h>
#include <algorithm>
using namespace ecliptix::security::opaque;

namespace ecliptix::security::opaque::initiator {
    RegistrationRequest::RegistrationRequest() : data(REGISTRATION_REQUEST_LENGTH) {
    }

    RegistrationRecord::RegistrationRecord() : envelope(ENVELOPE_LENGTH), initiator_public_key(PUBLIC_KEY_LENGTH) {
    }

    Result create_registration_request_impl(const uint8_t *secure_key, size_t secure_key_length,
                                            RegistrationRequest &request, InitiatorState &state) {
        if (!secure_key || secure_key_length == 0) [[unlikely]] {
            return Result::InvalidInput;
        }
        if (const Result result = crypto::random_bytes(state.initiator_private_key.data(), PRIVATE_KEY_LENGTH);
            result != Result::Success) [[unlikely]] {
            return result;
        }
        if (crypto_scalarmult_ristretto255_base(state.initiator_public_key.data(),
                                                state.initiator_private_key.data()) != 0) [[unlikely]] {
            return Result::CryptoError;
        }
        state.secure_key.assign(secure_key, secure_key + secure_key_length);
        return oblivious_prf::blind(secure_key, secure_key_length, request.data.data(),
                                    state.oblivious_prf_blind_scalar.data());
    }

    Result finalize_registration_impl(const uint8_t *registration_response, size_t response_length,
                                      InitiatorState &state, RegistrationRecord &record) {
        if (!registration_response || response_length != REGISTRATION_RESPONSE_LENGTH) {
            return Result::InvalidInput;
        }
        const uint8_t *evaluated_element = registration_response;
        const uint8_t *responder_public_key = registration_response + crypto_core_ristretto255_BYTES;
        uint8_t oblivious_prf_output[crypto_hash_sha512_BYTES];
        Result result = oblivious_prf::finalize(state.secure_key.data(), state.secure_key.size(),
                                                state.oblivious_prf_blind_scalar.data(),
                                                evaluated_element, oblivious_prf_output);
        if (result != Result::Success) {
            return result;
        }
        uint8_t randomized_pwd[crypto_hash_sha512_BYTES];
        crypto_hash_sha512_state hash_state;
        crypto_hash_sha512_init(&hash_state);
        crypto_hash_sha512_update(&hash_state, oblivious_prf_output, sizeof(oblivious_prf_output));
        crypto_hash_sha512_update(&hash_state, state.secure_key.data(), state.secure_key.size());
        crypto_hash_sha512_final(&hash_state, randomized_pwd);
        std::copy_n(responder_public_key, PUBLIC_KEY_LENGTH,
                    state.responder_public_key.begin());
        Envelope env;
        result = envelope::seal(randomized_pwd, sizeof(randomized_pwd),
                                responder_public_key,
                                state.initiator_private_key.data(),
                                state.initiator_public_key.data(),
                                state.master_key.data(),
                                env);
        if (result != Result::Success) {
            return result;
        }
        record.envelope.resize(env.nonce.size() + env.ciphertext.size() + env.auth_tag.size());
        size_t offset = 0;
        std::ranges::copy(env.nonce, record.envelope.begin() + static_cast<std::ptrdiff_t>(offset));
        offset += env.nonce.size();
        std::ranges::copy(env.ciphertext,
                          record.envelope.begin() + static_cast<std::ptrdiff_t>(offset));
        offset += env.ciphertext.size();
        std::ranges::copy(env.auth_tag,
                          record.envelope.begin() + static_cast<std::ptrdiff_t>(offset));
        std::ranges::copy(state.initiator_public_key,
                          record.initiator_public_key.begin());
        sodium_memzero(randomized_pwd, sizeof(randomized_pwd));
        sodium_memzero(oblivious_prf_output, sizeof(oblivious_prf_output));
        return Result::Success;
    }
}
