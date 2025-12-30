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
        if (!secure_key || secure_key_length == 0 ||
            secure_key_length > MAX_SECURE_KEY_LENGTH) [[unlikely]] {
            return Result::InvalidInput;
        }
        if (!crypto::init()) {
            return Result::CryptoError;
        }
        do {
            crypto_core_ristretto255_scalar_random(state.initiator_private_key.data());
        } while (sodium_is_zero(state.initiator_private_key.data(), state.initiator_private_key.size()) == 1);
        if (crypto_scalarmult_ristretto255_base(state.initiator_public_key.data(),
                                                state.initiator_private_key.data()) != 0) [[unlikely]] {
            return Result::CryptoError;
        }
        state.secure_key.assign(secure_key, secure_key + secure_key_length);
        return oblivious_prf::blind(secure_key, secure_key_length, request.data.data(),
                                    state.oblivious_prf_blind_scalar.data());
    }

    Result finalize_registration_impl(const uint8_t *registration_response, size_t response_length,
                                      const uint8_t *expected_responder_public_key, size_t expected_key_length,
                                      InitiatorState &state, RegistrationRecord &record) {
        if (!registration_response || response_length != REGISTRATION_RESPONSE_LENGTH ||
            !expected_responder_public_key || expected_key_length != PUBLIC_KEY_LENGTH) {
            return Result::InvalidInput;
        }
        if (!crypto::init()) {
            return Result::CryptoError;
        }
        const uint8_t *evaluated_element = registration_response;
        const uint8_t *responder_public_key = registration_response + crypto_core_ristretto255_BYTES;
        if (crypto_core_ristretto255_is_valid_point(responder_public_key) != 1 ||
            util::is_all_zero(responder_public_key, PUBLIC_KEY_LENGTH)) {
            return Result::InvalidPublicKey;
        }
        if (crypto_verify_32(responder_public_key, expected_responder_public_key) != 0) {
            return Result::AuthenticationError;
        }
        auto result = Result::Success;
        uint8_t oblivious_prf_output[crypto_hash_sha512_BYTES] = {};
        uint8_t randomized_pwd[crypto_hash_sha512_BYTES] = {};
        Envelope env;
        size_t offset = 0;
        result = oblivious_prf::finalize(state.secure_key.data(), state.secure_key.size(),
                                         state.oblivious_prf_blind_scalar.data(),
                                         evaluated_element, oblivious_prf_output);
        if (result != Result::Success) {
            goto cleanup;
        }
        result = crypto::derive_randomized_password(oblivious_prf_output, sizeof(oblivious_prf_output),
                                                    state.secure_key.data(), state.secure_key.size(),
                                                    randomized_pwd, sizeof(randomized_pwd));
        if (result != Result::Success) {
            goto cleanup;
        }

        result = envelope::seal(randomized_pwd, sizeof(randomized_pwd),
                                responder_public_key,
                                state.initiator_private_key.data(),
                                state.initiator_public_key.data(),
                                env);
        if (result != Result::Success) {
            goto cleanup;
        }
        std::copy_n(responder_public_key, PUBLIC_KEY_LENGTH,
                    state.responder_public_key.begin());
        record.envelope.resize(env.nonce.size() + env.ciphertext.size() + env.auth_tag.size());
        offset = 0;
        std::ranges::copy(env.nonce, record.envelope.begin() + static_cast<std::ptrdiff_t>(offset));
        offset += env.nonce.size();
        std::ranges::copy(env.ciphertext,
                          record.envelope.begin() + static_cast<std::ptrdiff_t>(offset));
        offset += env.ciphertext.size();
        std::ranges::copy(env.auth_tag,
                          record.envelope.begin() + static_cast<std::ptrdiff_t>(offset));
        std::ranges::copy(state.initiator_public_key,
                          record.initiator_public_key.begin());
        result = Result::Success;
    cleanup:
        sodium_memzero(randomized_pwd, sizeof(randomized_pwd));
        sodium_memzero(oblivious_prf_output, sizeof(oblivious_prf_output));
        return result;
    }
}
