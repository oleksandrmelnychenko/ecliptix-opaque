#include "opaque/initiator.h"
#include "opaque/protocol.h"
#include "opaque/pq.h"
#include "opaque/secure_cleanup.h"
#include "opaque/debug_log.h"
#include <sodium.h>
#include <algorithm>
using namespace ecliptix::security::opaque;

namespace ecliptix::security::opaque::initiator {
    RegistrationRequest::RegistrationRequest() : data(REGISTRATION_REQUEST_LENGTH) {
    }

    RegistrationRecord::RegistrationRecord() : envelope(ENVELOPE_LENGTH),
                                               initiator_public_key(PUBLIC_KEY_LENGTH) {
    }

    Result create_registration_request_impl(const uint8_t *secure_key, size_t secure_key_length,
                                            RegistrationRequest &request, InitiatorState &state) {
        log::section("AGENT: Create Registration Request (PQ)");
        if (!secure_key || secure_key_length == 0 ||
            secure_key_length > MAX_SECURE_KEY_LENGTH) [[unlikely]] {
            return Result::InvalidInput;
        }
        if (!crypto::init()) {
            return Result::CryptoError;
        }
        log::hex("secure_key (password)", secure_key, secure_key_length);

        do {
            crypto_core_ristretto255_scalar_random(state.initiator_private_key.data());
        } while (sodium_is_zero(state.initiator_private_key.data(), state.initiator_private_key.size()) == 1);
        log::hex("initiator_private_key (EC)", state.initiator_private_key);

        if (crypto_scalarmult_ristretto255_base(state.initiator_public_key.data(),
                                                state.initiator_private_key.data()) != 0) [[unlikely]] {
            return Result::CryptoError;
        }
        log::hex("initiator_public_key (EC)", state.initiator_public_key);

        state.secure_key.assign(secure_key, secure_key + secure_key_length);
        const auto result = oblivious_prf::blind(secure_key, secure_key_length, request.data.data(),
                                           state.oblivious_prf_blind_scalar.data());
        log::hex("oblivious_prf_blind_scalar", state.oblivious_prf_blind_scalar);
        log::hex("registration_request (blinded element)", request.data);
        return result;
    }

    Result finalize_registration_impl(const uint8_t *registration_response, size_t response_length,
                                      const uint8_t *expected_responder_public_key, size_t expected_key_length,
                                      InitiatorState &state, RegistrationRecord &record) {
        log::section("AGENT: Finalize Registration (PQ)");
        if (!registration_response || response_length != REGISTRATION_RESPONSE_LENGTH ||
            !expected_responder_public_key || expected_key_length != PUBLIC_KEY_LENGTH) [[unlikely]] {
            return Result::InvalidInput;
        }
        if (!crypto::init()) {
            return Result::CryptoError;
        }
        log::hex("registration_response", registration_response, response_length);
        log::hex("expected_responder_public_key", expected_responder_public_key, expected_key_length);

        protocol::RegistrationResponseView response_view{};
        const Result parse_result = protocol::parse_registration_response(registration_response, response_length,
                                                                    response_view);
        if (parse_result != Result::Success) {
            return parse_result;
        }
        const uint8_t *evaluated_element = response_view.evaluated_element;
        const uint8_t *responder_public_key = response_view.responder_public_key;
        log::hex("evaluated_element (from response)", evaluated_element, crypto_core_ristretto255_BYTES);
        log::hex("responder_public_key (from response)", responder_public_key, PUBLIC_KEY_LENGTH);

        if (const Result key_result = crypto::validate_public_key(responder_public_key, PUBLIC_KEY_LENGTH);
            key_result != Result::Success) {
            return key_result;
        }
        if (crypto_verify_32(responder_public_key, expected_responder_public_key) != 0) {
            return Result::AuthenticationError;
        }

        SecureLocal<crypto_hash_sha512_BYTES> oblivious_prf_output;
        SecureLocal<crypto_hash_sha512_BYTES> randomized_pwd;
        Envelope env;

        auto success_cleanup = make_cleanup([&] {
            if (!state.secure_key.empty()) {
                sodium_memzero(state.secure_key.data(), state.secure_key.size());
                state.secure_key.clear();
            }
            if (!state.oblivious_prf_blind_scalar.empty()) {
                sodium_memzero(state.oblivious_prf_blind_scalar.data(), state.oblivious_prf_blind_scalar.size());
                state.oblivious_prf_blind_scalar.clear();
            }
        });

        OPAQUE_TRY(oblivious_prf::finalize(state.secure_key.data(), state.secure_key.size(),
                                            state.oblivious_prf_blind_scalar.data(),
                                            evaluated_element, oblivious_prf_output));
        log::hex("oblivious_prf_output", oblivious_prf_output.data(), oblivious_prf_output.size());

        OPAQUE_TRY(crypto::derive_randomized_password(oblivious_prf_output, oblivious_prf_output.size(),
                                                       state.secure_key.data(), state.secure_key.size(),
                                                       randomized_pwd, randomized_pwd.size()));
        log::hex("randomized_pwd", randomized_pwd.data(), randomized_pwd.size());

        OPAQUE_TRY(envelope::seal(randomized_pwd, randomized_pwd.size(),
                                   responder_public_key,
                                   state.initiator_private_key.data(),
                                   state.initiator_public_key.data(),
                                   env));
        log::hex("envelope.nonce", env.nonce);
        log::hex("envelope.ciphertext", env.ciphertext);
        log::hex("envelope.auth_tag", env.auth_tag);

        std::copy_n(responder_public_key, PUBLIC_KEY_LENGTH,
                    state.responder_public_key.begin());

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

        log::hex("registration_record.envelope", record.envelope);
        log::hex("registration_record.initiator_public_key (EC)", record.initiator_public_key);

        return Result::Success;
    }
}
