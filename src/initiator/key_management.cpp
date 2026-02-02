#include "opaque/initiator.h"
#include <sodium.h>
#include <algorithm>
#include <utility>
#include <stdexcept>

namespace ecliptix::security::opaque::initiator {
    Result create_registration_request_impl(const uint8_t *secure_key, size_t secure_key_length,
                                            RegistrationRequest &request, InitiatorState &state);

    Result finalize_registration_impl(const uint8_t *registration_response, size_t response_length,
                                      const uint8_t *expected_responder_public_key, size_t expected_key_length,
                                      InitiatorState &state, RegistrationRecord &record);

    Result generate_ke1_impl(const uint8_t *secure_key, size_t secure_key_length,
                             KE1 &ke1, InitiatorState &state);

    Result generate_ke3_impl(const uint8_t *ke2_data, size_t ke2_length,
                             const uint8_t *responder_public_key, InitiatorState &state, KE3 &ke3);

    Result initiator_finish_impl(InitiatorState &state, secure_bytes &session_key, secure_bytes &master_key);

    InitiatorState::InitiatorState() : secure_key(0), initiator_private_key(PRIVATE_KEY_LENGTH),
                                       initiator_public_key(PUBLIC_KEY_LENGTH),
                                       initiator_ephemeral_private_key(PRIVATE_KEY_LENGTH),
                                       initiator_ephemeral_public_key(PUBLIC_KEY_LENGTH),
                                       responder_public_key(PUBLIC_KEY_LENGTH),
                                       session_key(0),
                                       oblivious_prf_blind_scalar(PRIVATE_KEY_LENGTH),
                                       initiator_nonce(NONCE_LENGTH),
                                       master_key(0),
                                       pq_ephemeral_public_key(0),
                                       pq_ephemeral_secret_key(0),
                                       pq_shared_secret(0) {
    }

    InitiatorState::~InitiatorState() {
        if (!secure_key.empty()) {
            sodium_memzero(secure_key.data(), secure_key.size());
        }
        sodium_memzero(initiator_private_key.data(), initiator_private_key.size());
        sodium_memzero(initiator_public_key.data(), initiator_public_key.size());
        sodium_memzero(initiator_ephemeral_private_key.data(), initiator_ephemeral_private_key.size());
        sodium_memzero(initiator_ephemeral_public_key.data(), initiator_ephemeral_public_key.size());
        sodium_memzero(responder_public_key.data(), responder_public_key.size());
        if (!session_key.empty()) {
            sodium_memzero(session_key.data(), session_key.size());
        }
        sodium_memzero(oblivious_prf_blind_scalar.data(), oblivious_prf_blind_scalar.size());
        sodium_memzero(initiator_nonce.data(), initiator_nonce.size());
        if (!master_key.empty()) {
            sodium_memzero(master_key.data(), master_key.size());
        }

        if (!pq_ephemeral_public_key.empty()) {
            sodium_memzero(pq_ephemeral_public_key.data(), pq_ephemeral_public_key.size());
        }
        if (!pq_ephemeral_secret_key.empty()) {
            sodium_memzero(pq_ephemeral_secret_key.data(), pq_ephemeral_secret_key.size());
        }
        if (!pq_shared_secret.empty()) {
            sodium_memzero(pq_shared_secret.data(), pq_shared_secret.size());
        }
    }

    class OpaqueInitiator::Impl {
        ResponderPublicKey responder_public_key_;

    public:
        explicit Impl(ResponderPublicKey responder_public_key)
            : responder_public_key_(std::move(responder_public_key)) {
            if (!crypto::init()) {
                throw std::runtime_error("Failed to initialize cryptographic library");
            }
            if (!responder_public_key_.verify()) {
                throw std::runtime_error("Invalid responder public key");
            }
        }

        static Result create_registration_request(const uint8_t *secure_key, size_t secure_key_length,
                                                  RegistrationRequest &request, InitiatorState &state) {
            return create_registration_request_impl(secure_key, secure_key_length, request, state);
        }

        Result finalize_registration(const uint8_t *registration_response, size_t response_length,
                                     InitiatorState &state, RegistrationRecord &record) const {
            return finalize_registration_impl(registration_response, response_length,
                                              responder_public_key_.key_data.data(),
                                              responder_public_key_.key_data.size(),
                                              state, record);
        }

        static Result generate_ke1(const uint8_t *secure_key, size_t secure_key_length,
                                   KE1 &ke1, InitiatorState &state) {
            return generate_ke1_impl(secure_key, secure_key_length, ke1, state);
        }

        Result generate_ke3(const uint8_t *ke2_data, size_t ke2_length,
                            InitiatorState &state, KE3 &ke3) const {
            return generate_ke3_impl(ke2_data, ke2_length, responder_public_key_.key_data.data(), state, ke3);
        }

        static Result initiator_finish(InitiatorState &state, secure_bytes &session_key, secure_bytes &master_key) {
            return initiator_finish_impl(state, session_key, master_key);
        }

        [[nodiscard]] const ResponderPublicKey &get_responder_public_key() const {
            return responder_public_key_;
        }
    };

    OpaqueInitiator::OpaqueInitiator(const ResponderPublicKey &responder_public_key)
        : impl_(std::make_unique<Impl>(responder_public_key)) {
    }

    OpaqueInitiator::~OpaqueInitiator() = default;

    Result OpaqueInitiator::create_registration_request(const uint8_t *secure_key, size_t secure_key_length,
                                                        RegistrationRequest &request, InitiatorState &state) {
        return Impl::create_registration_request(secure_key, secure_key_length, request, state);
    }

    Result OpaqueInitiator::finalize_registration(const uint8_t *registration_response, size_t response_length,
                                                  InitiatorState &state, RegistrationRecord &record) const {
        return impl_->finalize_registration(registration_response, response_length, state, record);
    }

    Result OpaqueInitiator::generate_ke1(const uint8_t *secure_key, size_t secure_key_length,
                                         KE1 &ke1, InitiatorState &state) {
        return Impl::generate_ke1(secure_key, secure_key_length, ke1, state);
    }

    Result OpaqueInitiator::generate_ke3(const uint8_t *ke2_data, size_t ke2_length,
                                         InitiatorState &state, KE3 &ke3) const {
        return impl_->generate_ke3(ke2_data, ke2_length, state, ke3);
    }

    Result OpaqueInitiator::initiator_finish(InitiatorState &state, secure_bytes &session_key,
                                             secure_bytes &master_key) {
        return Impl::initiator_finish(state, session_key, master_key);
    }
}
