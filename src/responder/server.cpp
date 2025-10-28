#include "opaque/responder.h"
#include <sodium.h>
#include <stdexcept>

namespace ecliptix::security::opaque::responder {
    namespace {
        namespace crypto = crypto;
    }

    ResponderKeyPair::ResponderKeyPair() : private_key(PRIVATE_KEY_LENGTH), public_key(PUBLIC_KEY_LENGTH) {
    }

    ResponderKeyPair::~ResponderKeyPair() {
        sodium_memzero(private_key.data(), private_key.size());
        sodium_memzero(public_key.data(), public_key.size());
    }

    Result ResponderKeyPair::generate(ResponderKeyPair &keypair) {
        if (const Result result = crypto::random_bytes(keypair.private_key.data(), PRIVATE_KEY_LENGTH);
            result != Result::Success) [[unlikely]] {
            return result;
        }
        if (crypto_scalarmult_ristretto255_base(keypair.public_key.data(),
                                                keypair.private_key.data()) != 0) [[unlikely]] {
            return Result::CryptoError;
        }
        return Result::Success;
    }

    class OpaqueResponder::Impl {
        ResponderKeyPair responder_keypair_;

    public:
        explicit Impl(const ResponderKeyPair &responder_keypair) : responder_keypair_(responder_keypair) {
            if (!crypto::init()) {
                throw std::runtime_error("Failed to initialize cryptographic library");
            }
        }

        Result create_registration_response(const uint8_t *registration_request, const size_t request_length,
                                            RegistrationResponse &response, ResponderCredentials &credentials) const {
            return create_registration_response_impl(registration_request, request_length,
                                                     responder_keypair_.private_key,
                                                     responder_keypair_.public_key,
                                                     response, credentials);
        }

        Result generate_ke2(const uint8_t *ke1_data, const size_t ke1_length,
                            const ResponderCredentials &credentials,
                            KE2 &ke2, ResponderState &state) const {
            return generate_ke2_impl(ke1_data, ke1_length, credentials,
                                     responder_keypair_.private_key,
                                     responder_keypair_.public_key,
                                     ke2, state);
        }

        static Result responder_finish(const uint8_t *ke3_data, const size_t ke3_length,
                                       const ResponderState &state, secure_bytes &session_key) {
            return responder_finish_impl(ke3_data, ke3_length, state, session_key);
        }

        [[nodiscard]] const secure_bytes &get_public_key() const {
            return responder_keypair_.public_key;
        }
    };

    OpaqueResponder::OpaqueResponder(const ResponderKeyPair &responder_keypair) : impl_(
        std::make_unique<Impl>(responder_keypair)) {
    }

    OpaqueResponder::~OpaqueResponder() = default;

    Result OpaqueResponder::create_registration_response(const uint8_t *registration_request,
                                                         const size_t request_length,
                                                         RegistrationResponse &response,
                                                         ResponderCredentials &credentials) const {
        return impl_->create_registration_response(registration_request, request_length, response, credentials);
    }

    Result OpaqueResponder::generate_ke2(const uint8_t *ke1_data, const size_t ke1_length,
                                         const ResponderCredentials &credentials,
                                         KE2 &ke2, ResponderState &state) const {
        return impl_->generate_ke2(ke1_data, ke1_length, credentials, ke2, state);
    }

    Result OpaqueResponder::responder_finish(const uint8_t *ke3_data, const size_t ke3_length,
                                             const ResponderState &state, secure_bytes &session_key) {
        return Impl::responder_finish(ke3_data, ke3_length, state, session_key);
    }

    const secure_bytes &OpaqueResponder::get_public_key() const {
        return impl_->get_public_key();
    }
}
