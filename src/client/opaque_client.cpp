#include "opaque/client.h"
#include <sodium.h>

namespace ecliptix::security::opaque::client {

RegistrationRequest::RegistrationRequest() : data(REGISTRATION_REQUEST_LENGTH) {}

RegistrationRecord::RegistrationRecord() : envelope(ENVELOPE_LENGTH), client_public_key(PUBLIC_KEY_LENGTH) {}

KE1::KE1() : client_nonce(NONCE_LENGTH), client_public_key(PUBLIC_KEY_LENGTH), credential_request(32) {}

KE3::KE3() : client_mac(MAC_LENGTH) {}

ClientState::ClientState() : password(0), client_private_key(PRIVATE_KEY_LENGTH),
                            client_public_key(PUBLIC_KEY_LENGTH),
                            server_public_key(PUBLIC_KEY_LENGTH),
                            session_key(0) {}

ClientState::~ClientState() {
    if (!password.empty()) {
        sodium_memzero(password.data(), password.size());
    }
    sodium_memzero(client_private_key.data(), client_private_key.size());
    sodium_memzero(client_public_key.data(), client_public_key.size());
    sodium_memzero(server_public_key.data(), server_public_key.size());
    if (!session_key.empty()) {
        sodium_memzero(session_key.data(), session_key.size());
    }
}

class OpaqueClient::Impl {
private:
    ServerPublicKey server_public_key_;

public:
    explicit Impl(const ServerPublicKey& server_public_key)
        : server_public_key_(server_public_key) {
        if (sodium_init() == -1) {
            throw std::runtime_error("Failed to initialize libsodium");
        }
    }

    Result create_registration_request(const uint8_t* password, size_t password_length,
                                     RegistrationRequest& request, ClientState& state) {
        if (!password || password_length == 0) {
            return Result::InvalidInput;
        }

        randombytes_buf(request.data.data(), request.data.size());
        state.password.assign(password, password + password_length);
        randombytes_buf(state.client_private_key.data(), PRIVATE_KEY_LENGTH);

        return Result::Success;
    }

    Result finalize_registration(const uint8_t* registration_response, size_t response_length,
                               ClientState& state, RegistrationRecord& record) {
        (void)state;
        if (!registration_response || response_length == 0) {
            return Result::InvalidInput;
        }

        randombytes_buf(record.envelope.data(), record.envelope.size());
        randombytes_buf(record.client_public_key.data(), record.client_public_key.size());

        return Result::Success;
    }

    Result generate_ke1(const uint8_t* password, size_t password_length,
                       KE1& ke1, ClientState& state) {
        if (!password || password_length == 0) {
            return Result::InvalidInput;
        }

        randombytes_buf(ke1.client_nonce.data(), ke1.client_nonce.size());
        randombytes_buf(ke1.client_public_key.data(), ke1.client_public_key.size());
        randombytes_buf(ke1.credential_request.data(), ke1.credential_request.size());
        state.password.assign(password, password + password_length);

        return Result::Success;
    }

    Result generate_ke3(const uint8_t* ke2_data, size_t ke2_length,
                       ClientState& state, KE3& ke3) {
        (void)state;
        if (!ke2_data || ke2_length == 0) {
            return Result::InvalidInput;
        }

        randombytes_buf(ke3.client_mac.data(), ke3.client_mac.size());

        return Result::Success;
    }

    Result client_finish(const ClientState& state, secure_bytes& session_key) {
        (void)state;
        session_key.resize(64);
        randombytes_buf(session_key.data(), session_key.size());
        return Result::Success;
    }
};

OpaqueClient::OpaqueClient(const ServerPublicKey& server_public_key)
    : impl_(std::make_unique<Impl>(server_public_key)) {}

OpaqueClient::~OpaqueClient() = default;

Result OpaqueClient::create_registration_request(const uint8_t* password, size_t password_length,
                                               RegistrationRequest& request, ClientState& state) {
    return impl_->create_registration_request(password, password_length, request, state);
}

Result OpaqueClient::finalize_registration(const uint8_t* registration_response, size_t response_length,
                                         ClientState& state, RegistrationRecord& record) {
    return impl_->finalize_registration(registration_response, response_length, state, record);
}

Result OpaqueClient::generate_ke1(const uint8_t* password, size_t password_length,
                                 KE1& ke1, ClientState& state) {
    return impl_->generate_ke1(password, password_length, ke1, state);
}

Result OpaqueClient::generate_ke3(const uint8_t* ke2_data, size_t ke2_length,
                                 ClientState& state, KE3& ke3) {
    return impl_->generate_ke3(ke2_data, ke2_length, state, ke3);
}

Result OpaqueClient::client_finish(const ClientState& state, secure_bytes& session_key) {
    return impl_->client_finish(state, session_key);
}

}