#include "opaque/client.h"
#include <sodium.h>
#include <algorithm>
namespace ecliptix::security::opaque::client {
Result create_registration_request_impl(const uint8_t* password, size_t password_length,
                                       RegistrationRequest& request, ClientState& state);
Result finalize_registration_impl(const uint8_t* registration_response, size_t response_length,
                                 ClientState& state, RegistrationRecord& record);
Result generate_ke1_impl(const uint8_t* password, size_t password_length,
                        KE1& ke1, ClientState& state);
Result generate_ke3_impl(const uint8_t* ke2_data, size_t ke2_length,
                        ClientState& state, KE3& ke3);
Result client_finish_impl(const ClientState& state, secure_bytes& session_key);
ClientState::ClientState() : password(0), client_private_key(PRIVATE_KEY_LENGTH),
                            client_public_key(PUBLIC_KEY_LENGTH),
                            client_ephemeral_private_key(PRIVATE_KEY_LENGTH),
                            client_ephemeral_public_key(PUBLIC_KEY_LENGTH),
                            server_public_key(PUBLIC_KEY_LENGTH),
                            session_key(0) {}
ClientState::~ClientState() {
    if (!password.empty()) {
        sodium_memzero(password.data(), password.size());
    }
    sodium_memzero(client_private_key.data(), client_private_key.size());
    sodium_memzero(client_public_key.data(), client_public_key.size());
    sodium_memzero(client_ephemeral_private_key.data(), client_ephemeral_private_key.size());
    sodium_memzero(client_ephemeral_public_key.data(), client_ephemeral_public_key.size());
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
        if (!crypto::init()) {
            throw std::runtime_error("Failed to initialize cryptographic library");
        }
    }
    Result create_registration_request(const uint8_t* password, size_t password_length,
                                     RegistrationRequest& request, ClientState& state) {
        return create_registration_request_impl(password, password_length, request, state);
    }
    Result finalize_registration(const uint8_t* registration_response, size_t response_length,
                               ClientState& state, RegistrationRecord& record) {
        return finalize_registration_impl(registration_response, response_length, state, record);
    }
    Result generate_ke1(const uint8_t* password, size_t password_length,
                       KE1& ke1, ClientState& state) {
        return generate_ke1_impl(password, password_length, ke1, state);
    }
    Result generate_ke3(const uint8_t* ke2_data, size_t ke2_length,
                       ClientState& state, KE3& ke3) {
        return generate_ke3_impl(ke2_data, ke2_length, state, ke3);
    }
    Result client_finish(const ClientState& state, secure_bytes& session_key) {
        return client_finish_impl(state, session_key);
    }
    const ServerPublicKey& get_server_public_key() const {
        return server_public_key_;
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