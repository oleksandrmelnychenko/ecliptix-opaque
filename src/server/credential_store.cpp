#include "opaque/server.h"
#include <sodium.h>
#include <unordered_map>
#include <string>
#include <algorithm>

namespace ecliptix::security::opaque::server {

namespace {
    namespace crypto = ecliptix::security::opaque::crypto;
}

ServerKeyPair::ServerKeyPair() : private_key(PRIVATE_KEY_LENGTH), public_key(PUBLIC_KEY_LENGTH) {}

ServerKeyPair::~ServerKeyPair() {
    sodium_memzero(private_key.data(), private_key.size());
    sodium_memzero(public_key.data(), public_key.size());
}

Result ServerKeyPair::generate(ServerKeyPair& keypair) {
    crypto::random_bytes(keypair.private_key.data(), PRIVATE_KEY_LENGTH);

    if (crypto_scalarmult_ristretto255_base(keypair.public_key.data(),
                                           keypair.private_key.data()) != 0) {
        return Result::CryptoError;
    }

    return Result::Success;
}

CredentialFile::CredentialFile() : user_id(0) {}

class CredentialStore::Impl {
private:
    std::unordered_map<std::string, ServerCredentials> credentials_map_;

public:
    Result store_credentials(const uint8_t* user_id, size_t user_id_length,
                           const ServerCredentials& credentials) {
        if (!user_id || user_id_length == 0) {
            return Result::InvalidInput;
        }

        std::string key(reinterpret_cast<const char*>(user_id), user_id_length);
        credentials_map_[key] = credentials;

        return Result::Success;
    }

    Result retrieve_credentials(const uint8_t* user_id, size_t user_id_length,
                              ServerCredentials& credentials) {
        if (!user_id || user_id_length == 0) {
            return Result::InvalidInput;
        }

        std::string key(reinterpret_cast<const char*>(user_id), user_id_length);
        auto it = credentials_map_.find(key);

        if (it == credentials_map_.end()) {
            return Result::ValidationError;
        }

        credentials = it->second;
        return Result::Success;
    }

    Result remove_credentials(const uint8_t* user_id, size_t user_id_length) {
        if (!user_id || user_id_length == 0) {
            return Result::InvalidInput;
        }

        std::string key(reinterpret_cast<const char*>(user_id), user_id_length);
        auto it = credentials_map_.find(key);

        if (it == credentials_map_.end()) {
            return Result::ValidationError;
        }

        credentials_map_.erase(it);
        return Result::Success;
    }
};

CredentialStore::CredentialStore() : impl_(std::make_unique<Impl>()) {}

CredentialStore::~CredentialStore() = default;

Result CredentialStore::store_credentials(const uint8_t* user_id, size_t user_id_length,
                                        const ServerCredentials& credentials) {
    return impl_->store_credentials(user_id, user_id_length, credentials);
}

Result CredentialStore::retrieve_credentials(const uint8_t* user_id, size_t user_id_length,
                                           ServerCredentials& credentials) {
    return impl_->retrieve_credentials(user_id, user_id_length, credentials);
}

Result CredentialStore::remove_credentials(const uint8_t* user_id, size_t user_id_length) {
    return impl_->remove_credentials(user_id, user_id_length);
}

class OpaqueServer::Impl {
private:
    ServerKeyPair server_keypair_;

public:
    explicit Impl(const ServerKeyPair& server_keypair) : server_keypair_(server_keypair) {
        if (!crypto::init()) {
            throw std::runtime_error("Failed to initialize cryptographic library");
        }
    }

    Result create_registration_response(const uint8_t* registration_request, size_t request_length,
                                      RegistrationResponse& response, ServerCredentials& credentials) {
        return create_registration_response_impl(registration_request, request_length,
                                                server_keypair_.private_key,
                                                server_keypair_.public_key,
                                                response, credentials);
    }

    Result generate_ke2(const uint8_t* ke1_data, size_t ke1_length,
                       const ServerCredentials& credentials,
                       KE2& ke2, ServerState& state) {
        return generate_ke2_impl(ke1_data, ke1_length, credentials,
                                server_keypair_.private_key,
                                server_keypair_.public_key,
                                ke2, state);
    }

    Result server_finish(const uint8_t* ke3_data, size_t ke3_length,
                        const ServerState& state, secure_bytes& session_key) {
        return server_finish_impl(ke3_data, ke3_length, state, session_key);
    }

    const secure_bytes& get_public_key() const {
        return server_keypair_.public_key;
    }
};

OpaqueServer::OpaqueServer(const ServerKeyPair& server_keypair)
    : impl_(std::make_unique<Impl>(server_keypair)) {}

OpaqueServer::~OpaqueServer() = default;

Result OpaqueServer::create_registration_response(const uint8_t* registration_request, size_t request_length,
                                                RegistrationResponse& response, ServerCredentials& credentials) {
    return impl_->create_registration_response(registration_request, request_length, response, credentials);
}

Result OpaqueServer::generate_ke2(const uint8_t* ke1_data, size_t ke1_length,
                                 const ServerCredentials& credentials,
                                 KE2& ke2, ServerState& state) {
    return impl_->generate_ke2(ke1_data, ke1_length, credentials, ke2, state);
}

Result OpaqueServer::server_finish(const uint8_t* ke3_data, size_t ke3_length,
                                  const ServerState& state, secure_bytes& session_key) {
    return impl_->server_finish(ke3_data, ke3_length, state, session_key);
}

const secure_bytes& OpaqueServer::get_public_key() const {
    return impl_->get_public_key();
}

}