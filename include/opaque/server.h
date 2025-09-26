#pragma once
#include "opaque.h"
namespace ecliptix::security::opaque::server {
struct RegistrationResponse {
    secure_bytes data;
    RegistrationResponse();
};
struct KE2 {
    secure_bytes server_nonce;
    secure_bytes server_public_key;
    secure_bytes credential_response;
    secure_bytes server_mac;
    KE2();
};
struct ServerState {
    secure_bytes server_private_key;
    secure_bytes server_public_key;
    secure_bytes server_ephemeral_private_key;
    secure_bytes server_ephemeral_public_key;
    secure_bytes client_public_key;
    secure_bytes session_key;
    secure_bytes expected_client_mac;
    ServerState();
    ~ServerState();
};
struct ServerKeyPair {
    secure_bytes private_key;
    secure_bytes public_key;
    ServerKeyPair();
    ~ServerKeyPair();
    static Result generate(ServerKeyPair& keypair);
};
class OpaqueServer {
public:
    explicit OpaqueServer(const ServerKeyPair& server_keypair);
    ~OpaqueServer();
    OpaqueServer(const OpaqueServer&) = delete;
    OpaqueServer& operator=(const OpaqueServer&) = delete;
    Result create_registration_response(
        const uint8_t* registration_request,
        size_t request_length,
        RegistrationResponse& response,
        ServerCredentials& credentials
    );
    Result generate_ke2(
        const uint8_t* ke1_data,
        size_t ke1_length,
        const ServerCredentials& credentials,
        KE2& ke2,
        ServerState& state
    );
    Result server_finish(
        const uint8_t* ke3_data,
        size_t ke3_length,
        const ServerState& state,
        secure_bytes& session_key
    );
    const secure_bytes& get_public_key() const;
private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};
Result create_registration_response_impl(
    const uint8_t* registration_request,
    size_t request_length,
    const secure_bytes& server_private_key,
    const secure_bytes& server_public_key,
    RegistrationResponse& response,
    ServerCredentials& credentials
);
Result generate_ke2_impl(
    const uint8_t* ke1_data,
    size_t ke1_length,
    const ServerCredentials& credentials,
    const secure_bytes& server_private_key,
    const secure_bytes& server_public_key,
    KE2& ke2,
    ServerState& state
);
Result server_finish_impl(
    const uint8_t* ke3_data,
    size_t ke3_length,
    const ServerState& state,
    secure_bytes& session_key
);
}