#pragma once
#include "opaque.h"
namespace ecliptix::security::opaque::client {
struct RegistrationRequest {
    secure_bytes data;
    RegistrationRequest();
};
struct RegistrationRecord {
    secure_bytes envelope;
    secure_bytes client_public_key;
    RegistrationRecord();
};
struct KE1 {
    secure_bytes client_nonce;
    secure_bytes client_public_key;
    secure_bytes credential_request;
    KE1();
};
struct KE3 {
    secure_bytes client_mac;
    KE3();
};
struct ClientState {
    secure_bytes password;
    secure_bytes client_private_key;
    secure_bytes client_public_key;
    secure_bytes client_ephemeral_private_key;
    secure_bytes client_ephemeral_public_key;
    secure_bytes server_public_key;
    secure_bytes session_key;
    secure_bytes oprf_blind_scalar;
    secure_bytes client_nonce;
    ClientState();
    ~ClientState();
};
class OpaqueClient {
public:
    explicit OpaqueClient(const ServerPublicKey& server_public_key);
    ~OpaqueClient();
    OpaqueClient(const OpaqueClient&) = delete;
    OpaqueClient& operator=(const OpaqueClient&) = delete;
    Result create_registration_request(
        const uint8_t* password,
        size_t password_length,
        RegistrationRequest& request,
        ClientState& state
    );
    Result finalize_registration(
        const uint8_t* registration_response,
        size_t response_length,
        ClientState& state,
        RegistrationRecord& record
    );
    Result generate_ke1(
        const uint8_t* password,
        size_t password_length,
        KE1& ke1,
        ClientState& state
    );
    Result generate_ke3(
        const uint8_t* ke2_data,
        size_t ke2_length,
        ClientState& state,
        KE3& ke3
    );
    Result client_finish(
        const ClientState& state,
        secure_bytes& session_key
    );
private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};
}