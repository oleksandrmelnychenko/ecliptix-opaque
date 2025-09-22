#include "opaque/server.h"
#include <cstring>
extern "C" {
using namespace ecliptix::security::opaque;
using namespace ecliptix::security::opaque::server;
typedef struct {
    OpaqueServer* server;
} opaque_server_handle_t;
typedef struct {
    ServerState* state;
} server_state_handle_t;
typedef struct {
    ServerKeyPair* keypair;
} server_keypair_handle_t;
typedef struct {
    CredentialStore* store;
} credential_store_handle_t;
int opaque_server_keypair_generate(server_keypair_handle_t** handle) {
    if (!handle) {
        return static_cast<int>(Result::InvalidInput);
    }
    try {
        auto keypair = new ServerKeyPair();
        Result result = ServerKeyPair::generate(*keypair);
        if (result != Result::Success) {
            delete keypair;
            return static_cast<int>(result);
        }
        auto keypair_handle = new server_keypair_handle_t;
        keypair_handle->keypair = keypair;
        *handle = keypair_handle;
        return static_cast<int>(Result::Success);
    } catch (...) {
        return static_cast<int>(Result::MemoryError);
    }
}
void opaque_server_keypair_destroy(server_keypair_handle_t* handle) {
    if (handle) {
        delete handle->keypair;
        delete handle;
    }
}
int opaque_server_keypair_get_public_key(server_keypair_handle_t* handle,
                                        uint8_t* public_key, size_t key_buffer_size) {
    if (!handle || !handle->keypair || !public_key || key_buffer_size < PUBLIC_KEY_LENGTH) {
        return static_cast<int>(Result::InvalidInput);
    }
    std::memcpy(public_key, handle->keypair->public_key.data(), PUBLIC_KEY_LENGTH);
    return static_cast<int>(Result::Success);
}
int opaque_server_create(server_keypair_handle_t* keypair_handle,
                        opaque_server_handle_t** handle) {
    if (!keypair_handle || !keypair_handle->keypair || !handle) {
        return static_cast<int>(Result::InvalidInput);
    }
    try {
        auto server = new OpaqueServer(*keypair_handle->keypair);
        auto server_handle = new opaque_server_handle_t;
        server_handle->server = server;
        *handle = server_handle;
        return static_cast<int>(Result::Success);
    } catch (...) {
        return static_cast<int>(Result::MemoryError);
    }
}
void opaque_server_destroy(opaque_server_handle_t* handle) {
    if (handle) {
        delete handle->server;
        delete handle;
    }
}
int opaque_server_state_create(server_state_handle_t** handle) {
    if (!handle) {
        return static_cast<int>(Result::InvalidInput);
    }
    try {
        auto state = new ServerState();
        auto state_handle = new server_state_handle_t;
        state_handle->state = state;
        *handle = state_handle;
        return static_cast<int>(Result::Success);
    } catch (...) {
        return static_cast<int>(Result::MemoryError);
    }
}
void opaque_server_state_destroy(server_state_handle_t* handle) {
    if (handle) {
        delete handle->state;
        delete handle;
    }
}
int opaque_server_create_registration_response(opaque_server_handle_t* server_handle,
                                              const uint8_t* request_data, size_t request_length,
                                              uint8_t* response_data, size_t response_buffer_size,
                                              uint8_t* credentials_data, size_t credentials_buffer_size) {
    if (!server_handle || !server_handle->server || !request_data ||
        request_length != REGISTRATION_REQUEST_LENGTH ||
        !response_data || response_buffer_size < REGISTRATION_RESPONSE_LENGTH ||
        !credentials_data || credentials_buffer_size < (ENVELOPE_LENGTH + PRIVATE_KEY_LENGTH)) {
        return static_cast<int>(Result::InvalidInput);
    }
    RegistrationResponse response;
    ServerCredentials credentials;
    Result result = server_handle->server->create_registration_response(
        request_data, request_length, response, credentials);
    if (result == Result::Success) {
        std::memcpy(response_data, response.data.data(), REGISTRATION_RESPONSE_LENGTH);
        std::memcpy(credentials_data, credentials.envelope.data(), ENVELOPE_LENGTH);
        std::memcpy(credentials_data + ENVELOPE_LENGTH, credentials.masking_key.data(), PRIVATE_KEY_LENGTH);
    }
    return static_cast<int>(result);
}
int opaque_server_generate_ke2(opaque_server_handle_t* server_handle,
                               const uint8_t* ke1_data, size_t ke1_length,
                               const uint8_t* credentials_data, size_t credentials_length,
                               uint8_t* ke2_data, size_t ke2_buffer_size,
                               server_state_handle_t* state_handle) {
    if (!server_handle || !server_handle->server || !ke1_data || ke1_length != KE1_LENGTH ||
        !credentials_data || credentials_length < (ENVELOPE_LENGTH + PRIVATE_KEY_LENGTH) ||
        !ke2_data || ke2_buffer_size < KE2_LENGTH ||
        !state_handle || !state_handle->state) {
        return static_cast<int>(Result::InvalidInput);
    }
    ServerCredentials credentials;
    credentials.envelope.assign(credentials_data, credentials_data + ENVELOPE_LENGTH);
    credentials.masking_key.assign(credentials_data + ENVELOPE_LENGTH,
                                  credentials_data + ENVELOPE_LENGTH + PRIVATE_KEY_LENGTH);
    KE2 ke2;
    Result result = server_handle->server->generate_ke2(
        ke1_data, ke1_length, credentials, ke2, *state_handle->state);
    if (result == Result::Success) {
        size_t offset = 0;
        std::memcpy(ke2_data + offset, ke2.server_nonce.data(), NONCE_LENGTH);
        offset += NONCE_LENGTH;
        std::memcpy(ke2_data + offset, ke2.server_public_key.data(), PUBLIC_KEY_LENGTH);
        offset += PUBLIC_KEY_LENGTH;
        std::memcpy(ke2_data + offset, ke2.credential_response.data(), CREDENTIAL_RESPONSE_LENGTH);
        offset += CREDENTIAL_RESPONSE_LENGTH;
        std::memcpy(ke2_data + offset, ke2.server_mac.data(), MAC_LENGTH);
    }
    return static_cast<int>(result);
}
int opaque_server_finish(opaque_server_handle_t* server_handle,
                        const uint8_t* ke3_data, size_t ke3_length,
                        server_state_handle_t* state_handle,
                        uint8_t* session_key, size_t session_key_buffer_size) {
    if (!server_handle || !server_handle->server || !ke3_data || ke3_length != KE3_LENGTH ||
        !state_handle || !state_handle->state ||
        !session_key || session_key_buffer_size < HASH_LENGTH) {
        return static_cast<int>(Result::InvalidInput);
    }
    secure_bytes key;
    Result result = server_handle->server->server_finish(
        ke3_data, ke3_length, *state_handle->state, key);
    if (result == Result::Success) {
        std::memcpy(session_key, key.data(), std::min(key.size(), session_key_buffer_size));
    }
    return static_cast<int>(result);
}
int opaque_credential_store_create(credential_store_handle_t** handle) {
    if (!handle) {
        return static_cast<int>(Result::InvalidInput);
    }
    try {
        auto store = new CredentialStore();
        auto store_handle = new credential_store_handle_t;
        store_handle->store = store;
        *handle = store_handle;
        return static_cast<int>(Result::Success);
    } catch (...) {
        return static_cast<int>(Result::MemoryError);
    }
}
void opaque_credential_store_destroy(credential_store_handle_t* handle) {
    if (handle) {
        delete handle->store;
        delete handle;
    }
}
int opaque_credential_store_store(credential_store_handle_t* store_handle,
                                 const uint8_t* user_id, size_t user_id_length,
                                 const uint8_t* credentials_data, size_t credentials_length) {
    if (!store_handle || !store_handle->store || !user_id || user_id_length == 0 ||
        !credentials_data || credentials_length < (ENVELOPE_LENGTH + PRIVATE_KEY_LENGTH)) {
        return static_cast<int>(Result::InvalidInput);
    }
    ServerCredentials credentials;
    credentials.envelope.assign(credentials_data, credentials_data + ENVELOPE_LENGTH);
    credentials.masking_key.assign(credentials_data + ENVELOPE_LENGTH,
                                  credentials_data + ENVELOPE_LENGTH + PRIVATE_KEY_LENGTH);
    Result result = store_handle->store->store_credentials(user_id, user_id_length, credentials);
    return static_cast<int>(result);
}
int opaque_credential_store_retrieve(credential_store_handle_t* store_handle,
                                    const uint8_t* user_id, size_t user_id_length,
                                    uint8_t* credentials_data, size_t credentials_buffer_size) {
    if (!store_handle || !store_handle->store || !user_id || user_id_length == 0 ||
        !credentials_data || credentials_buffer_size < (ENVELOPE_LENGTH + PRIVATE_KEY_LENGTH)) {
        return static_cast<int>(Result::InvalidInput);
    }
    ServerCredentials credentials;
    Result result = store_handle->store->retrieve_credentials(user_id, user_id_length, credentials);
    if (result == Result::Success) {
        std::memcpy(credentials_data, credentials.envelope.data(), ENVELOPE_LENGTH);
        std::memcpy(credentials_data + ENVELOPE_LENGTH, credentials.masking_key.data(), PRIVATE_KEY_LENGTH);
    }
    return static_cast<int>(result);
}
}