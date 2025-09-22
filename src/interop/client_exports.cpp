#include "opaque/client.h"
#include <cstring>

extern "C" {

using namespace ecliptix::security::opaque;
using namespace ecliptix::security::opaque::client;

typedef struct {
    OpaqueClient* client;
} opaque_client_handle_t;

typedef struct {
    ClientState* state;
} client_state_handle_t;

int opaque_client_create(const uint8_t* server_public_key, size_t key_length,
                        opaque_client_handle_t** handle) {
    if (!server_public_key || key_length != PUBLIC_KEY_LENGTH || !handle) {
        return static_cast<int>(Result::InvalidInput);
    }

    try {
        ServerPublicKey server_key(server_public_key, key_length);
        if (!server_key.verify()) {
            return static_cast<int>(Result::ValidationError);
        }

        auto client = new OpaqueClient(server_key);
        auto client_handle = new opaque_client_handle_t;
        client_handle->client = client;
        *handle = client_handle;

        return static_cast<int>(Result::Success);
    } catch (...) {
        return static_cast<int>(Result::MemoryError);
    }
}

void opaque_client_destroy(opaque_client_handle_t* handle) {
    if (handle) {
        delete handle->client;
        delete handle;
    }
}

int opaque_client_state_create(client_state_handle_t** handle) {
    if (!handle) {
        return static_cast<int>(Result::InvalidInput);
    }

    try {
        auto state = new ClientState();
        auto state_handle = new client_state_handle_t;
        state_handle->state = state;
        *handle = state_handle;

        return static_cast<int>(Result::Success);
    } catch (...) {
        return static_cast<int>(Result::MemoryError);
    }
}

void opaque_client_state_destroy(client_state_handle_t* handle) {
    if (handle) {
        delete handle->state;
        delete handle;
    }
}

int opaque_client_create_registration_request(opaque_client_handle_t* client_handle,
                                             const uint8_t* password, size_t password_length,
                                             uint8_t* request_data, size_t request_buffer_size,
                                             client_state_handle_t* state_handle) {
    if (!client_handle || !client_handle->client || !password || password_length == 0 ||
        !request_data || request_buffer_size < REGISTRATION_REQUEST_LENGTH ||
        !state_handle || !state_handle->state) {
        return static_cast<int>(Result::InvalidInput);
    }

    RegistrationRequest request;
    Result result = client_handle->client->create_registration_request(
        password, password_length, request, *state_handle->state);

    if (result == Result::Success) {
        std::memcpy(request_data, request.data.data(), REGISTRATION_REQUEST_LENGTH);
    }

    return static_cast<int>(result);
}

int opaque_client_finalize_registration(opaque_client_handle_t* client_handle,
                                       const uint8_t* response_data, size_t response_length,
                                       client_state_handle_t* state_handle,
                                       uint8_t* record_data, size_t record_buffer_size) {
    if (!client_handle || !client_handle->client || !response_data ||
        response_length != REGISTRATION_RESPONSE_LENGTH ||
        !state_handle || !state_handle->state ||
        !record_data || record_buffer_size < (ENVELOPE_LENGTH + PUBLIC_KEY_LENGTH)) {
        return static_cast<int>(Result::InvalidInput);
    }

    RegistrationRecord record;
    Result result = client_handle->client->finalize_registration(
        response_data, response_length, *state_handle->state, record);

    if (result == Result::Success) {
        std::memcpy(record_data, record.envelope.data(), ENVELOPE_LENGTH);
        std::memcpy(record_data + ENVELOPE_LENGTH, record.client_public_key.data(), PUBLIC_KEY_LENGTH);
    }

    return static_cast<int>(result);
}

int opaque_client_generate_ke1(opaque_client_handle_t* client_handle,
                               const uint8_t* password, size_t password_length,
                               uint8_t* ke1_data, size_t ke1_buffer_size,
                               client_state_handle_t* state_handle) {
    if (!client_handle || !client_handle->client || !password || password_length == 0 ||
        !ke1_data || ke1_buffer_size < KE1_LENGTH ||
        !state_handle || !state_handle->state) {
        return static_cast<int>(Result::InvalidInput);
    }

    KE1 ke1;
    Result result = client_handle->client->generate_ke1(
        password, password_length, ke1, *state_handle->state);

    if (result == Result::Success) {
        size_t offset = 0;
        std::memcpy(ke1_data + offset, ke1.client_nonce.data(), NONCE_LENGTH);
        offset += NONCE_LENGTH;
        std::memcpy(ke1_data + offset, ke1.client_public_key.data(), PUBLIC_KEY_LENGTH);
        offset += PUBLIC_KEY_LENGTH;
        std::memcpy(ke1_data + offset, ke1.credential_request.data(), ke1.credential_request.size());
    }

    return static_cast<int>(result);
}

int opaque_client_generate_ke3(opaque_client_handle_t* client_handle,
                               const uint8_t* ke2_data, size_t ke2_length,
                               client_state_handle_t* state_handle,
                               uint8_t* ke3_data, size_t ke3_buffer_size) {
    if (!client_handle || !client_handle->client || !ke2_data || ke2_length != KE2_LENGTH ||
        !state_handle || !state_handle->state ||
        !ke3_data || ke3_buffer_size < KE3_LENGTH) {
        return static_cast<int>(Result::InvalidInput);
    }

    KE3 ke3;
    Result result = client_handle->client->generate_ke3(
        ke2_data, ke2_length, *state_handle->state, ke3);

    if (result == Result::Success) {
        std::memcpy(ke3_data, ke3.client_mac.data(), MAC_LENGTH);
    }

    return static_cast<int>(result);
}

int opaque_client_finish(opaque_client_handle_t* client_handle,
                        client_state_handle_t* state_handle,
                        uint8_t* session_key, size_t session_key_buffer_size) {
    if (!client_handle || !client_handle->client ||
        !state_handle || !state_handle->state ||
        !session_key || session_key_buffer_size < HASH_LENGTH) {
        return static_cast<int>(Result::InvalidInput);
    }

    secure_bytes key;
    Result result = client_handle->client->client_finish(*state_handle->state, key);

    if (result == Result::Success) {
        std::memcpy(session_key, key.data(), std::min(key.size(), session_key_buffer_size));
    }

    return static_cast<int>(result);
}

}