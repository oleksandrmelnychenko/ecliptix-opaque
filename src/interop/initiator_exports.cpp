#include "opaque/opaque.h"
#include "opaque/initiator.h"
#include "opaque/version.h"
#include "opaque/hardcoded_keys.h"
#include <sodium.h>
#include <cstring>
#include <memory>
#include <algorithm>
using namespace ecliptix::security::opaque;

struct OpaqueClientHandle {
    std::unique_ptr<initiator::OpaqueInitiator> opaque_client;
    ResponderPublicKey server_public_key;
    bool is_initialized;

    OpaqueClientHandle(const uint8_t *server_key, size_t key_len)
        : server_public_key(server_key, key_len), is_initialized(false) {
        if (!server_public_key.verify()) {
            throw std::runtime_error("Invalid server public key");
        }
        opaque_client = std::make_unique<initiator::OpaqueInitiator>(server_public_key);
        is_initialized = true;
    }

    ~OpaqueClientHandle() {
        is_initialized = false;
    }
};

struct ClientStateHandle {
    std::unique_ptr<initiator::InitiatorState> client_state;
    bool has_active_session;

    ClientStateHandle() : has_active_session(false) {
        client_state = std::make_unique<initiator::InitiatorState>();
        has_active_session = true;
    }

    ~ClientStateHandle() {
        has_active_session = false;
    }
};

extern "C" {
int opaque_client_create(
    const uint8_t *server_public_key,
    size_t key_length,
    void **handle) {
    if (!server_public_key || key_length != PUBLIC_KEY_LENGTH || !handle) {
        return static_cast<int>(Result::InvalidInput);
    }
    if (crypto_core_ristretto255_is_valid_point(server_public_key) != 1) {
        return static_cast<int>(Result::InvalidPublicKey);
    }
    try {
        if (!crypto::init()) {
            return static_cast<int>(Result::CryptoError);
        }
        auto client = std::make_unique<OpaqueClientHandle>(server_public_key, key_length);
        *handle = client.release();
        return static_cast<int>(Result::Success);
    } catch (const std::exception &) {
        return static_cast<int>(Result::MemoryError);
    }
}

void opaque_client_destroy(void *handle) {
    if (handle) {
        std::unique_ptr<OpaqueClientHandle> client(
            static_cast<OpaqueClientHandle *>(handle));
    }
}

int opaque_client_state_create(void **handle) {
    if (!handle) {
        return static_cast<int>(Result::InvalidInput);
    }
    try {
        auto state = std::make_unique<ClientStateHandle>();
        state->has_active_session = true;
        *handle = state.release();
        return static_cast<int>(Result::Success);
    } catch (const std::exception &) {
        return static_cast<int>(Result::MemoryError);
    }
}

void opaque_client_state_destroy(void *handle) {
    if (handle) {
        std::unique_ptr<ClientStateHandle> state(
            static_cast<ClientStateHandle *>(handle));
    }
}

int opaque_client_create_registration_request(
    void *client_handle,
    const uint8_t *secure_key,
    size_t secure_key_length,
    void *state_handle,
    uint8_t *request_out,
    size_t request_length) {
    if (!client_handle || !secure_key || secure_key_length == 0 ||
        !state_handle || !request_out || request_length < REGISTRATION_REQUEST_LENGTH) {
        return static_cast<int>(Result::InvalidInput);
    }
    auto *client = static_cast<OpaqueClientHandle *>(client_handle);
    auto *state = static_cast<ClientStateHandle *>(state_handle);
    if (!client->is_initialized || !state->has_active_session) {
        return static_cast<int>(Result::ValidationError);
    }
    try {
        initiator::RegistrationRequest request;
        Result result = client->opaque_client->create_registration_request(
            secure_key, secure_key_length, request, *state->client_state);
        if (result != Result::Success) {
            return static_cast<int>(result);
        }

        if (request.data.size() != REGISTRATION_REQUEST_LENGTH) {
            return static_cast<int>(Result::CryptoError);
        }
        std::copy(request.data.begin(), request.data.end(), request_out);
        return static_cast<int>(Result::Success);
    } catch (const std::exception &) {
        return static_cast<int>(Result::MemoryError);
    }
}

int opaque_client_finalize_registration(
    void *client_handle,
    const uint8_t *response,
    size_t response_length,
    const uint8_t *master_key,
    size_t master_key_length,
    void *state_handle,
    uint8_t *record_out,
    size_t record_length) {
    if (!client_handle || !response || response_length < REGISTRATION_RESPONSE_LENGTH ||
        !master_key || master_key_length != MASTER_KEY_LENGTH ||
        !state_handle || !record_out || record_length < (ENVELOPE_LENGTH + PUBLIC_KEY_LENGTH)) {
        return static_cast<int>(Result::InvalidInput);
    }
    auto *client = static_cast<OpaqueClientHandle *>(client_handle);
    auto *state = static_cast<ClientStateHandle *>(state_handle);
    if (!client->is_initialized || !state->has_active_session) {
        return static_cast<int>(Result::ValidationError);
    }
    try {
        std::copy(master_key, master_key + MASTER_KEY_LENGTH, state->client_state->master_key.begin());
        initiator::RegistrationRecord record;
        Result result = client->opaque_client->finalize_registration(
            response, response_length, *state->client_state, record);
        if (result != Result::Success) {
            return static_cast<int>(result);
        }

        const size_t expected_record_size = record.envelope.size() + record.initiator_public_key.size();
        if (record_length < expected_record_size) {
            return static_cast<int>(Result::InvalidInput);
        }

        size_t offset = 0;
        std::copy(record.envelope.begin(), record.envelope.end(), record_out + offset);
        offset += record.envelope.size();
        std::copy(record.initiator_public_key.begin(), record.initiator_public_key.end(), record_out + offset);

        return static_cast<int>(Result::Success);
    } catch (const std::exception &) {
        return static_cast<int>(Result::MemoryError);
    }
}

int opaque_client_generate_ke1(
    void *client_handle,
    const uint8_t *secure_key,
    size_t secure_key_length,
    void *state_handle,
    uint8_t *ke1_out,
    size_t ke1_length) {
    if (!client_handle || !secure_key || secure_key_length == 0 ||
        !state_handle || !ke1_out || ke1_length < KE1_LENGTH) {
        return static_cast<int>(Result::InvalidInput);
    }
    const auto *client = static_cast<OpaqueClientHandle *>(client_handle);
    const auto *state = static_cast<ClientStateHandle *>(state_handle);
    if (!client->is_initialized || !state->has_active_session) {
        return static_cast<int>(Result::ValidationError);
    }
    try {
        initiator::KE1 ke1;
        Result result = initiator::OpaqueInitiator::generate_ke1(
            secure_key, secure_key_length, ke1, *state->client_state);
        if (result != Result::Success) {
            return static_cast<int>(result);
        }

        size_t offset = 0;
        std::ranges::copy(ke1.credential_request, ke1_out + offset);
        offset += ke1.credential_request.size();
        std::ranges::copy(ke1.initiator_public_key, ke1_out + offset);
        offset += ke1.initiator_public_key.size();
        std::ranges::copy(ke1.initiator_nonce, ke1_out + offset);

        return static_cast<int>(Result::Success);
    } catch (const std::exception &) {
        return static_cast<int>(Result::MemoryError);
    }
}

int opaque_client_generate_ke3(
    void *client_handle,
    const uint8_t *ke2,
    const size_t ke2_length,
    void *state_handle,
    uint8_t *ke3_out,
    size_t ke3_length) {
    if (!client_handle || !ke2 || ke2_length < KE2_LENGTH ||
        !state_handle || !ke3_out || ke3_length < KE3_LENGTH) {
        return static_cast<int>(Result::InvalidInput);
    }
    const auto *client = static_cast<OpaqueClientHandle *>(client_handle);
    const auto *state = static_cast<ClientStateHandle *>(state_handle);
    if (!client->is_initialized || !state->has_active_session) {
        return static_cast<int>(Result::ValidationError);
    }
    try {
        initiator::KE3 ke3;
        Result result = client->opaque_client->generate_ke3(
            ke2, ke2_length, *state->client_state, ke3);
        if (result != Result::Success) {
            return static_cast<int>(result);
        }

        std::ranges::copy(ke3.initiator_mac, ke3_out);
        return static_cast<int>(Result::Success);
    } catch (const std::exception &) {
        return static_cast<int>(Result::MemoryError);
    }
}

int opaque_client_finish(
    void *client_handle,
    void *state_handle,
    uint8_t *session_key_out,
    size_t session_key_length,
    uint8_t *master_key_out,
    size_t master_key_length) {
    if (!client_handle || !state_handle ||
        !session_key_out || session_key_length < HASH_LENGTH ||
        !master_key_out || master_key_length != MASTER_KEY_LENGTH) {
        return static_cast<int>(Result::InvalidInput);
    }
    const auto *client = static_cast<OpaqueClientHandle *>(client_handle);
    const auto *state = static_cast<ClientStateHandle *>(state_handle);
    if (!client->is_initialized || !state->has_active_session) {
        return static_cast<int>(Result::ValidationError);
    }
    try {
        secure_bytes session_key;
        if (Result result = initiator::OpaqueInitiator::initiator_finish(*state->client_state, session_key);
            result != Result::Success) {
            return static_cast<int>(result);
        }

        const size_t copy_length = std::min(session_key_length, session_key.size());
        std::copy_n(session_key.begin(), static_cast<std::ptrdiff_t>(copy_length), session_key_out);
        std::ranges::copy(state->client_state->master_key, master_key_out);
        return static_cast<int>(Result::Success);
    } catch (const std::exception &) {
        return static_cast<int>(Result::MemoryError);
    }
}

int opaque_client_create_default(void **handle) {
    return opaque_client_create(keys::SERVER_PUBLIC_KEY, PUBLIC_KEY_LENGTH, handle);
}

const char *opaque_client_get_version() {
    return OPAQUE_CLIENT_VERSION;
}
}
