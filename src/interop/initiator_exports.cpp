#include "opaque/opaque.h"
#include "opaque/initiator.h"
#include "opaque/protocol.h"
#include "opaque/version.h"
#include "opaque/hardcoded_keys.h"
#include "opaque/export.h"
#include <sodium.h>
#include <memory>
#include <algorithm>
#include <stdexcept>

#ifdef OPAQUE_INTEROP_LOGGING
#include <cstdio>
#warning "OPAQUE_INTEROP_LOGGING is enabled - DO NOT use in production builds!"

namespace {
constexpr char kAgentLogPrefix[] = "[ECLIPTIX-OPAQUE-AGENT] ";
constexpr size_t kHexPreviewBytes = 8;
}

#define OPAQUE_AGENT_LOG(fmt, ...) fprintf(stderr, "%s" fmt "\n", kAgentLogPrefix __VA_OPT__(,) __VA_ARGS__)
#define OPAQUE_AGENT_LOG_HEX(label, data, len) do { \
    fprintf(stderr, "%s%s: ", kAgentLogPrefix, label); \
    for (size_t i_ = 0; i_ < ((len) > kHexPreviewBytes ? kHexPreviewBytes : (len)); i_++) fprintf(stderr, "%02x", (data)[i_]); \
    if ((len) > kHexPreviewBytes) fprintf(stderr, "..."); \
    fprintf(stderr, " (len=%zu)\n", (size_t)(len)); \
} while(0)

#else

#define OPAQUE_AGENT_LOG(fmt, ...) ((void)0)
#define OPAQUE_AGENT_LOG_HEX(label, data, len) ((void)0)

#endif

using namespace ecliptix::security::opaque;

struct OpaqueAgentHandle {
    std::unique_ptr<initiator::OpaqueInitiator> opaque_agent;
    ResponderPublicKey server_public_key;
    bool is_initialized;

    OpaqueAgentHandle(const uint8_t *server_key, size_t key_len)
        : server_public_key(server_key, key_len), is_initialized(false) {
        if (!server_public_key.verify()) {
            throw std::runtime_error("Invalid server public key");
        }
        opaque_agent = std::make_unique<initiator::OpaqueInitiator>(server_public_key);
        is_initialized = true;
    }

    ~OpaqueAgentHandle() {
        is_initialized = false;
    }
};

struct AgentStateHandle {
    std::unique_ptr<initiator::InitiatorState> agent_state;
    bool has_active_session;

    AgentStateHandle() : has_active_session(false) {
        agent_state = std::make_unique<initiator::InitiatorState>();
        has_active_session = true;
    }

    ~AgentStateHandle() {
        has_active_session = false;
    }
};

extern "C" {
ECLIPTIX_OPAQUE_C_EXPORT int opaque_agent_create(
    const uint8_t *server_public_key,
    size_t key_length,
    void **handle) {
    OPAQUE_AGENT_LOG("=== opaque_agent_create ===");
    OPAQUE_AGENT_LOG("key_length=%zu, handle=%p", key_length, (void*)handle);
    if (!server_public_key || key_length != PUBLIC_KEY_LENGTH || !handle) {
        OPAQUE_AGENT_LOG("ERROR: InvalidInput - server_public_key=%p, key_length=%zu", (void*)server_public_key,
                          key_length);
        return static_cast<int>(Result::InvalidInput);
    }
    OPAQUE_AGENT_LOG_HEX("server_public_key", server_public_key, key_length);
    if (!crypto::init()) {
        OPAQUE_AGENT_LOG("ERROR: crypto::init() failed");
        return static_cast<int>(Result::CryptoError);
    }
    if (Result key_result = crypto::validate_public_key(server_public_key, PUBLIC_KEY_LENGTH);
        key_result != Result::Success) {
        OPAQUE_AGENT_LOG("ERROR: Invalid server public key (%d)", static_cast<int>(key_result));
        return static_cast<int>(key_result);
    }
    try {
        auto client = std::make_unique<OpaqueAgentHandle>(server_public_key, key_length);
        *handle = client.release();
        OPAQUE_AGENT_LOG("SUCCESS: client handle created at %p", *handle);
        return static_cast<int>(Result::Success);
    } catch (const std::exception &e) {
        OPAQUE_AGENT_LOG("ERROR: Exception - %s", e.what());
        return static_cast<int>(Result::MemoryError);
    }
}

ECLIPTIX_OPAQUE_C_EXPORT void opaque_agent_destroy(void *handle) {
    OPAQUE_AGENT_LOG("=== opaque_agent_destroy === handle=%p", handle);
    if (handle) {
        std::unique_ptr<OpaqueAgentHandle> client(
            static_cast<OpaqueAgentHandle *>(handle));
    }
}

ECLIPTIX_OPAQUE_C_EXPORT int opaque_agent_state_create(void **handle) {
    OPAQUE_AGENT_LOG("=== opaque_agent_state_create ===");
    if (!handle) {
        OPAQUE_AGENT_LOG("ERROR: InvalidInput - handle is null");
        return static_cast<int>(Result::InvalidInput);
    }
    try {
        auto state = std::make_unique<AgentStateHandle>();
        state->has_active_session = true;
        *handle = state.release();
        OPAQUE_AGENT_LOG("SUCCESS: state handle created at %p", *handle);
        return static_cast<int>(Result::Success);
    } catch (const std::exception &e) {
        OPAQUE_AGENT_LOG("ERROR: Exception - %s", e.what());
        return static_cast<int>(Result::MemoryError);
    }
}

ECLIPTIX_OPAQUE_C_EXPORT void opaque_agent_state_destroy(void *handle) {
    OPAQUE_AGENT_LOG("=== opaque_agent_state_destroy === handle=%p", handle);
    if (handle) {
        std::unique_ptr<AgentStateHandle> state(
            static_cast<AgentStateHandle *>(handle));
    }
}

ECLIPTIX_OPAQUE_C_EXPORT int opaque_agent_create_registration_request(
    void *client_handle,
    const uint8_t *secure_key,
    size_t secure_key_length,
    void *state_handle,
    uint8_t *request_out,
    size_t request_length) {
    OPAQUE_AGENT_LOG("=== opaque_agent_create_registration_request ===");
    OPAQUE_AGENT_LOG("client_handle=%p, state_handle=%p, secure_key_length=%zu, request_length=%zu",
                      client_handle, state_handle, secure_key_length, request_length);
    if (!client_handle || !secure_key || secure_key_length == 0 ||
        !state_handle || !request_out || request_length < REGISTRATION_REQUEST_LENGTH) {
        OPAQUE_AGENT_LOG("ERROR: InvalidInput");
        return static_cast<int>(Result::InvalidInput);
    }
    auto *client = static_cast<OpaqueAgentHandle *>(client_handle);
    auto *state = static_cast<AgentStateHandle *>(state_handle);
    OPAQUE_AGENT_LOG("client->is_initialized=%d, state->has_active_session=%d",
                      client->is_initialized, state->has_active_session);
    if (!client->is_initialized || !state->has_active_session) {
        OPAQUE_AGENT_LOG("ERROR: ValidationError - client or state not ready");
        return static_cast<int>(Result::ValidationError);
    }
    try {
        initiator::RegistrationRequest request;
        OPAQUE_AGENT_LOG("Calling create_registration_request...");
        Result result = client->opaque_agent->create_registration_request(
            secure_key, secure_key_length, request, *state->agent_state);
        OPAQUE_AGENT_LOG("create_registration_request returned: %d", static_cast<int>(result));
        if (result != Result::Success) {
            return static_cast<int>(result);
        }

        if (request.data.size() != REGISTRATION_REQUEST_LENGTH) {
            OPAQUE_AGENT_LOG("ERROR: request.data.size()=%zu != expected %zu",
                              request.data.size(), REGISTRATION_REQUEST_LENGTH);
            return static_cast<int>(Result::CryptoError);
        }
        std::copy(request.data.begin(), request.data.end(), request_out);
        OPAQUE_AGENT_LOG_HEX("request_out", request_out, REGISTRATION_REQUEST_LENGTH);
        OPAQUE_AGENT_LOG("SUCCESS: registration request created");
        return static_cast<int>(Result::Success);
    } catch (const std::exception &e) {
        OPAQUE_AGENT_LOG("ERROR: Exception - %s", e.what());
        return static_cast<int>(Result::MemoryError);
    }
}

ECLIPTIX_OPAQUE_C_EXPORT int opaque_agent_finalize_registration(
    void *client_handle,
    const uint8_t *response,
    const size_t response_length,
    void *state_handle,
    uint8_t *record_out,
    const size_t record_length) {
    OPAQUE_AGENT_LOG("=== opaque_agent_finalize_registration ===");
    OPAQUE_AGENT_LOG("client_handle=%p, state_handle=%p", client_handle, state_handle);
    OPAQUE_AGENT_LOG("response_length=%zu (expected=%zu), record_length=%zu (expected=%zu)",
                      response_length, REGISTRATION_RESPONSE_LENGTH,
                      record_length, REGISTRATION_RECORD_LENGTH);
    if (!client_handle || !response || response_length != REGISTRATION_RESPONSE_LENGTH ||
        !state_handle || !record_out || record_length < REGISTRATION_RECORD_LENGTH) {
        OPAQUE_AGENT_LOG("ERROR: InvalidInput - response=%p, record_out=%p",
                          (void*)response, (void*)record_out);
        return static_cast<int>(Result::InvalidInput);
    }
    OPAQUE_AGENT_LOG_HEX("response", response, response_length);
    auto *client = static_cast<OpaqueAgentHandle *>(client_handle);
    auto *state = static_cast<AgentStateHandle *>(state_handle);
    if (!client->is_initialized || !state->has_active_session) {
        OPAQUE_AGENT_LOG("ERROR: ValidationError");
        return static_cast<int>(Result::ValidationError);
    }
    try {
        initiator::RegistrationRecord record;
        OPAQUE_AGENT_LOG("Calling finalize_registration...");
        Result result = client->opaque_agent->finalize_registration(
            response, response_length, *state->agent_state, record);
        OPAQUE_AGENT_LOG("finalize_registration returned: %d", static_cast<int>(result));
        if (result != Result::Success) {
            return static_cast<int>(result);
        }

        OPAQUE_AGENT_LOG("envelope.size=%zu, initiator_public_key.size=%zu",
                          record.envelope.size(), record.initiator_public_key.size());
        Result write_result = protocol::write_registration_record(
            record.envelope.data(), record.envelope.size(),
            record.initiator_public_key.data(), record.initiator_public_key.size(),
            record_out, record_length);
        if (write_result != Result::Success) {
            OPAQUE_AGENT_LOG("ERROR: write_registration_record failed (%d)", static_cast<int>(write_result));
            return static_cast<int>(write_result);
        }

        OPAQUE_AGENT_LOG_HEX("record_out", record_out, REGISTRATION_RECORD_LENGTH);
        OPAQUE_AGENT_LOG("SUCCESS: registration finalized");
        return static_cast<int>(Result::Success);
    } catch (const std::exception &e) {
        OPAQUE_AGENT_LOG("ERROR: Exception - %s", e.what());
        return static_cast<int>(Result::MemoryError);
    }
}

ECLIPTIX_OPAQUE_C_EXPORT int opaque_agent_generate_ke1(
    void *client_handle,
    const uint8_t *secure_key,
    size_t secure_key_length,
    void *state_handle,
    uint8_t *ke1_out,
    size_t ke1_length) {
    OPAQUE_AGENT_LOG("=== opaque_agent_generate_ke1 ===");
    OPAQUE_AGENT_LOG("client_handle=%p, state_handle=%p, secure_key_length=%zu, ke1_length=%zu (expected=%zu)",
                      client_handle, state_handle, secure_key_length, ke1_length, KE1_LENGTH);
    if (!client_handle || !secure_key || secure_key_length == 0 ||
        !state_handle || !ke1_out || ke1_length < KE1_LENGTH) {
        OPAQUE_AGENT_LOG("ERROR: InvalidInput");
        return static_cast<int>(Result::InvalidInput);
    }
    const auto *client = static_cast<OpaqueAgentHandle *>(client_handle);
    const auto *state = static_cast<AgentStateHandle *>(state_handle);
    if (!client->is_initialized || !state->has_active_session) {
        OPAQUE_AGENT_LOG("ERROR: ValidationError");
        return static_cast<int>(Result::ValidationError);
    }
    try {
        initiator::KE1 ke1;
        OPAQUE_AGENT_LOG("Calling generate_ke1...");
        Result result = initiator::OpaqueInitiator::generate_ke1(
            secure_key, secure_key_length, ke1, *state->agent_state);
        OPAQUE_AGENT_LOG("generate_ke1 returned: %d", static_cast<int>(result));
        if (result != Result::Success) {
            return static_cast<int>(result);
        }

        Result write_result = protocol::write_ke1(
            ke1.credential_request.data(), ke1.credential_request.size(),
            ke1.initiator_public_key.data(), ke1.initiator_public_key.size(),
            ke1.initiator_nonce.data(), ke1.initiator_nonce.size(),
            ke1.pq_ephemeral_public_key.data(), ke1.pq_ephemeral_public_key.size(),
            ke1_out, ke1_length);
        if (write_result != Result::Success) {
            OPAQUE_AGENT_LOG("ERROR: write_ke1 failed (%d)", static_cast<int>(write_result));
            return static_cast<int>(write_result);
        }

        OPAQUE_AGENT_LOG_HEX("ke1_out", ke1_out, KE1_LENGTH);
        OPAQUE_AGENT_LOG("SUCCESS: KE1 generated");
        return static_cast<int>(Result::Success);
    } catch (const std::exception &e) {
        OPAQUE_AGENT_LOG("ERROR: Exception - %s", e.what());
        return static_cast<int>(Result::MemoryError);
    }
}

ECLIPTIX_OPAQUE_C_EXPORT int opaque_agent_generate_ke3(
    void *client_handle,
    const uint8_t *ke2,
    const size_t ke2_length,
    void *state_handle,
    uint8_t *ke3_out,
    const size_t ke3_length) {
    OPAQUE_AGENT_LOG("=== opaque_agent_generate_ke3 ===");
    OPAQUE_AGENT_LOG("client_handle=%p, state_handle=%p, ke2_length=%zu (expected=%zu), ke3_length=%zu",
                      client_handle, state_handle, ke2_length, KE2_LENGTH, ke3_length);
    if (!client_handle || !ke2 || ke2_length != KE2_LENGTH ||
        !state_handle || !ke3_out || ke3_length < KE3_LENGTH) {
        OPAQUE_AGENT_LOG("ERROR: InvalidInput");
        return static_cast<int>(Result::InvalidInput);
    }
    OPAQUE_AGENT_LOG_HEX("ke2", ke2, ke2_length);
    const auto *client = static_cast<OpaqueAgentHandle *>(client_handle);
    const auto *state = static_cast<AgentStateHandle *>(state_handle);
    if (!client->is_initialized || !state->has_active_session) {
        OPAQUE_AGENT_LOG("ERROR: ValidationError");
        return static_cast<int>(Result::ValidationError);
    }
    try {
        initiator::KE3 ke3;
        OPAQUE_AGENT_LOG("Calling generate_ke3...");
        Result result = client->opaque_agent->generate_ke3(
            ke2, ke2_length, *state->agent_state, ke3);
        OPAQUE_AGENT_LOG("generate_ke3 returned: %d", static_cast<int>(result));
        if (result != Result::Success) {
            return static_cast<int>(result);
        }

        Result write_result = protocol::write_ke3(
            ke3.initiator_mac.data(), ke3.initiator_mac.size(),
            ke3_out, ke3_length);
        if (write_result != Result::Success) {
            OPAQUE_AGENT_LOG("ERROR: write_ke3 failed (%d)", static_cast<int>(write_result));
            return static_cast<int>(write_result);
        }
        OPAQUE_AGENT_LOG_HEX("ke3_out", ke3_out, KE3_LENGTH);
        OPAQUE_AGENT_LOG("SUCCESS: KE3 generated");
        return static_cast<int>(Result::Success);
    } catch (const std::exception &e) {
        OPAQUE_AGENT_LOG("ERROR: Exception - %s", e.what());
        return static_cast<int>(Result::MemoryError);
    }
}

ECLIPTIX_OPAQUE_C_EXPORT int opaque_agent_finish(
    void *client_handle,
    void *state_handle,
    uint8_t *session_key_out,
    size_t session_key_length,
    uint8_t *master_key_out,
    size_t master_key_length) {
    OPAQUE_AGENT_LOG("=== opaque_agent_finish ===");
    OPAQUE_AGENT_LOG("client_handle=%p, state_handle=%p, session_key_length=%zu, master_key_length=%zu",
                      client_handle, state_handle, session_key_length, master_key_length);
    if (!client_handle || !state_handle ||
        !session_key_out || session_key_length < HASH_LENGTH ||
        !master_key_out || master_key_length < MASTER_KEY_LENGTH) {
        OPAQUE_AGENT_LOG("ERROR: InvalidInput");
        return static_cast<int>(Result::InvalidInput);
    }
    const auto *client = static_cast<OpaqueAgentHandle *>(client_handle);
    const auto *state = static_cast<AgentStateHandle *>(state_handle);
    if (!client->is_initialized || !state->has_active_session) {
        OPAQUE_AGENT_LOG("ERROR: ValidationError");
        return static_cast<int>(Result::ValidationError);
    }
    try {
        secure_bytes session_key;
        secure_bytes master_key;
        OPAQUE_AGENT_LOG("Calling initiator_finish...");
        if (Result result = initiator::OpaqueInitiator::initiator_finish(*state->agent_state, session_key, master_key);
            result != Result::Success) {
            OPAQUE_AGENT_LOG("initiator_finish returned: %d", static_cast<int>(result));
            return static_cast<int>(result);
        }

        const size_t copy_length = std::min(session_key_length, session_key.size());
        std::copy_n(session_key.begin(), static_cast<std::ptrdiff_t>(copy_length), session_key_out);
        if (master_key.size() != MASTER_KEY_LENGTH) {
            OPAQUE_AGENT_LOG("ERROR: master_key size mismatch");
            return static_cast<int>(Result::CryptoError);
        }
        std::copy_n(master_key.begin(), MASTER_KEY_LENGTH, master_key_out);
        OPAQUE_AGENT_LOG("SUCCESS: client finished (keys derived, not logged)");
        return static_cast<int>(Result::Success);
    } catch (const std::exception &e) {
        OPAQUE_AGENT_LOG("ERROR: Exception - %s", e.what());
        return static_cast<int>(Result::MemoryError);
    }
}

ECLIPTIX_OPAQUE_C_EXPORT int opaque_agent_create_default(void **handle) {
#if defined(ECLIPTIX_OPAQUE_ENABLE_INSECURE_TEST_KEYS)
    return opaque_agent_create(keys::SERVER_PUBLIC_KEY, PUBLIC_KEY_LENGTH, handle);
#else
    if (!handle) {
        return static_cast<int>(Result::InvalidInput);
    }
    *handle = nullptr;
    return static_cast<int>(Result::InvalidInput);
#endif
}

ECLIPTIX_OPAQUE_C_EXPORT const char *opaque_agent_get_version() {
    return OPAQUE_AGENT_VERSION;
}

ECLIPTIX_OPAQUE_C_EXPORT size_t opaque_get_ke1_length() {
    return KE1_LENGTH;
}

ECLIPTIX_OPAQUE_C_EXPORT size_t opaque_get_ke2_length() {
    return KE2_LENGTH;
}

ECLIPTIX_OPAQUE_C_EXPORT size_t opaque_get_ke3_length() {
    return KE3_LENGTH;
}

ECLIPTIX_OPAQUE_C_EXPORT size_t opaque_get_registration_record_length() {
    return REGISTRATION_RECORD_LENGTH;
}

ECLIPTIX_OPAQUE_C_EXPORT size_t opaque_get_kem_public_key_length() {
    return pq_constants::KEM_PUBLIC_KEY_LENGTH;
}

ECLIPTIX_OPAQUE_C_EXPORT size_t opaque_get_kem_ciphertext_length() {
    return pq_constants::KEM_CIPHERTEXT_LENGTH;
}
}
