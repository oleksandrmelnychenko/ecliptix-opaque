#include "opaque/responder.h"
#include "opaque/protocol.h"
#include "opaque/pq.h"
#include "opaque/version.h"
#include "opaque/hardcoded_keys.h"
#include "opaque/export.h"
#include <sodium.h>
#include <cstring>

#ifdef OPAQUE_INTEROP_LOGGING
#include <cstdio>
#warning "OPAQUE_INTEROP_LOGGING is enabled - DO NOT use in production builds!"

namespace {
constexpr char kServerLogPrefix[] = "[ECLIPTIX-OPAQUE-SERVER] ";
constexpr size_t kHexPreviewBytes = 8;
}

#define OPAQUE_SERVER_LOG(fmt, ...) fprintf(stderr, "%s" fmt "\n", kServerLogPrefix __VA_OPT__(,) __VA_ARGS__)
#define OPAQUE_SERVER_LOG_HEX(label, data, len) do { \
    fprintf(stderr, "%s%s: ", kServerLogPrefix, label); \
    for (size_t i_ = 0; i_ < ((len) > kHexPreviewBytes ? kHexPreviewBytes : (len)); i_++) fprintf(stderr, "%02x", (data)[i_]); \
    if ((len) > kHexPreviewBytes) fprintf(stderr, "..."); \
    fprintf(stderr, " (len=%zu)\n", (size_t)(len)); \
} while(0)

#else

#define OPAQUE_SERVER_LOG(fmt, ...) ((void)0)
#define OPAQUE_SERVER_LOG_HEX(label, data, len) ((void)0)

#endif

extern "C" {
using namespace ecliptix::security::opaque;
using namespace ecliptix::security::opaque::responder;

typedef struct {
    OpaqueResponder *server;
} opaque_server_handle_t;

typedef struct {
    ResponderState *state;
} server_state_handle_t;

typedef struct {
    ResponderKeyPair *keypair;
} server_keypair_handle_t;

ECLIPTIX_OPAQUE_C_EXPORT int opaque_server_keypair_generate(server_keypair_handle_t **handle) {
    OPAQUE_SERVER_LOG("=== opaque_server_keypair_generate ===");
    if (!handle) {
        OPAQUE_SERVER_LOG("ERROR: InvalidInput - handle is null");
        return static_cast<int>(Result::InvalidInput);
    }
    try {
        if (!crypto::init()) {
            OPAQUE_SERVER_LOG("ERROR: crypto::init() failed");
            return static_cast<int>(Result::CryptoError);
        }
        const auto keypair = new ResponderKeyPair();
        if (Result result = ResponderKeyPair::generate(*keypair); result != Result::Success) {
            OPAQUE_SERVER_LOG("ERROR: keypair generate failed: %d", static_cast<int>(result));
            delete keypair;
            return static_cast<int>(result);
        }
        const auto keypair_handle = new server_keypair_handle_t;
        keypair_handle->keypair = keypair;
        *handle = keypair_handle;
        OPAQUE_SERVER_LOG("SUCCESS: keypair generated at %p", (void*)*handle);
        return static_cast<int>(Result::Success);
    } catch (...) {
        OPAQUE_SERVER_LOG("ERROR: Exception");
        return static_cast<int>(Result::MemoryError);
    }
}

ECLIPTIX_OPAQUE_C_EXPORT void opaque_server_keypair_destroy(server_keypair_handle_t *handle) {
    if (handle) {
        delete handle->keypair;
        delete handle;
    }
}

ECLIPTIX_OPAQUE_C_EXPORT int opaque_server_keypair_get_public_key(server_keypair_handle_t *handle,
                                         uint8_t *public_key, size_t key_buffer_size) {
    if (!handle || !handle->keypair || !public_key || key_buffer_size < PUBLIC_KEY_LENGTH) {
        return static_cast<int>(Result::InvalidInput);
    }
    std::memcpy(public_key, handle->keypair->public_key.data(), PUBLIC_KEY_LENGTH);
    return static_cast<int>(Result::Success);
}

ECLIPTIX_OPAQUE_C_EXPORT int opaque_server_create(server_keypair_handle_t *keypair_handle,
                         opaque_server_handle_t **handle) {
    if (!keypair_handle || !keypair_handle->keypair || !handle) {
        return static_cast<int>(Result::InvalidInput);
    }
    if (!crypto::init()) {
        return static_cast<int>(Result::CryptoError);
    }
    if (Result key_result = crypto::validate_public_key(keypair_handle->keypair->public_key.data(),
                                                        keypair_handle->keypair->public_key.size());
        key_result != Result::Success) {
        return static_cast<int>(key_result);
    }
    uint8_t derived_public_key[PUBLIC_KEY_LENGTH];
    if (crypto_scalarmult_ristretto255_base(derived_public_key, keypair_handle->keypair->private_key.data()) != 0) {
        sodium_memzero(derived_public_key, sizeof(derived_public_key));
        return static_cast<int>(Result::CryptoError);
    }
    if (crypto_verify_32(derived_public_key, keypair_handle->keypair->public_key.data()) != 0) {
        sodium_memzero(derived_public_key, sizeof(derived_public_key));
        return static_cast<int>(Result::InvalidPublicKey);
    }
    sodium_memzero(derived_public_key, sizeof(derived_public_key));
    try {
        const auto server = new OpaqueResponder(*keypair_handle->keypair);
        const auto server_handle = new opaque_server_handle_t;
        server_handle->server = server;
        *handle = server_handle;
        return static_cast<int>(Result::Success);
    } catch (...) {
        return static_cast<int>(Result::MemoryError);
    }
}

ECLIPTIX_OPAQUE_C_EXPORT void opaque_server_destroy(const opaque_server_handle_t *handle) {
    if (handle) {
        delete handle->server;
        delete handle;
    }
}

ECLIPTIX_OPAQUE_C_EXPORT int opaque_server_state_create(server_state_handle_t **handle) {
    if (!handle) {
        return static_cast<int>(Result::InvalidInput);
    }
    try {
        const auto state = new ResponderState();
        const auto state_handle = new server_state_handle_t;
        state_handle->state = state;
        *handle = state_handle;
        return static_cast<int>(Result::Success);
    } catch (...) {
        return static_cast<int>(Result::MemoryError);
    }
}

ECLIPTIX_OPAQUE_C_EXPORT void opaque_server_state_destroy(const server_state_handle_t *handle) {
    if (handle) {
        delete handle->state;
        delete handle;
    }
}

ECLIPTIX_OPAQUE_C_EXPORT int opaque_server_create_registration_response(const opaque_server_handle_t *server_handle,
                                               const uint8_t *request_data, size_t request_length,
                                               const uint8_t *account_id, size_t account_id_length,
                                               uint8_t *response_data, size_t response_buffer_size) {
    OPAQUE_SERVER_LOG("=== opaque_server_create_registration_response ===");
    OPAQUE_SERVER_LOG("server_handle=%p, request_length=%zu (expected=%zu)",
                      (void*)server_handle, request_length, REGISTRATION_REQUEST_LENGTH);
    OPAQUE_SERVER_LOG("response_buffer_size=%zu, account_id_length=%zu",
                      response_buffer_size, account_id_length);
    if (!server_handle || !server_handle->server || !request_data ||
        request_length != REGISTRATION_REQUEST_LENGTH ||
        !account_id || account_id_length == 0 ||
        !response_data || response_buffer_size < REGISTRATION_RESPONSE_LENGTH) {
        OPAQUE_SERVER_LOG("ERROR: InvalidInput");
        return static_cast<int>(Result::InvalidInput);
    }
    OPAQUE_SERVER_LOG_HEX("request_data", request_data, request_length);
    RegistrationResponse response;
    OPAQUE_SERVER_LOG("Calling create_registration_response...");
    Result result = server_handle->server->create_registration_response(
        request_data, request_length, account_id, account_id_length, response);
    OPAQUE_SERVER_LOG("create_registration_response returned: %d", static_cast<int>(result));
    if (result == Result::Success) {
        std::memcpy(response_data, response.data.data(), REGISTRATION_RESPONSE_LENGTH);
        OPAQUE_SERVER_LOG_HEX("response_data", response_data, REGISTRATION_RESPONSE_LENGTH);
        OPAQUE_SERVER_LOG("SUCCESS: registration response created");
    }
    return static_cast<int>(result);
}

ECLIPTIX_OPAQUE_C_EXPORT int opaque_server_build_credentials(const uint8_t *registration_record, size_t record_length,
                                    uint8_t *credentials_out, size_t credentials_out_length) {
    OPAQUE_SERVER_LOG("=== opaque_server_build_credentials ===");
    const size_t record_expected = REGISTRATION_RECORD_LENGTH;
    const size_t credentials_expected = RESPONDER_CREDENTIALS_LENGTH;
    OPAQUE_SERVER_LOG("record_length=%zu (expected=%zu), credentials_out_length=%zu (expected=%zu)",
                      record_length, record_expected, credentials_out_length, credentials_expected);

    if (!registration_record || record_length < record_expected ||
        !credentials_out || credentials_out_length < credentials_expected) {
        OPAQUE_SERVER_LOG("ERROR: InvalidInput");
        return static_cast<int>(Result::InvalidInput);
    }
    OPAQUE_SERVER_LOG_HEX("registration_record", registration_record, record_length);
    ResponderCredentials credentials;
    Result result = build_credentials(registration_record, record_length, credentials);
    if (result != Result::Success) {
        OPAQUE_SERVER_LOG("ERROR: build_credentials failed: %d", static_cast<int>(result));
        return static_cast<int>(result);
    }
    Result write_result = protocol::write_registration_record(
        credentials.envelope.data(), credentials.envelope.size(),
        credentials.initiator_public_key.data(), credentials.initiator_public_key.size(),
        credentials_out, credentials_out_length);
    if (write_result != Result::Success) {
        OPAQUE_SERVER_LOG("ERROR: write_registration_record failed: %d", static_cast<int>(write_result));
        return static_cast<int>(write_result);
    }
    OPAQUE_SERVER_LOG_HEX("credentials_out", credentials_out, credentials_expected);
    OPAQUE_SERVER_LOG("SUCCESS: credentials built");
    return static_cast<int>(Result::Success);
}

ECLIPTIX_OPAQUE_C_EXPORT int opaque_server_generate_ke2(const opaque_server_handle_t *server_handle,
                               const uint8_t *ke1_data, const size_t ke1_length,
                               const uint8_t *account_id, const size_t account_id_length,
                               const uint8_t *credentials_data, size_t credentials_length,
                               uint8_t *ke2_data, const size_t ke2_buffer_size,
                               const server_state_handle_t *state_handle) {
    OPAQUE_SERVER_LOG("=== opaque_server_generate_ke2 ===");
    OPAQUE_SERVER_LOG("server_handle=%p, state_handle=%p", (void*)server_handle, (void*)state_handle);
    OPAQUE_SERVER_LOG("ke1_length=%zu (expected=%zu), credentials_length=%zu (expected=%zu), ke2_buffer_size=%zu (expected=%zu)",
                      ke1_length, KE1_LENGTH,
                      credentials_length, RESPONDER_CREDENTIALS_LENGTH,
                      ke2_buffer_size, KE2_LENGTH);
    if (!server_handle || !server_handle->server || !ke1_data || ke1_length != KE1_LENGTH ||
        !account_id || account_id_length == 0 ||
        !credentials_data || credentials_length < RESPONDER_CREDENTIALS_LENGTH ||
        !ke2_data || ke2_buffer_size < KE2_LENGTH ||
        !state_handle || !state_handle->state) {
        OPAQUE_SERVER_LOG("ERROR: InvalidInput");
        return static_cast<int>(Result::InvalidInput);
    }
    OPAQUE_SERVER_LOG_HEX("ke1_data", ke1_data, ke1_length);
    OPAQUE_SERVER_LOG_HEX("credentials_data", credentials_data, credentials_length);
    protocol::RegistrationRecordView record_view{};
    Result parse_result = protocol::parse_registration_record(credentials_data, credentials_length, record_view);
    if (parse_result != Result::Success) {
        OPAQUE_SERVER_LOG("ERROR: Invalid credentials record (%d)", static_cast<int>(parse_result));
        return static_cast<int>(parse_result);
    }
    ResponderCredentials credentials;
    credentials.envelope.assign(record_view.envelope, record_view.envelope + ENVELOPE_LENGTH);
    credentials.initiator_public_key.assign(record_view.initiator_public_key,
                                            record_view.initiator_public_key + PUBLIC_KEY_LENGTH);
    KE2 ke2;
    OPAQUE_SERVER_LOG("Calling generate_ke2...");
    Result result = server_handle->server->generate_ke2(
        ke1_data, ke1_length, account_id, account_id_length, credentials, ke2, *state_handle->state);
    OPAQUE_SERVER_LOG("generate_ke2 returned: %d", static_cast<int>(result));
    if (result == Result::Success) {
        Result write_result = protocol::write_ke2(
            ke2.responder_nonce.data(), ke2.responder_nonce.size(),
            ke2.responder_public_key.data(), ke2.responder_public_key.size(),
            ke2.credential_response.data(), ke2.credential_response.size(),
            ke2.responder_mac.data(), ke2.responder_mac.size(),
            ke2.kem_ciphertext.data(), ke2.kem_ciphertext.size(),
            ke2_data, ke2_buffer_size);
        if (write_result != Result::Success) {
            OPAQUE_SERVER_LOG("ERROR: write_ke2 failed (%d)", static_cast<int>(write_result));
            return static_cast<int>(write_result);
        }
        OPAQUE_SERVER_LOG_HEX("ke2_data", ke2_data, KE2_LENGTH);
        OPAQUE_SERVER_LOG("SUCCESS: KE2 generated");
    }
    return static_cast<int>(result);
}

ECLIPTIX_OPAQUE_C_EXPORT int opaque_server_finish(const opaque_server_handle_t *server_handle,
                         const uint8_t *ke3_data, const size_t ke3_length,
                         const server_state_handle_t *state_handle,
                         uint8_t *session_key, const size_t session_key_buffer_size,
                         uint8_t *master_key_out, const size_t master_key_buffer_size) {
    OPAQUE_SERVER_LOG("=== opaque_server_finish ===");
    OPAQUE_SERVER_LOG("server_handle=%p, state_handle=%p", (void*)server_handle, (void*)state_handle);
    OPAQUE_SERVER_LOG("ke3_length=%zu (expected=%zu), session_key_buffer_size=%zu, master_key_buffer_size=%zu",
                      ke3_length, KE3_LENGTH, session_key_buffer_size, master_key_buffer_size);
    if (!server_handle || !server_handle->server || !ke3_data || ke3_length != KE3_LENGTH ||
        !state_handle || !state_handle->state ||
        !session_key || session_key_buffer_size < HASH_LENGTH ||
        !master_key_out || master_key_buffer_size < MASTER_KEY_LENGTH) {
        OPAQUE_SERVER_LOG("ERROR: InvalidInput");
        return static_cast<int>(Result::InvalidInput);
    }
    OPAQUE_SERVER_LOG_HEX("ke3_data", ke3_data, ke3_length);
    secure_bytes key;
    secure_bytes master_key;
    OPAQUE_SERVER_LOG("Calling responder_finish...");
    Result result = server_handle->server->responder_finish(
        ke3_data, ke3_length, *state_handle->state, key, master_key);
    OPAQUE_SERVER_LOG("responder_finish returned: %d", static_cast<int>(result));
    if (result == Result::Success) {
        std::memcpy(session_key, key.data(), std::min(key.size(), session_key_buffer_size));
        std::memcpy(master_key_out, master_key.data(), MASTER_KEY_LENGTH);
        OPAQUE_SERVER_LOG("SUCCESS: server finished (keys derived, not logged)");
    }
    return static_cast<int>(result);
}

ECLIPTIX_OPAQUE_C_EXPORT int opaque_server_create_default(opaque_server_handle_t **handle) {
#if defined(ECLIPTIX_OPAQUE_ENABLE_INSECURE_TEST_KEYS)
    if (!handle) {
        return static_cast<int>(Result::InvalidInput);
    }
    try {
        const auto keypair = new ResponderKeyPair();
        keypair->private_key.assign(keys::SERVER_PRIVATE_KEY, keys::SERVER_PRIVATE_KEY + PRIVATE_KEY_LENGTH);
        keypair->public_key.assign(keys::SERVER_PUBLIC_KEY, keys::SERVER_PUBLIC_KEY + PUBLIC_KEY_LENGTH);

        const auto server = new OpaqueResponder(*keypair);
        const auto server_handle = new opaque_server_handle_t;
        server_handle->server = server;
        *handle = server_handle;

        delete keypair;
        return static_cast<int>(Result::Success);
    } catch (...) {
        return static_cast<int>(Result::MemoryError);
    }
#else
    if (!handle) {
        return static_cast<int>(Result::InvalidInput);
    }
    *handle = nullptr;
    return static_cast<int>(Result::InvalidInput);
#endif
}

ECLIPTIX_OPAQUE_C_EXPORT int opaque_server_derive_keypair_from_seed(
    const uint8_t *seed, const size_t seed_len,
    uint8_t *private_key, const size_t private_key_buffer_len,
    uint8_t *public_key, const size_t public_key_buffer_len) {
    if (!seed || seed_len == 0 ||
        !private_key || private_key_buffer_len < PRIVATE_KEY_LENGTH ||
        !public_key || public_key_buffer_len < PUBLIC_KEY_LENGTH) {
        return static_cast<int>(Result::InvalidInput);
    }

    try {
        namespace crypto = crypto;
        if (!crypto::init()) {
            return static_cast<int>(Result::CryptoError);
        }

        uint8_t hash[crypto_hash_sha512_BYTES];
        crypto_hash_sha512(hash, seed, seed_len);

        crypto_core_ristretto255_scalar_reduce(private_key, hash);
        if (sodium_is_zero(private_key, PRIVATE_KEY_LENGTH) == 1) {
            sodium_memzero(hash, sizeof(hash));
            return static_cast<int>(Result::InvalidInput);
        }
        sodium_memzero(hash, sizeof(hash));

        if (crypto_scalarmult_ristretto255_base(public_key, private_key) != 0) {
            return static_cast<int>(Result::CryptoError);
        }

        return static_cast<int>(Result::Success);
    } catch (...) {
        return static_cast<int>(Result::CryptoError);
    }
}

ECLIPTIX_OPAQUE_C_EXPORT int opaque_server_create_with_keys(
    const uint8_t *private_key, const size_t private_key_len,
    const uint8_t *public_key, const size_t public_key_len,
    opaque_server_handle_t **handle) {
    OPAQUE_SERVER_LOG("=== opaque_server_create_with_keys ===");
    OPAQUE_SERVER_LOG("private_key_len=%zu, public_key_len=%zu", private_key_len, public_key_len);
    if (!private_key || private_key_len != PRIVATE_KEY_LENGTH ||
        !public_key || public_key_len != PUBLIC_KEY_LENGTH || !handle) {
        OPAQUE_SERVER_LOG("ERROR: InvalidInput");
        return static_cast<int>(Result::InvalidInput);
    }
    OPAQUE_SERVER_LOG_HEX("public_key", public_key, public_key_len);
    if (!crypto::init()) {
        OPAQUE_SERVER_LOG("ERROR: crypto::init() failed");
        return static_cast<int>(Result::CryptoError);
    }
    if (Result key_result = crypto::validate_public_key(public_key, PUBLIC_KEY_LENGTH);
        key_result != Result::Success) {
        OPAQUE_SERVER_LOG("ERROR: Invalid public key (%d)", static_cast<int>(key_result));
        return static_cast<int>(key_result);
    }
    uint8_t derived_public_key[PUBLIC_KEY_LENGTH];
    if (crypto_scalarmult_ristretto255_base(derived_public_key, private_key) != 0) {
        OPAQUE_SERVER_LOG("ERROR: scalar mult failed");
        sodium_memzero(derived_public_key, sizeof(derived_public_key));
        return static_cast<int>(Result::CryptoError);
    }
    if (crypto_verify_32(derived_public_key, public_key) != 0) {
        OPAQUE_SERVER_LOG("ERROR: derived public key doesn't match provided public key");
        sodium_memzero(derived_public_key, sizeof(derived_public_key));
        return static_cast<int>(Result::InvalidPublicKey);
    }
    sodium_memzero(derived_public_key, sizeof(derived_public_key));

    try {
        const auto keypair = new ResponderKeyPair();
        keypair->private_key.assign(private_key, private_key + PRIVATE_KEY_LENGTH);
        keypair->public_key.assign(public_key, public_key + PUBLIC_KEY_LENGTH);

        const auto server = new OpaqueResponder(*keypair);
        const auto server_handle = new opaque_server_handle_t;
        server_handle->server = server;
        *handle = server_handle;

        delete keypair;
        OPAQUE_SERVER_LOG("SUCCESS: server created at %p", (void*)*handle);
        return static_cast<int>(Result::Success);
    } catch (...) {
        OPAQUE_SERVER_LOG("ERROR: Exception");
        return static_cast<int>(Result::MemoryError);
    }
}

ECLIPTIX_OPAQUE_C_EXPORT const char *opaque_server_get_version() {
    return OPAQUE_SERVER_VERSION;
}

ECLIPTIX_OPAQUE_C_EXPORT size_t opaque_server_get_ke2_length() {
    return KE2_LENGTH;
}

ECLIPTIX_OPAQUE_C_EXPORT size_t opaque_server_get_registration_record_length() {
    return REGISTRATION_RECORD_LENGTH;
}

ECLIPTIX_OPAQUE_C_EXPORT size_t opaque_server_get_credentials_length() {
    return RESPONDER_CREDENTIALS_LENGTH;
}

ECLIPTIX_OPAQUE_C_EXPORT size_t opaque_server_get_kem_ciphertext_length() {
    return pq_constants::KEM_CIPHERTEXT_LENGTH;
}
}
