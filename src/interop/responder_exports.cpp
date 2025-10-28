#include "opaque/responder.h"
#include "opaque/version.h"
#include "opaque/hardcoded_keys.h"
#include <cstring>
#include <sodium.h>

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

int opaque_server_keypair_generate(server_keypair_handle_t **handle) {
    if (!handle) {
        return static_cast<int>(Result::InvalidInput);
    }
    try {
        const auto keypair = new ResponderKeyPair();
        if (Result result = ResponderKeyPair::generate(*keypair); result != Result::Success) {
            delete keypair;
            return static_cast<int>(result);
        }
        const auto keypair_handle = new server_keypair_handle_t;
        keypair_handle->keypair = keypair;
        *handle = keypair_handle;
        return static_cast<int>(Result::Success);
    } catch (...) {
        return static_cast<int>(Result::MemoryError);
    }
}

void opaque_server_keypair_destroy(server_keypair_handle_t *handle) {
    if (handle) {
        delete handle->keypair;
        delete handle;
    }
}

int opaque_server_keypair_get_public_key(server_keypair_handle_t *handle,
                                         uint8_t *public_key, size_t key_buffer_size) {
    if (!handle || !handle->keypair || !public_key || key_buffer_size < PUBLIC_KEY_LENGTH) {
        return static_cast<int>(Result::InvalidInput);
    }
    std::memcpy(public_key, handle->keypair->public_key.data(), PUBLIC_KEY_LENGTH);
    return static_cast<int>(Result::Success);
}

int opaque_server_create(server_keypair_handle_t *keypair_handle,
                         opaque_server_handle_t **handle) {
    if (!keypair_handle || !keypair_handle->keypair || !handle) {
        return static_cast<int>(Result::InvalidInput);
    }
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

void opaque_server_destroy(const opaque_server_handle_t *handle) {
    if (handle) {
        delete handle->server;
        delete handle;
    }
}

int opaque_server_state_create(server_state_handle_t **handle) {
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

void opaque_server_state_destroy(const server_state_handle_t *handle) {
    if (handle) {
        delete handle->state;
        delete handle;
    }
}

int opaque_server_create_registration_response(const opaque_server_handle_t *server_handle,
                                               const uint8_t *request_data, size_t request_length,
                                               uint8_t *response_data, size_t response_buffer_size,
                                               uint8_t *credentials_data, size_t credentials_buffer_size) {
    if (!server_handle || !server_handle->server || !request_data ||
        request_length != REGISTRATION_REQUEST_LENGTH ||
        !response_data || response_buffer_size < REGISTRATION_RESPONSE_LENGTH ||
        !credentials_data || credentials_buffer_size < (ENVELOPE_LENGTH + PRIVATE_KEY_LENGTH + PUBLIC_KEY_LENGTH)) {
        return static_cast<int>(Result::InvalidInput);
    }
    RegistrationResponse response;
    ResponderCredentials credentials;
    Result result = server_handle->server->create_registration_response(
        request_data, request_length, response, credentials);
    if (result == Result::Success) {
        std::memcpy(response_data, response.data.data(), REGISTRATION_RESPONSE_LENGTH);
        std::memcpy(credentials_data, credentials.envelope.data(), ENVELOPE_LENGTH);
        std::memcpy(credentials_data + ENVELOPE_LENGTH, credentials.masking_key.data(), PRIVATE_KEY_LENGTH);
        std::memcpy(credentials_data + ENVELOPE_LENGTH + PRIVATE_KEY_LENGTH, credentials.initiator_public_key.data(),
                    PUBLIC_KEY_LENGTH);
    }
    return static_cast<int>(result);
}

int opaque_server_generate_ke2(const opaque_server_handle_t *server_handle,
                               const uint8_t *ke1_data, const size_t ke1_length,
                               const uint8_t *credentials_data, size_t credentials_length,
                               uint8_t *ke2_data, const size_t ke2_buffer_size,
                               const server_state_handle_t *state_handle) {
    if (!server_handle || !server_handle->server || !ke1_data || ke1_length != KE1_LENGTH ||
        !credentials_data || credentials_length < ENVELOPE_LENGTH + PRIVATE_KEY_LENGTH + PUBLIC_KEY_LENGTH ||
        !ke2_data || ke2_buffer_size < KE2_LENGTH ||
        !state_handle || !state_handle->state) {
        return static_cast<int>(Result::InvalidInput);
    }
    ResponderCredentials credentials;
    credentials.envelope.assign(credentials_data, credentials_data + ENVELOPE_LENGTH);
    credentials.masking_key.assign(credentials_data + ENVELOPE_LENGTH,
                                   credentials_data + ENVELOPE_LENGTH + PRIVATE_KEY_LENGTH);
    credentials.initiator_public_key.assign(credentials_data + ENVELOPE_LENGTH + PRIVATE_KEY_LENGTH,
                                            credentials_data + ENVELOPE_LENGTH + PRIVATE_KEY_LENGTH +
                                            PUBLIC_KEY_LENGTH);
    KE2 ke2;
    Result result = server_handle->server->generate_ke2(
        ke1_data, ke1_length, credentials, ke2, *state_handle->state);
    if (result == Result::Success) {
        size_t offset = 0;
        std::memcpy(ke2_data + offset, ke2.responder_nonce.data(), NONCE_LENGTH);
        offset += NONCE_LENGTH;
        std::memcpy(ke2_data + offset, ke2.responder_public_key.data(), PUBLIC_KEY_LENGTH);
        offset += PUBLIC_KEY_LENGTH;
        std::memcpy(ke2_data + offset, ke2.credential_response.data(), CREDENTIAL_RESPONSE_LENGTH);
        offset += CREDENTIAL_RESPONSE_LENGTH;
        std::memcpy(ke2_data + offset, ke2.responder_mac.data(), MAC_LENGTH);
    }
    return static_cast<int>(result);
}

int opaque_server_finish(const opaque_server_handle_t *server_handle,
                         const uint8_t *ke3_data, const size_t ke3_length,
                         const server_state_handle_t *state_handle,
                         uint8_t *session_key, const size_t session_key_buffer_size) {
    if (!server_handle || !server_handle->server || !ke3_data || ke3_length != KE3_LENGTH ||
        !state_handle || !state_handle->state ||
        !session_key || session_key_buffer_size < HASH_LENGTH) {
        return static_cast<int>(Result::InvalidInput);
    }
    secure_bytes key;
    Result result = server_handle->server->responder_finish(
        ke3_data, ke3_length, *state_handle->state, key);
    if (result == Result::Success) {
        std::memcpy(session_key, key.data(), std::min(key.size(), session_key_buffer_size));
    }
    return static_cast<int>(result);
}

int opaque_server_create_default(opaque_server_handle_t **handle) {
    if (!handle) {
        return static_cast<int>(Result::InvalidInput);
    }
    try {
        const auto keypair = new ResponderKeyPair();
        keypair->private_key.assign(keys::SERVER_PRIVATE_KEY, keys::SERVER_PRIVATE_KEY + 32);
        keypair->public_key.assign(keys::SERVER_PUBLIC_KEY, keys::SERVER_PUBLIC_KEY + 32);

        const auto server = new OpaqueResponder(*keypair);
        const auto server_handle = new opaque_server_handle_t;
        server_handle->server = server;
        *handle = server_handle;

        delete keypair;
        return static_cast<int>(Result::Success);
    } catch (...) {
        return static_cast<int>(Result::MemoryError);
    }
}

int opaque_server_derive_keypair_from_seed(
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

        uint8_t hash[crypto_hash_sha512_BYTES];
        crypto_hash_sha512(hash, seed, seed_len);

        std::copy_n(hash, PRIVATE_KEY_LENGTH, private_key);

        private_key[0] &= 248;
        private_key[31] &= 127;
        private_key[31] |= 64;

        if (crypto_scalarmult_ristretto255_base(public_key, private_key) != 0) {
            return static_cast<int>(Result::CryptoError);
        }

        return static_cast<int>(Result::Success);
    } catch (...) {
        return static_cast<int>(Result::CryptoError);
    }
}

int opaque_server_create_with_keys(
    const uint8_t *private_key, const size_t private_key_len,
    const uint8_t *public_key, const size_t public_key_len,
    opaque_server_handle_t **handle) {
    if (!private_key || private_key_len != PRIVATE_KEY_LENGTH ||
        !public_key || public_key_len != PUBLIC_KEY_LENGTH || !handle) {
        return static_cast<int>(Result::InvalidInput);
    }

    try {
        const auto keypair = new ResponderKeyPair();
        keypair->private_key.assign(private_key, private_key + PRIVATE_KEY_LENGTH);
        keypair->public_key.assign(public_key, public_key + PUBLIC_KEY_LENGTH);

        const auto server = new OpaqueResponder(*keypair);
        const auto server_handle = new opaque_server_handle_t;
        server_handle->server = server;
        *handle = server_handle;

        delete keypair;
        return static_cast<int>(Result::Success);
    } catch (...) {
        return static_cast<int>(Result::MemoryError);
    }
}

const char *opaque_server_get_version() {
    return OPAQUE_SERVER_VERSION;
}
}
