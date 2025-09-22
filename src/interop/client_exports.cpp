#include "opaque/opaque.h"
#include <sodium.h>
#include <cstring>
#include <memory>
#include <algorithm>
using namespace ecliptix::security::opaque;
struct OpaqueClientHandle {
    bool is_initialized;
    secure_bytes server_public_key;
    secure_bytes client_context;
    OpaqueClientHandle()
        : is_initialized(false)
        , server_public_key(PUBLIC_KEY_LENGTH)
        , client_context(64) {}
    ~OpaqueClientHandle() {
        is_initialized = false;
    }
};
struct ClientStateHandle {
    bool has_active_session;
    secure_bytes session_data;
    secure_bytes password_hash;
    secure_bytes blind_scalar;
    ClientStateHandle()
        : has_active_session(false)
        , session_data(128)
        , password_hash(HASH_LENGTH)
        , blind_scalar(PRIVATE_KEY_LENGTH) {}
    ~ClientStateHandle() {
        has_active_session = false;
    }
};
extern "C" {
int opaque_client_create(
    const uint8_t* server_public_key,
    size_t key_length,
    void** handle) {
    if (!server_public_key || key_length != PUBLIC_KEY_LENGTH || !handle) {
        return static_cast<int>(Result::InvalidInput);
    }
    if (crypto_core_ristretto255_is_valid_point(server_public_key) != 1) {
        return static_cast<int>(Result::InvalidPublicKey);
    }
    try {
        auto client = std::make_unique<OpaqueClientHandle>();
        std::copy(server_public_key, server_public_key + key_length,
                 client->server_public_key.begin());
        if (!crypto::init()) {
            return static_cast<int>(Result::CryptoError);
        }
        client->is_initialized = true;
        *handle = client.release();
        return static_cast<int>(Result::Success);
    } catch (const std::exception&) {
        return static_cast<int>(Result::MemoryError);
    }
}
void opaque_client_destroy(void* handle) {
    if (handle) {
        std::unique_ptr<OpaqueClientHandle> client(
            static_cast<OpaqueClientHandle*>(handle));
    }
}
int opaque_client_state_create(void** handle) {
    if (!handle) {
        return static_cast<int>(Result::InvalidInput);
    }
    try {
        auto state = std::make_unique<ClientStateHandle>();
        state->has_active_session = true;
        *handle = state.release();
        return static_cast<int>(Result::Success);
    } catch (const std::exception&) {
        return static_cast<int>(Result::MemoryError);
    }
}
void opaque_client_state_destroy(void* handle) {
    if (handle) {
        std::unique_ptr<ClientStateHandle> state(
            static_cast<ClientStateHandle*>(handle));
    }
}
int opaque_client_create_registration_request(
    void* client_handle,
    const uint8_t* password,
    size_t password_length,
    void* state_handle,
    uint8_t* request_out,
    size_t request_length) {
    if (!client_handle || !password || password_length == 0 ||
        !state_handle || !request_out || request_length < REGISTRATION_REQUEST_LENGTH) {
        return static_cast<int>(Result::InvalidInput);
    }
    auto* client = static_cast<OpaqueClientHandle*>(client_handle);
    auto* state = static_cast<ClientStateHandle*>(state_handle);
    if (!client->is_initialized || !state->has_active_session) {
        return static_cast<int>(Result::ValidationError);
    }
    try {
        uint8_t password_hash[HASH_LENGTH];
        Result result = crypto::kdf_extract(
            reinterpret_cast<const uint8_t*>("OPAQUE-Registration"), 19,
            password, password_length,
            password_hash);
        if (result != Result::Success) {
            return static_cast<int>(Result::CryptoError);
        }
        std::copy(password_hash, password_hash + HASH_LENGTH,
                 state->password_hash.begin());
        uint8_t blinded_element[PUBLIC_KEY_LENGTH];
        uint8_t blind_scalar[PRIVATE_KEY_LENGTH];
        result = oprf::blind(password_hash, HASH_LENGTH, blinded_element, blind_scalar);
        if (result != Result::Success) {
            return static_cast<int>(Result::CryptoError);
        }
        std::copy(blind_scalar, blind_scalar + PRIVATE_KEY_LENGTH,
                 state->blind_scalar.begin());
        std::copy(blinded_element, blinded_element + PUBLIC_KEY_LENGTH, request_out);
        return static_cast<int>(Result::Success);
    } catch (const std::exception&) {
        return static_cast<int>(Result::MemoryError);
    }
}
int opaque_client_finalize_registration(
    void* client_handle,
    const uint8_t* response,
    size_t response_length,
    void* state_handle,
    uint8_t* record_out,
    size_t record_length) {
    if (!client_handle || !response || response_length < REGISTRATION_RESPONSE_LENGTH ||
        !state_handle || !record_out || record_length < 168) {
        return static_cast<int>(Result::InvalidInput);
    }
    auto* client = static_cast<OpaqueClientHandle*>(client_handle);
    auto* state = static_cast<ClientStateHandle*>(state_handle);
    if (!client->is_initialized || !state->has_active_session) {
        return static_cast<int>(Result::ValidationError);
    }
    try {
        uint8_t evaluated_element[PUBLIC_KEY_LENGTH];
        std::copy(response, response + PUBLIC_KEY_LENGTH, evaluated_element);
        uint8_t oprf_output[HASH_LENGTH];
        Result result = oprf::finalize(
            state->password_hash.data(), HASH_LENGTH,
            state->blind_scalar.data(),
            evaluated_element,
            oprf_output);
        if (result != Result::Success) {
            return static_cast<int>(Result::CryptoError);
        }
        uint8_t client_private_key[PRIVATE_KEY_LENGTH];
        uint8_t client_public_key[PUBLIC_KEY_LENGTH];
        result = crypto::random_bytes(client_private_key, PRIVATE_KEY_LENGTH);
        if (result != Result::Success) {
            return static_cast<int>(Result::CryptoError);
        }
        result = crypto::derive_key_pair(client_private_key, client_private_key, client_public_key);
        if (result != Result::Success) {
            return static_cast<int>(Result::CryptoError);
        }
        Envelope envelope;
        result = envelope::seal(
            oprf_output, HASH_LENGTH,
            client->server_public_key.data(),
            client_private_key,
            client_public_key,
            envelope);
        if (result != Result::Success) {
            return static_cast<int>(Result::CryptoError);
        }
        size_t offset = 0;
        std::copy(envelope.nonce.begin(), envelope.nonce.end(), record_out + offset);
        offset += envelope.nonce.size();
        std::copy(envelope.ciphertext.begin(), envelope.ciphertext.end(), record_out + offset);
        offset += envelope.ciphertext.size();
        std::copy(envelope.auth_tag.begin(), envelope.auth_tag.end(), record_out + offset);
        offset += envelope.auth_tag.size();
        std::copy(client_public_key, client_public_key + PUBLIC_KEY_LENGTH, record_out + offset);
        return static_cast<int>(Result::Success);
    } catch (const std::exception&) {
        return static_cast<int>(Result::MemoryError);
    }
}
int opaque_client_generate_ke1(
    void* client_handle,
    const uint8_t* password,
    size_t password_length,
    void* state_handle,
    uint8_t* ke1_out,
    size_t ke1_length) {
    if (!client_handle || !password || password_length == 0 ||
        !state_handle || !ke1_out || ke1_length < KE1_LENGTH) {
        return static_cast<int>(Result::InvalidInput);
    }
    auto* client = static_cast<OpaqueClientHandle*>(client_handle);
    auto* state = static_cast<ClientStateHandle*>(state_handle);
    if (!client->is_initialized || !state->has_active_session) {
        return static_cast<int>(Result::ValidationError);
    }
    try {
        uint8_t password_hash[HASH_LENGTH];
        Result result = crypto::kdf_extract(
            reinterpret_cast<const uint8_t*>("OPAQUE-Authentication"), 22,
            password, password_length,
            password_hash);
        if (result != Result::Success) {
            return static_cast<int>(Result::CryptoError);
        }
        std::copy(password_hash, password_hash + HASH_LENGTH,
                 state->password_hash.begin());
        uint8_t blinded_element[PUBLIC_KEY_LENGTH];
        uint8_t blind_scalar[PRIVATE_KEY_LENGTH];
        result = oprf::blind(password_hash, HASH_LENGTH, blinded_element, blind_scalar);
        if (result != Result::Success) {
            return static_cast<int>(Result::CryptoError);
        }
        std::copy(blind_scalar, blind_scalar + PRIVATE_KEY_LENGTH,
                 state->blind_scalar.begin());
        uint8_t ephemeral_private[PRIVATE_KEY_LENGTH];
        uint8_t ephemeral_public[PUBLIC_KEY_LENGTH];
        result = crypto::random_bytes(ephemeral_private, PRIVATE_KEY_LENGTH);
        if (result != Result::Success) {
            return static_cast<int>(Result::CryptoError);
        }
        result = crypto::derive_key_pair(ephemeral_private, ephemeral_private, ephemeral_public);
        if (result != Result::Success) {
            return static_cast<int>(Result::CryptoError);
        }
        size_t offset = 0;
        std::copy(blinded_element, blinded_element + PUBLIC_KEY_LENGTH, ke1_out + offset);
        offset += PUBLIC_KEY_LENGTH;
        std::copy(ephemeral_public, ephemeral_public + PUBLIC_KEY_LENGTH, ke1_out + offset);
        offset += PUBLIC_KEY_LENGTH;
        result = crypto::random_bytes(ke1_out + offset, NONCE_LENGTH);
        if (result != Result::Success) {
            return static_cast<int>(Result::CryptoError);
        }
        std::copy(ephemeral_private, ephemeral_private + PRIVATE_KEY_LENGTH,
                 state->session_data.begin());
        return static_cast<int>(Result::Success);
    } catch (const std::exception&) {
        return static_cast<int>(Result::MemoryError);
    }
}
int opaque_client_generate_ke3(
    void* client_handle,
    const uint8_t* ke2,
    size_t ke2_length,
    void* state_handle,
    uint8_t* ke3_out,
    size_t ke3_length) {
    if (!client_handle || !ke2 || ke2_length < KE2_LENGTH ||
        !state_handle || !ke3_out || ke3_length < KE3_LENGTH) {
        return static_cast<int>(Result::InvalidInput);
    }
    auto* client = static_cast<OpaqueClientHandle*>(client_handle);
    auto* state = static_cast<ClientStateHandle*>(state_handle);
    if (!client->is_initialized || !state->has_active_session) {
        return static_cast<int>(Result::ValidationError);
    }
    try {
        size_t offset = 0;
        uint8_t evaluated_element[PUBLIC_KEY_LENGTH];
        std::copy(ke2 + offset, ke2 + offset + PUBLIC_KEY_LENGTH, evaluated_element);
        offset += PUBLIC_KEY_LENGTH;
        uint8_t oprf_output[HASH_LENGTH];
        Result result = oprf::finalize(
            state->password_hash.data(), HASH_LENGTH,
            state->blind_scalar.data(),
            evaluated_element,
            oprf_output);
        if (result != Result::Success) {
            return static_cast<int>(Result::CryptoError);
        }
        uint8_t shared_secret[PRIVATE_KEY_LENGTH];
        result = crypto::random_bytes(shared_secret, PRIVATE_KEY_LENGTH);
        if (result != Result::Success) {
            return static_cast<int>(Result::CryptoError);
        }
        result = crypto::hmac(
            shared_secret, PRIVATE_KEY_LENGTH,
            oprf_output, HASH_LENGTH,
            ke3_out);
        if (result != Result::Success) {
            return static_cast<int>(Result::CryptoError);
        }
        std::copy(shared_secret, shared_secret + PRIVATE_KEY_LENGTH,
                 state->session_data.begin() + PRIVATE_KEY_LENGTH);
        return static_cast<int>(Result::Success);
    } catch (const std::exception&) {
        return static_cast<int>(Result::MemoryError);
    }
}
int opaque_client_finish(
    void* client_handle,
    void* state_handle,
    uint8_t* session_key_out,
    size_t session_key_length) {
    if (!client_handle || !state_handle ||
        !session_key_out || session_key_length < 32) {
        return static_cast<int>(Result::InvalidInput);
    }
    auto* client = static_cast<OpaqueClientHandle*>(client_handle);
    auto* state = static_cast<ClientStateHandle*>(state_handle);
    if (!client->is_initialized || !state->has_active_session) {
        return static_cast<int>(Result::ValidationError);
    }
    try {
        const uint8_t* shared_secret = state->session_data.data() + PRIVATE_KEY_LENGTH;
        Result result = crypto::kdf_expand(
            shared_secret, PRIVATE_KEY_LENGTH,
            reinterpret_cast<const uint8_t*>("OPAQUE-SessionKey"), 18,
            session_key_out, std::min(session_key_length, size_t(32)));
        if (result != Result::Success) {
            return static_cast<int>(Result::CryptoError);
        }
        return static_cast<int>(Result::Success);
    } catch (const std::exception&) {
        return static_cast<int>(Result::MemoryError);
    }
}
} 