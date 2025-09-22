#include "opaque/opaque.h"
#include <sodium.h>
#include <algorithm>
namespace ecliptix::security::opaque {
namespace envelope {
Result seal(const uint8_t* randomized_password, size_t password_length,
           const uint8_t* server_public_key,
           const uint8_t* client_private_key,
           const uint8_t* client_public_key,
           Envelope& envelope) {
    if (!randomized_password || password_length == 0 ||
        !server_public_key || !client_private_key ||
        !client_public_key) {
        return Result::InvalidInput;
    }
    randombytes_buf(envelope.nonce.data(), envelope.nonce.size());
    uint8_t auth_key[crypto_secretbox_KEYBYTES];
    crypto_hash_sha512_state state;
    crypto_hash_sha512_init(&state);
    const char* context = "OPAQUE-Envelope";
    crypto_hash_sha512_update(&state, reinterpret_cast<const uint8_t*>(context), strlen(context));
    crypto_hash_sha512_update(&state, server_public_key, PUBLIC_KEY_LENGTH);
    crypto_hash_sha512_update(&state, randomized_password, password_length);
    uint8_t hash[crypto_hash_sha512_BYTES];
    crypto_hash_sha512_final(&state, hash);
    std::copy(hash, hash + crypto_secretbox_KEYBYTES, auth_key);
    secure_bytes plaintext(PUBLIC_KEY_LENGTH + PRIVATE_KEY_LENGTH + PUBLIC_KEY_LENGTH);
    size_t offset = 0;
    std::copy(server_public_key, server_public_key + PUBLIC_KEY_LENGTH,
             plaintext.begin() + offset);
    offset += PUBLIC_KEY_LENGTH;
    std::copy(client_private_key, client_private_key + PRIVATE_KEY_LENGTH,
             plaintext.begin() + offset);
    offset += PRIVATE_KEY_LENGTH;
    std::copy(client_public_key, client_public_key + PUBLIC_KEY_LENGTH,
             plaintext.begin() + offset);
    secure_bytes combined(plaintext.size() + crypto_secretbox_MACBYTES);
    crypto_secretbox_easy(combined.data(), plaintext.data(), plaintext.size(),
                         envelope.nonce.data(), auth_key);
    envelope.ciphertext.resize(plaintext.size());
    envelope.auth_tag.resize(crypto_secretbox_MACBYTES);
    std::copy_n(combined.begin(), plaintext.size(),
             envelope.ciphertext.begin());
    std::copy(combined.begin() + plaintext.size(),
             combined.begin() + plaintext.size() + crypto_secretbox_MACBYTES,
             envelope.auth_tag.begin());
    sodium_memzero(auth_key, sizeof(auth_key));
    return Result::Success;
}
Result open(const Envelope& envelope,
           const uint8_t* randomized_password, size_t password_length,
           uint8_t* server_public_key,
           uint8_t* client_private_key,
           uint8_t* client_public_key) {
    if (!randomized_password || password_length == 0 ||
        !server_public_key || !client_private_key || !client_public_key) {
        return Result::InvalidInput;
    }
    uint8_t temp_server_key[PUBLIC_KEY_LENGTH];
    std::copy(server_public_key, server_public_key + PUBLIC_KEY_LENGTH, temp_server_key);
    uint8_t auth_key[crypto_secretbox_KEYBYTES];
    crypto_hash_sha512_state state;
    crypto_hash_sha512_init(&state);
    const char* context = "OPAQUE-Envelope";
    crypto_hash_sha512_update(&state, reinterpret_cast<const uint8_t*>(context), strlen(context));
    crypto_hash_sha512_update(&state, temp_server_key, PUBLIC_KEY_LENGTH);
    crypto_hash_sha512_update(&state, randomized_password, password_length);
    uint8_t hash[crypto_hash_sha512_BYTES];
    crypto_hash_sha512_final(&state, hash);
    std::copy(hash, hash + crypto_secretbox_KEYBYTES, auth_key);
    const size_t plaintext_length = PUBLIC_KEY_LENGTH + PRIVATE_KEY_LENGTH + PUBLIC_KEY_LENGTH;
    secure_bytes plaintext(plaintext_length);
    secure_bytes combined(envelope.ciphertext.size() + crypto_secretbox_MACBYTES);
    std::copy(envelope.ciphertext.begin(), envelope.ciphertext.end(), combined.begin());
    std::copy(envelope.auth_tag.begin(), envelope.auth_tag.end(),
             combined.begin() + envelope.ciphertext.size());
    if (crypto_secretbox_open_easy(plaintext.data(), combined.data(), combined.size(),
                                  envelope.nonce.data(), auth_key) != 0) {
        return Result::AuthenticationError;
    }
    sodium_memzero(auth_key, sizeof(auth_key));
    size_t offset = 0;
    std::copy(plaintext.begin() + offset, plaintext.begin() + offset + PUBLIC_KEY_LENGTH,
             server_public_key);
    offset += PUBLIC_KEY_LENGTH;
    std::copy(plaintext.begin() + offset, plaintext.begin() + offset + PRIVATE_KEY_LENGTH,
             client_private_key);
    offset += PRIVATE_KEY_LENGTH;
    std::copy(plaintext.begin() + offset, plaintext.begin() + offset + PUBLIC_KEY_LENGTH,
             client_public_key);
    uint8_t derived_public_key[PUBLIC_KEY_LENGTH];
    if (crypto_scalarmult_ristretto255_base(derived_public_key, client_private_key) != 0) {
        return Result::CryptoError;
    }
    if (!std::equal(client_public_key, client_public_key + PUBLIC_KEY_LENGTH,
                   derived_public_key)) {
        return Result::AuthenticationError;
    }
    return Result::Success;
}
}
}