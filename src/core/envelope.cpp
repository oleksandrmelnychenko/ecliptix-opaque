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

    secure_bytes key_material(password_length + PUBLIC_KEY_LENGTH + PRIVATE_KEY_LENGTH);
    size_t offset = 0;

    std::copy(randomized_password, randomized_password + password_length,
             key_material.begin() + offset);
    offset += password_length;

    std::copy(server_public_key, server_public_key + PUBLIC_KEY_LENGTH,
             key_material.begin() + offset);
    offset += PUBLIC_KEY_LENGTH;

    std::copy(client_private_key, client_private_key + PRIVATE_KEY_LENGTH,
             key_material.begin() + offset);

    uint8_t auth_key[crypto_secretbox_KEYBYTES];
    crypto_hash_sha512_state state;
    crypto_hash_sha512_init(&state);
    crypto_hash_sha512_update(&state, key_material.data(), key_material.size());

    uint8_t hash[crypto_hash_sha512_BYTES];
    crypto_hash_sha512_final(&state, hash);

    std::copy(hash, hash + crypto_secretbox_KEYBYTES, auth_key);

    secure_bytes plaintext(PUBLIC_KEY_LENGTH + PRIVATE_KEY_LENGTH);
    std::copy(server_public_key, server_public_key + PUBLIC_KEY_LENGTH,
             plaintext.begin());
    std::copy(client_private_key, client_private_key + PRIVATE_KEY_LENGTH,
             plaintext.begin() + PUBLIC_KEY_LENGTH);

    secure_bytes ciphertext(plaintext.size() + crypto_secretbox_MACBYTES);
    crypto_secretbox_easy(ciphertext.data(), plaintext.data(), plaintext.size(),
                         envelope.nonce.data(), auth_key);

    envelope.auth_tag.resize(crypto_secretbox_MACBYTES);
    std::copy(ciphertext.begin() + plaintext.size(),
             ciphertext.begin() + plaintext.size() + crypto_secretbox_MACBYTES,
             envelope.auth_tag.begin());

    sodium_memzero(auth_key, sizeof(auth_key));

    return Result::Success;
}

Result open(const uint8_t* randomized_password, size_t password_length,
           const Envelope& envelope,
           uint8_t* server_public_key,
           uint8_t* client_private_key) {
    if (!randomized_password || password_length == 0 ||
        !server_public_key || !client_private_key) {
        return Result::InvalidInput;
    }

    uint8_t client_public_key[PUBLIC_KEY_LENGTH];
    if (crypto_scalarmult_ristretto255_base(client_public_key, client_private_key) != 0) {
        return Result::CryptoError;
    }

    secure_bytes key_material(password_length + PUBLIC_KEY_LENGTH + PRIVATE_KEY_LENGTH);
    size_t offset = 0;

    std::copy(randomized_password, randomized_password + password_length,
             key_material.begin() + offset);
    offset += password_length;

    std::copy(server_public_key, server_public_key + PUBLIC_KEY_LENGTH,
             key_material.begin() + offset);
    offset += PUBLIC_KEY_LENGTH;

    std::copy(client_private_key, client_private_key + PRIVATE_KEY_LENGTH,
             key_material.begin() + offset);

    uint8_t auth_key[crypto_secretbox_KEYBYTES];
    crypto_hash_sha512_state state;
    crypto_hash_sha512_init(&state);
    crypto_hash_sha512_update(&state, key_material.data(), key_material.size());

    uint8_t hash[crypto_hash_sha512_BYTES];
    crypto_hash_sha512_final(&state, hash);

    std::copy(hash, hash + crypto_secretbox_KEYBYTES, auth_key);

    size_t plaintext_length = PUBLIC_KEY_LENGTH + PRIVATE_KEY_LENGTH;
    secure_bytes ciphertext(plaintext_length + crypto_secretbox_MACBYTES);
    secure_bytes plaintext(plaintext_length);

    std::copy(envelope.auth_tag.begin(), envelope.auth_tag.end(),
             ciphertext.begin() + plaintext_length);

    if (crypto_secretbox_open_easy(plaintext.data(), ciphertext.data(),
                                  ciphertext.size(), envelope.nonce.data(),
                                  auth_key) != 0) {
        sodium_memzero(auth_key, sizeof(auth_key));
        return Result::AuthenticationError;
    }

    std::copy(plaintext.begin(), plaintext.begin() + PUBLIC_KEY_LENGTH,
             server_public_key);
    std::copy(plaintext.begin() + PUBLIC_KEY_LENGTH,
             plaintext.begin() + PUBLIC_KEY_LENGTH + PRIVATE_KEY_LENGTH,
             client_private_key);

    sodium_memzero(auth_key, sizeof(auth_key));

    return Result::Success;
}

Result recover_credentials(const uint8_t* randomized_password, size_t password_length,
                          const Envelope& envelope,
                          uint8_t* server_public_key,
                          uint8_t* client_private_key,
                          uint8_t* client_public_key) {
    if (!randomized_password || password_length == 0 ||
        !server_public_key || !client_private_key || !client_public_key) {
        return Result::InvalidInput;
    }

    Result result = open(randomized_password, password_length, envelope,
                        server_public_key, client_private_key);
    if (result != Result::Success) {
        return result;
    }

    if (crypto_scalarmult_ristretto255_base(client_public_key, client_private_key) != 0) {
        return Result::CryptoError;
    }

    return Result::Success;
}

}

}