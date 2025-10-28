#include "opaque/client.h"
#include <sodium.h>
#include <algorithm>
namespace ecliptix::security::opaque::client {
namespace {
    namespace oprf = ecliptix::security::opaque::oprf;
    namespace crypto = ecliptix::security::opaque::crypto;
    namespace envelope = ecliptix::security::opaque::envelope;
}
KE1::KE1() : client_nonce(NONCE_LENGTH), client_public_key(PUBLIC_KEY_LENGTH),
             credential_request(crypto_core_ristretto255_BYTES) {}
KE3::KE3() : client_mac(MAC_LENGTH) {}
Result generate_ke1_impl(const uint8_t* password, size_t password_length,
                        KE1& ke1, ClientState& state) {
    if (!password || password_length == 0) {
        return Result::InvalidInput;
    }
    state.password.assign(password, password + password_length);
    crypto::random_bytes(state.client_ephemeral_private_key.data(), PRIVATE_KEY_LENGTH);
    if (crypto_scalarmult_ristretto255_base(state.client_ephemeral_public_key.data(),
                                           state.client_ephemeral_private_key.data()) != 0) {
        return Result::CryptoError;
    }
    crypto::random_bytes(ke1.client_nonce.data(), NONCE_LENGTH);
    std::copy(ke1.client_nonce.begin(), ke1.client_nonce.end(), state.client_nonce.begin());
    std::copy(state.client_ephemeral_public_key.begin(), state.client_ephemeral_public_key.end(),
             ke1.client_public_key.begin());
    return oprf::blind(password, password_length, ke1.credential_request.data(),
                      state.oprf_blind_scalar.data());
}
Result generate_ke3_impl(const uint8_t* ke2_data, size_t ke2_length,
                        const uint8_t* server_public_key, ClientState& state, KE3& ke3) {
    if (!ke2_data || ke2_length != KE2_LENGTH) {
        return Result::InvalidInput;
    }
    const uint8_t* server_nonce = ke2_data;
    const uint8_t* server_ephemeral_public_key = ke2_data + NONCE_LENGTH;
    const uint8_t* credential_response = ke2_data + NONCE_LENGTH + PUBLIC_KEY_LENGTH;
    const uint8_t* evaluated_element = credential_response;
    const uint8_t* envelope_data = credential_response + crypto_core_ristretto255_BYTES;
    uint8_t oprf_output[crypto_hash_sha512_BYTES];
    Result result = oprf::finalize(state.password.data(), state.password.size(),
                                  state.oprf_blind_scalar.data(),
                                  evaluated_element, oprf_output);
    if (result != Result::Success) {
        return result;
    }
    uint8_t randomized_pwd[crypto_hash_sha512_BYTES];
    crypto_hash_sha512_state hash_state;
    crypto_hash_sha512_init(&hash_state);
    crypto_hash_sha512_update(&hash_state, oprf_output, sizeof(oprf_output));
    crypto_hash_sha512_update(&hash_state, state.password.data(), state.password.size());
    crypto_hash_sha512_final(&hash_state, randomized_pwd);
    Envelope env;
    env.nonce.assign(envelope_data, envelope_data + NONCE_LENGTH);
    const size_t ciphertext_size = ENVELOPE_LENGTH - NONCE_LENGTH - crypto_secretbox_MACBYTES;
    env.ciphertext.assign(envelope_data + NONCE_LENGTH,
                         envelope_data + NONCE_LENGTH + ciphertext_size);
    env.auth_tag.assign(envelope_data + NONCE_LENGTH + ciphertext_size,
                       envelope_data + NONCE_LENGTH + ciphertext_size + crypto_secretbox_MACBYTES);
    uint8_t recovered_server_public_key[PUBLIC_KEY_LENGTH];
    uint8_t recovered_client_private_key[PRIVATE_KEY_LENGTH];
    uint8_t recovered_client_public_key[PUBLIC_KEY_LENGTH];
    uint8_t recovered_master_key[MASTER_KEY_LENGTH];
    result = envelope::open(env, randomized_pwd, sizeof(randomized_pwd),
                           server_public_key, recovered_server_public_key, recovered_client_private_key,
                           recovered_client_public_key, recovered_master_key);
    if (result != Result::Success) {
        return result;
    }
    std::copy(recovered_server_public_key, recovered_server_public_key + PUBLIC_KEY_LENGTH,
             state.server_public_key.begin());
    std::copy(recovered_client_private_key, recovered_client_private_key + PRIVATE_KEY_LENGTH,
             state.client_private_key.begin());
    std::copy(recovered_client_public_key, recovered_client_public_key + PUBLIC_KEY_LENGTH,
             state.client_public_key.begin());
    std::copy(recovered_master_key, recovered_master_key + MASTER_KEY_LENGTH,
             state.master_key.begin());
    uint8_t dh1[PUBLIC_KEY_LENGTH];
    if (crypto_scalarmult_ristretto255(dh1, recovered_client_private_key,
                                      recovered_server_public_key) != 0) {
        return Result::CryptoError;
    }
    uint8_t dh2[PUBLIC_KEY_LENGTH];
    if (crypto_scalarmult_ristretto255(dh2, state.client_ephemeral_private_key.data(),
                                      recovered_server_public_key) != 0) {
        return Result::CryptoError;
    }
    uint8_t dh3[PUBLIC_KEY_LENGTH];
    if (crypto_scalarmult_ristretto255(dh3, recovered_client_private_key,
                                      server_ephemeral_public_key) != 0) {
        return Result::CryptoError;
    }
    secure_bytes ikm(3 * PUBLIC_KEY_LENGTH);
    std::copy(dh1, dh1 + PUBLIC_KEY_LENGTH,
             ikm.begin());
    std::copy(dh2, dh2 + PUBLIC_KEY_LENGTH,
             ikm.begin() + PUBLIC_KEY_LENGTH);
    std::copy(dh3, dh3 + PUBLIC_KEY_LENGTH,
             ikm.begin() + 2 * PUBLIC_KEY_LENGTH);
    uint8_t prk[crypto_auth_hmacsha512_BYTES];
    const uint8_t salt[] = "OPAQUE";
    result = crypto::kdf_extract(salt, sizeof(salt) - 1, ikm.data(), ikm.size(), prk);
    if (result != Result::Success) {
        return result;
    }
    state.session_key.resize(HASH_LENGTH);
    const uint8_t session_info[] = "SessionKey";
    result = crypto::kdf_expand(prk, sizeof(prk), session_info, sizeof(session_info) - 1,
                               state.session_key.data(), state.session_key.size());
    if (result != Result::Success) {
        return result;
    }
    secure_bytes mac_input(2 * NONCE_LENGTH + 2 * PUBLIC_KEY_LENGTH);
    size_t offset = 0;
    std::copy(state.client_ephemeral_public_key.begin(), state.client_ephemeral_public_key.end(),
             mac_input.begin() + offset);
    offset += PUBLIC_KEY_LENGTH;
    std::copy(server_ephemeral_public_key, server_ephemeral_public_key + PUBLIC_KEY_LENGTH,
             mac_input.begin() + offset);
    offset += PUBLIC_KEY_LENGTH;
    std::copy(state.client_nonce.begin(), state.client_nonce.end(),
             mac_input.begin() + offset);
    offset += NONCE_LENGTH;
    std::copy(server_nonce, server_nonce + NONCE_LENGTH,
             mac_input.begin() + offset);
    uint8_t client_mac_key[crypto_auth_hmacsha512_BYTES];
    const uint8_t mac_info[] = "ClientMAC";
    result = crypto::kdf_expand(prk, sizeof(prk), mac_info, sizeof(mac_info) - 1,
                               client_mac_key, sizeof(client_mac_key));
    if (result != Result::Success) {
        return result;
    }
    result = crypto::hmac(client_mac_key, sizeof(client_mac_key),
                         mac_input.data(), mac_input.size(),
                         ke3.client_mac.data());
    sodium_memzero(randomized_pwd, sizeof(randomized_pwd));
    sodium_memzero(oprf_output, sizeof(oprf_output));
    sodium_memzero(prk, sizeof(prk));
    sodium_memzero(client_mac_key, sizeof(client_mac_key));
    return result;
}
Result client_finish_impl(const ClientState& state, secure_bytes& session_key) {
    if (state.session_key.empty()) {
        return Result::InvalidInput;
    }
    session_key = state.session_key;
    return Result::Success;
}
}