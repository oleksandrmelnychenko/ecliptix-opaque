/**
 * @file generate_test_vectors.cpp
 * @brief Generates deterministic test vectors for third-party verification.
 *
 * Uses a fixed seed to derive server keypair deterministically, producing
 * a reproducible full protocol trace with all intermediate values. Output is JSON.
 *
 * This allows independent implementors to verify their implementation
 * produces identical intermediate and final values.
 *
 * Usage:
 *   ./generate_test_vectors > test_vectors.json
 */

#include "opaque/opaque.h"
#include "opaque/initiator.h"
#include "opaque/responder.h"
#include "opaque/protocol.h"
#include "opaque/pq.h"
#include <sodium.h>
#include <cstdio>
#include <cstring>
#include <string>

using namespace ecliptix::security::opaque;

namespace {

std::string hex(const uint8_t* data, size_t len) {
    std::string result;
    result.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        char buf[3];
        std::snprintf(buf, sizeof(buf), "%02x", data[i]);
        result += buf;
    }
    return result;
}

std::string hex(const secure_bytes& v) {
    return hex(v.data(), v.size());
}

void json_field(const char* name, const std::string& value, bool last = false) {
    std::printf("    \"%s\": \"%s\"%s\n", name, value.c_str(), last ? "" : ",");
}

void json_field_int(const char* name, size_t value, bool last = false) {
    std::printf("    \"%s\": %zu%s\n", name, value, last ? "" : ",");
}

} // anonymous namespace


int main() {
    if (sodium_init() < 0) {
        std::fprintf(stderr, "sodium_init failed\n");
        return 1;
    }

    /*
     * Fixed seed for deterministic keypair derivation.
     * NOTE: The protocol still uses random nonces/ephemerals internally,
     * so this test vector captures ONE concrete execution trace.
     */
    const uint8_t server_seed[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
    };

    const char* password = "test_vector_password_v1";
    const uint8_t account_id[16] = {
        0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
    };

    /* Derive deterministic server keypair from seed */
    uint8_t server_sk[PRIVATE_KEY_LENGTH], server_pk[PUBLIC_KEY_LENGTH];
    if (crypto::derive_key_pair(server_seed, sizeof(server_seed),
                                 server_sk, server_pk) != Result::Success) {
        std::fprintf(stderr, "keypair derivation failed\n");
        return 1;
    }

    /* Create server and client objects */
    responder::ResponderKeyPair server_keypair;
    server_keypair.private_key.assign(server_sk, server_sk + PRIVATE_KEY_LENGTH);
    server_keypair.public_key.assign(server_pk, server_pk + PUBLIC_KEY_LENGTH);

    responder::OpaqueResponder server(server_keypair);
    ResponderPublicKey client_server_pk(server_pk, PUBLIC_KEY_LENGTH);
    initiator::OpaqueInitiator client(client_server_pk);

    std::printf("{\n");
    std::printf("  \"protocol\": \"Hybrid-PQ-OPAQUE\",\n");
    std::printf("  \"version\": \"ECLIPTIX-OPAQUE-PQ-v1\",\n");
    std::printf("  \"kem\": \"ML-KEM-768\",\n");
    std::printf("  \"dh_group\": \"Ristretto255\",\n");
    std::printf("  \"hash\": \"SHA-512\",\n");
    std::printf("  \"mac\": \"HMAC-SHA-512\",\n");
    std::printf("  \"aead\": \"XChaCha20-Poly1305\",\n");
    std::printf("  \"kdf\": \"Argon2id\",\n");
    std::printf("  \"combiner\": \"HKDF-Extract(label||transcript_hash, dh1||dh2||dh3||kem_ss)\",\n");
    std::printf("\n");

    /* ---- Inputs ---- */
    std::printf("  \"inputs\": {\n");
    json_field("server_seed", hex(server_seed, sizeof(server_seed)));
    json_field("server_private_key", hex(server_sk, sizeof(server_sk)));
    json_field("server_public_key", hex(server_pk, sizeof(server_pk)));
    json_field("password", hex(reinterpret_cast<const uint8_t*>(password), strlen(password)));
    json_field("password_utf8", password);
    json_field("account_id", hex(account_id, sizeof(account_id)), true);
    std::printf("  },\n\n");

    /* ---- Registration ---- */
    std::printf("  \"registration\": {\n");

    initiator::InitiatorState reg_state;
    initiator::RegistrationRequest reg_req;

    if (initiator::OpaqueInitiator::create_registration_request(
            reinterpret_cast<const uint8_t*>(password), strlen(password),
            reg_req, reg_state) != Result::Success) {
        std::fprintf(stderr, "create_registration_request failed\n");
        return 1;
    }

    json_field("registration_request", hex(reg_req.data));

    responder::RegistrationResponse reg_resp;
    if (server.create_registration_response(
            reg_req.data.data(), reg_req.data.size(),
            account_id, sizeof(account_id),
            reg_resp) != Result::Success) {
        std::fprintf(stderr, "create_registration_response failed\n");
        return 1;
    }

    json_field("registration_response", hex(reg_resp.data));

    initiator::RegistrationRecord reg_record;
    if (client.finalize_registration(
            reg_resp.data.data(), reg_resp.data.size(),
            reg_state, reg_record) != Result::Success) {
        std::fprintf(stderr, "finalize_registration failed\n");
        return 1;
    }

    secure_bytes record_buf;
    record_buf.resize(REGISTRATION_RECORD_LENGTH);
    if (protocol::write_registration_record(
            reg_record.envelope.data(), reg_record.envelope.size(),
            reg_record.initiator_public_key.data(), reg_record.initiator_public_key.size(),
            record_buf.data(), record_buf.size()) != Result::Success) {
        std::fprintf(stderr, "write_registration_record failed\n");
        return 1;
    }

    json_field("registration_record", hex(record_buf));
    json_field_int("registration_request_length", reg_req.data.size());
    json_field_int("registration_response_length", reg_resp.data.size());
    json_field_int("registration_record_length", record_buf.size(), true);
    std::printf("  },\n\n");

    /* Build credentials */
    ResponderCredentials credentials;
    if (responder::build_credentials(record_buf.data(), record_buf.size(),
                                      credentials) != Result::Success) {
        std::fprintf(stderr, "build_credentials failed\n");
        return 1;
    }

    /* ---- Authentication ---- */
    std::printf("  \"authentication\": {\n");

    initiator::InitiatorState auth_state;
    initiator::KE1 ke1;

    if (initiator::OpaqueInitiator::generate_ke1(
            reinterpret_cast<const uint8_t*>(password), strlen(password),
            ke1, auth_state) != Result::Success) {
        std::fprintf(stderr, "generate_ke1 failed\n");
        return 1;
    }

    secure_bytes ke1_data;
    ke1_data.resize(KE1_LENGTH);
    if (protocol::write_ke1(
            ke1.credential_request.data(), ke1.credential_request.size(),
            ke1.initiator_public_key.data(), ke1.initiator_public_key.size(),
            ke1.initiator_nonce.data(), ke1.initiator_nonce.size(),
            ke1.pq_ephemeral_public_key.data(), ke1.pq_ephemeral_public_key.size(),
            ke1_data.data(), ke1_data.size()) != Result::Success) {
        std::fprintf(stderr, "write_ke1 failed\n");
        return 1;
    }

    json_field("ke1", hex(ke1_data));
    json_field_int("ke1_length", ke1_data.size());

    /* KE2 */
    responder::ResponderState srv_state;
    responder::KE2 ke2;

    if (server.generate_ke2(
            ke1_data.data(), ke1_data.size(),
            account_id, sizeof(account_id),
            credentials, ke2, srv_state) != Result::Success) {
        std::fprintf(stderr, "generate_ke2 failed\n");
        return 1;
    }

    secure_bytes ke2_data;
    ke2_data.resize(KE2_LENGTH);
    if (protocol::write_ke2(
            ke2.responder_nonce.data(), ke2.responder_nonce.size(),
            ke2.responder_public_key.data(), ke2.responder_public_key.size(),
            ke2.credential_response.data(), ke2.credential_response.size(),
            ke2.responder_mac.data(), ke2.responder_mac.size(),
            ke2.kem_ciphertext.data(), ke2.kem_ciphertext.size(),
            ke2_data.data(), ke2_data.size()) != Result::Success) {
        std::fprintf(stderr, "write_ke2 failed\n");
        return 1;
    }

    json_field("ke2", hex(ke2_data));
    json_field_int("ke2_length", ke2_data.size());

    /* KE3 */
    initiator::KE3 ke3;

    if (client.generate_ke3(
            ke2_data.data(), ke2_data.size(),
            auth_state, ke3) != Result::Success) {
        std::fprintf(stderr, "generate_ke3 failed\n");
        return 1;
    }

    json_field("ke3", hex(ke3.initiator_mac));
    json_field_int("ke3_length", ke3.initiator_mac.size());

    /* Finish */
    secure_bytes server_session_key, server_master_key;
    if (server.responder_finish(
            ke3.initiator_mac.data(), ke3.initiator_mac.size(),
            srv_state, server_session_key, server_master_key) != Result::Success) {
        std::fprintf(stderr, "responder_finish failed\n");
        return 1;
    }

    secure_bytes client_session_key, client_master_key;
    if (initiator::OpaqueInitiator::initiator_finish(
            auth_state, client_session_key, client_master_key) != Result::Success) {
        std::fprintf(stderr, "initiator_finish failed\n");
        return 1;
    }

    json_field("server_session_key", hex(server_session_key));
    json_field("client_session_key", hex(client_session_key));
    json_field("server_master_key", hex(server_master_key));
    json_field("client_master_key", hex(client_master_key));

    /* Verify match */
    bool keys_match = (client_session_key == server_session_key) &&
                      (client_master_key == server_master_key);

    std::printf("    \"keys_match\": %s\n", keys_match ? "true" : "false");
    std::printf("  },\n\n");

    /* ---- Wire Sizes ---- */
    std::printf("  \"wire_sizes\": {\n");
    json_field_int("registration_request", REGISTRATION_REQUEST_LENGTH);
    json_field_int("registration_response", REGISTRATION_RESPONSE_LENGTH);
    json_field_int("registration_record", REGISTRATION_RECORD_LENGTH);
    json_field_int("ke1", KE1_LENGTH);
    json_field_int("ke2", KE2_LENGTH);
    json_field_int("ke3", KE3_LENGTH);
    json_field_int("kem_public_key", pq_constants::KEM_PUBLIC_KEY_LENGTH);
    json_field_int("kem_ciphertext", pq_constants::KEM_CIPHERTEXT_LENGTH);
    json_field_int("kem_shared_secret", pq_constants::KEM_SHARED_SECRET_LENGTH);
    json_field_int("total_auth_bytes", KE1_LENGTH + KE2_LENGTH + KE3_LENGTH, true);
    std::printf("  }\n");

    std::printf("}\n");

    return 0;
}
