#pragma once
#include "opaque.h"

namespace ecliptix::security::opaque::responder {

    struct RegistrationResponse {
        secure_bytes data;

        RegistrationResponse();
    };

    struct KE2 {
        secure_bytes responder_nonce;
        secure_bytes responder_public_key;
        secure_bytes credential_response;
        secure_bytes responder_mac;
        secure_bytes kem_ciphertext;

        KE2();
    };

    struct ResponderState {
        secure_bytes responder_private_key;
        secure_bytes responder_public_key;
        secure_bytes responder_ephemeral_private_key;
        secure_bytes responder_ephemeral_public_key;
        secure_bytes initiator_public_key;
        secure_bytes session_key;
        secure_bytes expected_initiator_mac;
        secure_bytes master_key;
        bool handshake_complete;

        secure_bytes pq_shared_secret;

        ResponderState();

        ~ResponderState();
    };

    struct ResponderKeyPair {
        secure_bytes private_key;
        secure_bytes public_key;

        ResponderKeyPair();

        ~ResponderKeyPair();

        [[nodiscard]] static Result generate(ResponderKeyPair &keypair);
    };

    class OpaqueResponder {
    public:
        explicit OpaqueResponder(const ResponderKeyPair &responder_keypair);

        ~OpaqueResponder();

        OpaqueResponder(const OpaqueResponder &) = delete;

        OpaqueResponder &operator=(const OpaqueResponder &) = delete;

        [[nodiscard]] Result create_registration_response(
            const uint8_t *registration_request,
            size_t request_length,
            const uint8_t *account_id,
            size_t account_id_length,
            RegistrationResponse &response) const;

        [[nodiscard]] Result generate_ke2(
            const uint8_t *ke1_data,
            size_t ke1_length,
            const uint8_t *account_id,
            size_t account_id_length,
            const ResponderCredentials &credentials,
            KE2 &ke2,
            ResponderState &state) const;

        [[nodiscard]] static Result responder_finish(
            const uint8_t *ke3_data,
            size_t ke3_length,
            ResponderState &state,
            secure_bytes &session_key,
            secure_bytes &master_key);

        [[nodiscard]] const secure_bytes &get_public_key() const;

    private:
        class Impl;
        std::unique_ptr<Impl> impl_;
    };

    [[nodiscard]] Result create_registration_response_impl(
        const uint8_t *registration_request,
        size_t request_length,
        const secure_bytes &responder_private_key,
        const secure_bytes &responder_public_key,
        const uint8_t *account_id,
        size_t account_id_length,
        RegistrationResponse &response);

    [[nodiscard]] Result build_credentials(
        const uint8_t *registration_record,
        size_t record_length,
        ResponderCredentials &credentials);

    [[nodiscard]] Result generate_ke2_impl(
        const uint8_t *ke1_data,
        size_t ke1_length,
        const ResponderCredentials &credentials,
        const secure_bytes &responder_private_key,
        const secure_bytes &responder_public_key,
        const uint8_t *account_id,
        size_t account_id_length,
        KE2 &ke2,
        ResponderState &state);

    [[nodiscard]] Result responder_finish_impl(
        const uint8_t *ke3_data,
        size_t ke3_length,
        ResponderState &state,
        secure_bytes &session_key,
        secure_bytes &master_key);
}
