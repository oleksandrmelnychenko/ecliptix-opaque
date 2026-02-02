#pragma once
#include "opaque.h"

namespace ecliptix::security::opaque::protocol {
    struct RegistrationResponseView {
        const uint8_t *evaluated_element;
        const uint8_t *responder_public_key;
    };

    struct RegistrationRecordView {
        const uint8_t *envelope;
        const uint8_t *initiator_public_key;
    };

    struct Ke1View {
        const uint8_t *credential_request;
        const uint8_t *initiator_public_key;
        const uint8_t *initiator_nonce;
        const uint8_t *pq_ephemeral_public_key;
    };

    struct Ke2View {
        const uint8_t *responder_nonce;
        const uint8_t *responder_public_key;
        const uint8_t *credential_response;
        const uint8_t *responder_mac;
        const uint8_t *kem_ciphertext;
    };

    struct Ke3View {
        const uint8_t *initiator_mac;
    };

    constexpr inline size_t kRegistrationResponseEvaluatedOffset = 0;
    constexpr inline size_t kRegistrationResponseResponderKeyOffset = REGISTRATION_REQUEST_LENGTH;
    constexpr inline size_t kRegistrationRecordEnvelopeOffset = 0;
    constexpr inline size_t kRegistrationRecordInitiatorKeyOffset = ENVELOPE_LENGTH;

    constexpr inline size_t kKe1CredentialRequestOffset = 0;
    constexpr inline size_t kKe1InitiatorPublicKeyOffset = REGISTRATION_REQUEST_LENGTH;
    constexpr inline size_t kKe1InitiatorNonceOffset = REGISTRATION_REQUEST_LENGTH + PUBLIC_KEY_LENGTH;
    constexpr inline size_t kKe1PqPublicKeyOffset = KE1_BASE_LENGTH;

    constexpr inline size_t kKe2ResponderNonceOffset = 0;
    constexpr inline size_t kKe2ResponderPublicKeyOffset = NONCE_LENGTH;
    constexpr inline size_t kKe2CredentialResponseOffset = NONCE_LENGTH + PUBLIC_KEY_LENGTH;
    constexpr inline size_t kKe2ResponderMacOffset = NONCE_LENGTH + PUBLIC_KEY_LENGTH + CREDENTIAL_RESPONSE_LENGTH;
    constexpr inline size_t kKe2KemCiphertextOffset = KE2_BASE_LENGTH;

    [[nodiscard]] Result parse_registration_response(const uint8_t *data, size_t length,
                                                     RegistrationResponseView &view);
    [[nodiscard]] Result parse_registration_record(const uint8_t *data, size_t length,
                                                   RegistrationRecordView &view);
    [[nodiscard]] Result parse_ke1(const uint8_t *data, size_t length, Ke1View &view);
    [[nodiscard]] Result parse_ke2(const uint8_t *data, size_t length, Ke2View &view);
    [[nodiscard]] Result parse_ke3(const uint8_t *data, size_t length, Ke3View &view);

    [[nodiscard]] Result write_registration_record(const uint8_t *envelope, size_t envelope_length,
                                                   const uint8_t *initiator_public_key, size_t initiator_key_length,
                                                   uint8_t *out, size_t out_length);
    [[nodiscard]] Result write_ke1(const uint8_t *credential_request, size_t credential_request_length,
                                   const uint8_t *initiator_public_key, size_t initiator_key_length,
                                   const uint8_t *initiator_nonce, size_t initiator_nonce_length,
                                   const uint8_t *pq_ephemeral_public_key, size_t pq_public_key_length,
                                   uint8_t *out, size_t out_length);
    [[nodiscard]] Result write_ke2(const uint8_t *responder_nonce, size_t responder_nonce_length,
                                   const uint8_t *responder_public_key, size_t responder_key_length,
                                   const uint8_t *credential_response, size_t credential_response_length,
                                   const uint8_t *responder_mac, size_t responder_mac_length,
                                   const uint8_t *kem_ciphertext, size_t kem_ciphertext_length,
                                   uint8_t *out, size_t out_length);
    [[nodiscard]] Result write_ke3(const uint8_t *initiator_mac, size_t initiator_mac_length,
                                   uint8_t *out, size_t out_length);
}
