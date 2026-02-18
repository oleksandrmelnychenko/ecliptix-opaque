#include "opaque/protocol.h"
#include <cstring>

namespace ecliptix::security::opaque::protocol {
    Result parse_registration_response(const uint8_t *data, const size_t length,
                                       RegistrationResponseView &view) {
        if (!data || length != REGISTRATION_RESPONSE_LENGTH) {
            return Result::InvalidInput;
        }
        view.evaluated_element = data + kRegistrationResponseEvaluatedOffset;
        view.responder_public_key = data + kRegistrationResponseResponderKeyOffset;
        return Result::Success;
    }

    Result parse_registration_record(const uint8_t *data, const size_t length,
                                     RegistrationRecordView &view) {
        if (!data || length != REGISTRATION_RECORD_LENGTH) {
            return Result::InvalidInput;
        }
        view.envelope = data + kRegistrationRecordEnvelopeOffset;
        view.initiator_public_key = data + kRegistrationRecordInitiatorKeyOffset;
        return Result::Success;
    }

    Result parse_ke1(const uint8_t *data, const size_t length, Ke1View &view) {
        if (!data || length != KE1_LENGTH) {
            return Result::InvalidInput;
        }
        view.credential_request = data + kKe1CredentialRequestOffset;
        view.initiator_public_key = data + kKe1InitiatorPublicKeyOffset;
        view.initiator_nonce = data + kKe1InitiatorNonceOffset;
        view.pq_ephemeral_public_key = data + kKe1PqPublicKeyOffset;
        return Result::Success;
    }

    Result parse_ke2(const uint8_t *data, const size_t length, Ke2View &view) {
        if (!data || length != KE2_LENGTH) {
            return Result::InvalidInput;
        }
        view.responder_nonce = data + kKe2ResponderNonceOffset;
        view.responder_public_key = data + kKe2ResponderPublicKeyOffset;
        view.credential_response = data + kKe2CredentialResponseOffset;
        view.responder_mac = data + kKe2ResponderMacOffset;
        view.kem_ciphertext = data + kKe2KemCiphertextOffset;
        return Result::Success;
    }

    Result parse_ke3(const uint8_t *data, const size_t length, Ke3View &view) {
        if (!data || length != KE3_LENGTH) {
            return Result::InvalidInput;
        }
        view.initiator_mac = data;
        return Result::Success;
    }

    Result write_registration_record(const uint8_t *envelope, const size_t envelope_length,
                                     const uint8_t *initiator_public_key, const size_t initiator_key_length,
                                     uint8_t *out, const size_t out_length) {
        if (!envelope || !initiator_public_key || !out) {
            return Result::InvalidInput;
        }
        if (envelope_length != ENVELOPE_LENGTH || initiator_key_length != PUBLIC_KEY_LENGTH) {
            return Result::InvalidInput;
        }
        if (out_length < REGISTRATION_RECORD_LENGTH) {
            return Result::InvalidInput;
        }
        std::memcpy(out + kRegistrationRecordEnvelopeOffset, envelope, ENVELOPE_LENGTH);
        std::memcpy(out + kRegistrationRecordInitiatorKeyOffset, initiator_public_key, PUBLIC_KEY_LENGTH);
        return Result::Success;
    }

    Result write_ke1(const uint8_t *credential_request, const size_t credential_request_length,
                     const uint8_t *initiator_public_key, const size_t initiator_key_length,
                     const uint8_t *initiator_nonce, const size_t initiator_nonce_length,
                     const uint8_t *pq_ephemeral_public_key, const size_t pq_public_key_length,
                     uint8_t *out, const size_t out_length) {
        if (!credential_request || !initiator_public_key || !initiator_nonce ||
            !pq_ephemeral_public_key || !out) {
            return Result::InvalidInput;
        }
        if (credential_request_length != REGISTRATION_REQUEST_LENGTH ||
            initiator_key_length != PUBLIC_KEY_LENGTH ||
            initiator_nonce_length != NONCE_LENGTH ||
            pq_public_key_length != pq_constants::KEM_PUBLIC_KEY_LENGTH) {
            return Result::InvalidInput;
        }
        if (out_length < KE1_LENGTH) {
            return Result::InvalidInput;
        }
        std::memcpy(out + kKe1CredentialRequestOffset, credential_request, REGISTRATION_REQUEST_LENGTH);
        std::memcpy(out + kKe1InitiatorPublicKeyOffset, initiator_public_key, PUBLIC_KEY_LENGTH);
        std::memcpy(out + kKe1InitiatorNonceOffset, initiator_nonce, NONCE_LENGTH);
        std::memcpy(out + kKe1PqPublicKeyOffset, pq_ephemeral_public_key, pq_constants::KEM_PUBLIC_KEY_LENGTH);
        return Result::Success;
    }

    Result write_ke2(const uint8_t *responder_nonce, const size_t responder_nonce_length,
                     const uint8_t *responder_public_key, const size_t responder_key_length,
                     const uint8_t *credential_response, const size_t credential_response_length,
                     const uint8_t *responder_mac, const size_t responder_mac_length,
                     const uint8_t *kem_ciphertext, const size_t kem_ciphertext_length,
                     uint8_t *out, const size_t out_length) {
        if (!responder_nonce || !responder_public_key || !credential_response ||
            !responder_mac || !kem_ciphertext || !out) {
            return Result::InvalidInput;
        }
        if (responder_nonce_length != NONCE_LENGTH ||
            responder_key_length != PUBLIC_KEY_LENGTH ||
            credential_response_length != CREDENTIAL_RESPONSE_LENGTH ||
            responder_mac_length != MAC_LENGTH ||
            kem_ciphertext_length != pq_constants::KEM_CIPHERTEXT_LENGTH) {
            return Result::InvalidInput;
        }
        if (out_length < KE2_LENGTH) {
            return Result::InvalidInput;
        }
        std::memcpy(out + kKe2ResponderNonceOffset, responder_nonce, NONCE_LENGTH);
        std::memcpy(out + kKe2ResponderPublicKeyOffset, responder_public_key, PUBLIC_KEY_LENGTH);
        std::memcpy(out + kKe2CredentialResponseOffset, credential_response, CREDENTIAL_RESPONSE_LENGTH);
        std::memcpy(out + kKe2ResponderMacOffset, responder_mac, MAC_LENGTH);
        std::memcpy(out + kKe2KemCiphertextOffset, kem_ciphertext, pq_constants::KEM_CIPHERTEXT_LENGTH);
        return Result::Success;
    }

    Result write_ke3(const uint8_t *initiator_mac, const size_t initiator_mac_length,
                     uint8_t *out, const size_t out_length) {
        if (!initiator_mac || !out) {
            return Result::InvalidInput;
        }
        if (initiator_mac_length != MAC_LENGTH) {
            return Result::InvalidInput;
        }
        if (out_length < KE3_LENGTH) {
            return Result::InvalidInput;
        }
        std::memcpy(out, initiator_mac, MAC_LENGTH);
        return Result::Success;
    }
}
