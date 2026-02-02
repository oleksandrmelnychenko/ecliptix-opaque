#include "opaque/responder.h"
#include "opaque/protocol.h"
#include "opaque/pq.h"
#include "opaque/debug_log.h"
#include <sodium.h>
#include <algorithm>

namespace ecliptix::security::opaque::responder {
    namespace {
        namespace oblivious_prf = oblivious_prf;
        namespace crypto = crypto;
    }

    RegistrationResponse::RegistrationResponse() : data(REGISTRATION_RESPONSE_LENGTH) {
    }

    Result create_registration_response_impl(const uint8_t *registration_request, const size_t request_length,
                                             const secure_bytes &responder_private_key,
                                             const secure_bytes &responder_public_key,
                                             const uint8_t *account_id,
                                             const size_t account_id_length,
                                             RegistrationResponse &response) {
        log::section("RELAY: Create Registration Response");
        if (!registration_request || request_length != REGISTRATION_REQUEST_LENGTH ||
            !account_id || account_id_length == 0) [[unlikely]] {
            return Result::InvalidInput;
        }
        if (!crypto::init()) {
            return Result::CryptoError;
        }
        log::hex("registration_request (blinded element)", registration_request, request_length);
        log::hex("responder_private_key", responder_private_key);
        log::hex("responder_public_key", responder_public_key);
        log::hex("account_id", account_id, account_id_length);

        const uint8_t *blinded_element = registration_request;
        if (Result point_result = crypto::validate_ristretto_point(blinded_element, REGISTRATION_REQUEST_LENGTH);
            point_result != Result::Success) {
            return Result::InvalidInput;
        }
        uint8_t evaluated_element[crypto_core_ristretto255_BYTES];
        uint8_t oprf_key[PRIVATE_KEY_LENGTH] = {};
        Result result = crypto::derive_oprf_key(responder_private_key.data(), responder_private_key.size(),
                                                account_id, account_id_length, oprf_key);
        if (result != Result::Success) [[unlikely]] {
            sodium_memzero(oprf_key, sizeof(oprf_key));
            return result;
        }
        log::hex("oprf_key (derived from responder_private_key + account_id)", oprf_key, sizeof(oprf_key));
        result = oblivious_prf::evaluate(blinded_element, oprf_key, evaluated_element);
        sodium_memzero(oprf_key, sizeof(oprf_key));
        if (result != Result::Success) [[unlikely]] {
            return result;
        }
        log::hex("evaluated_element (OPRF output)", evaluated_element, sizeof(evaluated_element));

        size_t offset = 0;
        std::copy_n(evaluated_element, crypto_core_ristretto255_BYTES,
                    response.data.begin() + static_cast<std::ptrdiff_t>(offset));
        offset += crypto_core_ristretto255_BYTES;
        std::ranges::copy(responder_public_key,
                          response.data.begin() + static_cast<std::ptrdiff_t>(offset));
        log::hex("registration_response", response.data);
        return Result::Success;
    }

    Result build_credentials(const uint8_t *registration_record, size_t record_length,
                             ResponderCredentials &credentials) {
        log::section("RELAY: Build Credentials from Registration Record");
        const size_t record_expected = REGISTRATION_RECORD_LENGTH;
        if (!registration_record || record_length < record_expected) {
            return Result::InvalidInput;
        }
        if (!crypto::init()) {
            return Result::CryptoError;
        }
        log::hex("registration_record", registration_record, record_length);
        protocol::RegistrationRecordView record_view{};
        Result parse_result = protocol::parse_registration_record(registration_record, record_length, record_view);
        if (parse_result != Result::Success) {
            return parse_result;
        }
        if (Result key_result = crypto::validate_public_key(record_view.initiator_public_key, PUBLIC_KEY_LENGTH);
            key_result != Result::Success) {
            return key_result;
        }

        credentials.envelope.assign(record_view.envelope, record_view.envelope + ENVELOPE_LENGTH);
        credentials.initiator_public_key.assign(record_view.initiator_public_key,
                                                record_view.initiator_public_key + PUBLIC_KEY_LENGTH);
        log::hex("credentials.envelope", credentials.envelope);
        log::hex("credentials.initiator_public_key (EC)", credentials.initiator_public_key);
        return Result::Success;
    }
}
