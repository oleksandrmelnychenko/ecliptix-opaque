#pragma once
#include "opaque.h"

namespace ecliptix::security::opaque::initiator {

struct RegistrationRequest {
  secure_bytes data;
  RegistrationRequest();
};

struct RegistrationRecord {
  secure_bytes envelope;
  secure_bytes initiator_public_key;
  RegistrationRecord();
};

struct KE1 {
  secure_bytes initiator_nonce;
  secure_bytes initiator_public_key;
  secure_bytes credential_request;
  KE1();
};

struct KE3 {
  secure_bytes initiator_mac;
  KE3();
};

struct InitiatorState {
  secure_bytes secure_key;
  secure_bytes initiator_private_key;
  secure_bytes initiator_public_key;
  secure_bytes initiator_ephemeral_private_key;
  secure_bytes initiator_ephemeral_public_key;
  secure_bytes responder_public_key;
  secure_bytes session_key;
  secure_bytes oblivious_prf_blind_scalar;
  secure_bytes initiator_nonce;
  secure_bytes master_key;

  InitiatorState();
  ~InitiatorState();
};

class OpaqueInitiator {
 public:
  explicit OpaqueInitiator(const ResponderPublicKey& responder_public_key);
  ~OpaqueInitiator();

  OpaqueInitiator(const OpaqueInitiator&) = delete;
  OpaqueInitiator& operator=(const OpaqueInitiator&) = delete;

  [[nodiscard]] static Result create_registration_request(
      const uint8_t* secure_key,
      size_t secure_key_length,
      RegistrationRequest& request,
      InitiatorState& state);

  [[nodiscard]] static Result finalize_registration(
      const uint8_t* registration_response,
      size_t response_length,
      InitiatorState& state,
      RegistrationRecord& record);

  [[nodiscard]] static Result generate_ke1(
      const uint8_t* secure_key,
      size_t secure_key_length,
      KE1& ke1,
      InitiatorState& state);

  [[nodiscard]] Result generate_ke3(
      const uint8_t* ke2_data,
      size_t ke2_length,
      InitiatorState& state,
      KE3& ke3) const;

  [[nodiscard]] static Result initiator_finish(
      const InitiatorState& state,
      secure_bytes& session_key);

 private:
  class Impl;
  std::unique_ptr<Impl> impl_;
};

}  // namespace ecliptix::security::opaque::initiator
