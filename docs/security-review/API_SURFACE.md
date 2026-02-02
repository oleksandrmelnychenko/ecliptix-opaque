# API Surface

This file lists the public entry points exposed by headers and C interop exports.

## C API (Interop)

Client:
- int opaque_client_create(const uint8_t *server_public_key, size_t key_length, void **handle)
- void opaque_client_destroy(void *handle)
- int opaque_client_state_create(void **handle)
- void opaque_client_state_destroy(void *handle)
- int opaque_client_create_registration_request(void *client_handle, const uint8_t *secure_key, size_t secure_key_length, void *state_handle, uint8_t *request_out, size_t request_length)
- int opaque_client_finalize_registration(void *client_handle, const uint8_t *response, size_t response_length, void *state_handle, uint8_t *record_out, size_t record_length)
- int opaque_client_generate_ke1(void *client_handle, const uint8_t *secure_key, size_t secure_key_length, void *state_handle, uint8_t *ke1_out, size_t ke1_length)
- int opaque_client_generate_ke3(void *client_handle, const uint8_t *ke2, size_t ke2_length, void *state_handle, uint8_t *ke3_out, size_t ke3_length)
- int opaque_client_finish(void *client_handle, void *state_handle, uint8_t *session_key_out, size_t session_key_length, uint8_t *master_key_out, size_t master_key_length)
- int opaque_client_create_default(void **handle)
- const char *opaque_client_get_version(void)

Sizes:
- size_t opaque_get_ke1_length(void)
- size_t opaque_get_ke2_length(void)
- size_t opaque_get_ke3_length(void)
- size_t opaque_get_registration_record_length(void)
- size_t opaque_get_kem_public_key_length(void)
- size_t opaque_get_kem_ciphertext_length(void)

Server:
- int opaque_server_keypair_generate(server_keypair_handle_t **handle)
- void opaque_server_keypair_destroy(server_keypair_handle_t *handle)
- int opaque_server_keypair_get_public_key(server_keypair_handle_t *handle, uint8_t *public_key, size_t key_buffer_size)
- int opaque_server_create(server_keypair_handle_t *keypair_handle, opaque_server_handle_t **handle)
- void opaque_server_destroy(const opaque_server_handle_t *handle)
- int opaque_server_state_create(server_state_handle_t **handle)
- void opaque_server_state_destroy(const server_state_handle_t *handle)
- int opaque_server_create_registration_response(const opaque_server_handle_t *server_handle, const uint8_t *request_data, size_t request_length, const uint8_t *account_id, size_t account_id_length, uint8_t *response_data, size_t response_buffer_size)
- int opaque_server_build_credentials(const uint8_t *registration_record, size_t record_length, uint8_t *credentials_out, size_t credentials_out_length)
- int opaque_server_generate_ke2(const opaque_server_handle_t *server_handle, const uint8_t *ke1_data, size_t ke1_length, const uint8_t *account_id, size_t account_id_length, const uint8_t *credentials_data, size_t credentials_length, uint8_t *ke2_data, size_t ke2_buffer_size, const server_state_handle_t *state_handle)
- int opaque_server_finish(const opaque_server_handle_t *server_handle, const uint8_t *ke3_data, size_t ke3_length, const server_state_handle_t *state_handle, uint8_t *session_key, size_t session_key_buffer_size, uint8_t *master_key_out, size_t master_key_buffer_size)
- int opaque_server_create_default(opaque_server_handle_t **handle)
- int opaque_server_derive_keypair_from_seed(const uint8_t *seed, size_t seed_len, uint8_t *private_key, size_t private_key_buffer_len, uint8_t *public_key, size_t public_key_buffer_len)
- int opaque_server_create_with_keys(const uint8_t *private_key, size_t private_key_len, const uint8_t *public_key, size_t public_key_len, opaque_server_handle_t **handle)
- const char *opaque_server_get_version(void)
- size_t opaque_server_get_ke2_length(void)
- size_t opaque_server_get_registration_record_length(void)
- size_t opaque_server_get_credentials_length(void)
- size_t opaque_server_get_kem_ciphertext_length(void)

## C++ API

Initiator (include/opaque/initiator.h):
- class OpaqueInitiator
  - static Result create_registration_request(...)
  - Result finalize_registration(...)
  - static Result generate_ke1(...)
  - Result generate_ke3(...)
  - static Result initiator_finish(...)
- InitiatorState, RegistrationRequest, RegistrationRecord, KE1, KE3

Responder (include/opaque/responder.h):
- class OpaqueResponder
  - Result create_registration_response(...)
  - Result generate_ke2(...)
  - static Result responder_finish(...)
  - const secure_bytes &get_public_key() const
- ResponderKeyPair::generate
- build_credentials(...)
- ResponderState, RegistrationResponse, KE2

Core (include/opaque/opaque.h):
- crypto::*, envelope::*, oblivious_prf::*, protocol::parse_*, protocol::write_*
- constants in namespace ecliptix::security::opaque
