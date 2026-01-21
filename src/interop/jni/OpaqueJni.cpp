/**
 * JNI Bindings for Ecliptix OPAQUE Client Library
 *
 * This file provides Java/Kotlin interoperability for the OPAQUE protocol
 * client implementation (Agent). It wraps the C exports with JNI functions.
 *
 * Package: com.ecliptix.security.opaque
 */

#include <jni.h>
#include <cstdint>
#include <cstring>
#include <memory>
#include <stdexcept>
#include "opaque/opaque.h"
#include "opaque/export.h"

using namespace ecliptix::security::opaque;

// External C functions from initiator_exports.cpp
extern "C" {
    int opaque_client_create(const uint8_t *server_public_key, size_t key_length, void **handle);
    void opaque_client_destroy(void *handle);
    int opaque_client_state_create(void **handle);
    void opaque_client_state_destroy(void *handle);
    int opaque_client_create_registration_request(void *client_handle, const uint8_t *secure_key,
                                                   size_t secure_key_length, void *state_handle,
                                                   uint8_t *request_out, size_t request_length);
    int opaque_client_finalize_registration(void *client_handle, const uint8_t *response,
                                            size_t response_length, void *state_handle,
                                            uint8_t *record_out, size_t record_length);
    int opaque_client_generate_ke1(void *client_handle, const uint8_t *secure_key,
                                    size_t secure_key_length, void *state_handle,
                                    uint8_t *ke1_out, size_t ke1_length);
    int opaque_client_generate_ke3(void *client_handle, const uint8_t *ke2, size_t ke2_length,
                                    void *state_handle, uint8_t *ke3_out, size_t ke3_length);
    int opaque_client_finish(void *client_handle, void *state_handle, uint8_t *session_key_out,
                              size_t session_key_length, uint8_t *master_key_out, size_t master_key_length);
    const char *opaque_client_get_version();
    size_t opaque_get_ke1_length();
    size_t opaque_get_ke2_length();
    size_t opaque_get_ke3_length();
    size_t opaque_get_registration_record_length();
    size_t opaque_get_kem_public_key_length();
    size_t opaque_get_kem_ciphertext_length();
}

// JNI package name mangling
#define JNI_PACKAGE com_ecliptix_security_opaque
#define JNI_CLASS OpaqueNative

// JNI function name macro
#define JNI_FUNC(name) Java_com_ecliptix_security_opaque_OpaqueNative_##name

namespace {
    // Helper to throw Java exception
    void throwOpaqueException(JNIEnv *env, const char *message, int errorCode) {
        jclass exceptionClass = env->FindClass("com/ecliptix/security/opaque/OpaqueException");
        if (exceptionClass != nullptr) {
            // Find constructor that takes message and error code
            jmethodID constructor = env->GetMethodID(exceptionClass, "<init>", "(Ljava/lang/String;I)V");
            if (constructor != nullptr) {
                jstring jMessage = env->NewStringUTF(message);
                jthrowable exception = (jthrowable)env->NewObject(exceptionClass, constructor, jMessage, errorCode);
                env->Throw(exception);
                env->DeleteLocalRef(jMessage);
            } else {
                // Fallback to standard exception
                env->ThrowNew(exceptionClass, message);
            }
        } else {
            // Fallback to RuntimeException
            jclass runtimeException = env->FindClass("java/lang/RuntimeException");
            env->ThrowNew(runtimeException, message);
        }
    }

    // Helper to convert byte array to native
    std::unique_ptr<uint8_t[]> byteArrayToNative(JNIEnv *env, jbyteArray array, jsize &length) {
        if (array == nullptr) {
            length = 0;
            return nullptr;
        }
        length = env->GetArrayLength(array);
        auto buffer = std::make_unique<uint8_t[]>(static_cast<size_t>(length));
        env->GetByteArrayRegion(array, 0, length, reinterpret_cast<jbyte*>(buffer.get()));
        return buffer;
    }

    // Helper to convert native to byte array
    jbyteArray nativeToByteArray(JNIEnv *env, const uint8_t *data, size_t length) {
        jbyteArray result = env->NewByteArray(static_cast<jsize>(length));
        if (result != nullptr) {
            env->SetByteArrayRegion(result, 0, static_cast<jsize>(length),
                                    reinterpret_cast<const jbyte*>(data));
        }
        return result;
    }
}

extern "C" {

/**
 * Initialize the cryptographic library
 * Must be called before any other operations
 */
JNIEXPORT jboolean JNICALL
JNI_FUNC(nativeInit)(JNIEnv *env, jclass clazz) {
    return crypto::init() ? JNI_TRUE : JNI_FALSE;
}

/**
 * Get the library version string
 */
JNIEXPORT jstring JNICALL
JNI_FUNC(nativeGetVersion)(JNIEnv *env, jclass clazz) {
    const char *version = opaque_client_get_version();
    return env->NewStringUTF(version);
}

/**
 * Create an OPAQUE client handle
 * @param serverPublicKey The server's public key (32 bytes)
 * @return Native handle pointer as long, 0 on error
 */
JNIEXPORT jlong JNICALL
JNI_FUNC(nativeClientCreate)(JNIEnv *env, jclass clazz, jbyteArray serverPublicKey) {
    if (serverPublicKey == nullptr) {
        throwOpaqueException(env, "Server public key cannot be null", static_cast<int>(Result::InvalidInput));
        return 0;
    }

    jsize keyLength;
    auto keyData = byteArrayToNative(env, serverPublicKey, keyLength);

    if (static_cast<size_t>(keyLength) != PUBLIC_KEY_LENGTH) {
        throwOpaqueException(env, "Invalid server public key length", static_cast<int>(Result::InvalidInput));
        return 0;
    }

    void *handle = nullptr;
    int result = opaque_client_create(keyData.get(), static_cast<size_t>(keyLength), &handle);

    if (result != static_cast<int>(Result::Success)) {
        throwOpaqueException(env, "Failed to create OPAQUE client", result);
        return 0;
    }

    return reinterpret_cast<jlong>(handle);
}

/**
 * Destroy an OPAQUE client handle
 */
JNIEXPORT void JNICALL
JNI_FUNC(nativeClientDestroy)(JNIEnv *env, jclass clazz, jlong handle) {
    if (handle != 0) {
        opaque_client_destroy(reinterpret_cast<void*>(handle));
    }
}

/**
 * Create a client state handle for session management
 * @return Native handle pointer as long, 0 on error
 */
JNIEXPORT jlong JNICALL
JNI_FUNC(nativeStateCreate)(JNIEnv *env, jclass clazz) {
    void *handle = nullptr;
    int result = opaque_client_state_create(&handle);

    if (result != static_cast<int>(Result::Success)) {
        throwOpaqueException(env, "Failed to create client state", result);
        return 0;
    }

    return reinterpret_cast<jlong>(handle);
}

/**
 * Destroy a client state handle
 */
JNIEXPORT void JNICALL
JNI_FUNC(nativeStateDestroy)(JNIEnv *env, jclass clazz, jlong handle) {
    if (handle != 0) {
        opaque_client_state_destroy(reinterpret_cast<void*>(handle));
    }
}

/**
 * Create a registration request
 * @param clientHandle Native client handle
 * @param secureKey The user's password/secure key
 * @param stateHandle Native state handle
 * @return Registration request bytes
 */
JNIEXPORT jbyteArray JNICALL
JNI_FUNC(nativeCreateRegistrationRequest)(JNIEnv *env, jclass clazz,
                                           jlong clientHandle, jbyteArray secureKey, jlong stateHandle) {
    if (clientHandle == 0 || stateHandle == 0) {
        throwOpaqueException(env, "Invalid handle", static_cast<int>(Result::InvalidInput));
        return nullptr;
    }

    if (secureKey == nullptr) {
        throwOpaqueException(env, "Secure key cannot be null", static_cast<int>(Result::InvalidInput));
        return nullptr;
    }

    jsize keyLength;
    auto keyData = byteArrayToNative(env, secureKey, keyLength);

    auto requestBuffer = std::make_unique<uint8_t[]>(REGISTRATION_REQUEST_LENGTH);

    int result = opaque_client_create_registration_request(
        reinterpret_cast<void*>(clientHandle),
        keyData.get(),
        static_cast<size_t>(keyLength),
        reinterpret_cast<void*>(stateHandle),
        requestBuffer.get(),
        REGISTRATION_REQUEST_LENGTH
    );

    if (result != static_cast<int>(Result::Success)) {
        throwOpaqueException(env, "Failed to create registration request", result);
        return nullptr;
    }

    return nativeToByteArray(env, requestBuffer.get(), REGISTRATION_REQUEST_LENGTH);
}

/**
 * Finalize registration with server response
 * @param clientHandle Native client handle
 * @param response Server's registration response
 * @param stateHandle Native state handle
 * @return Registration record bytes to send to server
 */
JNIEXPORT jbyteArray JNICALL
JNI_FUNC(nativeFinalizeRegistration)(JNIEnv *env, jclass clazz,
                                      jlong clientHandle, jbyteArray response, jlong stateHandle) {
    if (clientHandle == 0 || stateHandle == 0) {
        throwOpaqueException(env, "Invalid handle", static_cast<int>(Result::InvalidInput));
        return nullptr;
    }

    if (response == nullptr) {
        throwOpaqueException(env, "Response cannot be null", static_cast<int>(Result::InvalidInput));
        return nullptr;
    }

    jsize responseLength;
    auto responseData = byteArrayToNative(env, response, responseLength);

    if (static_cast<size_t>(responseLength) != REGISTRATION_RESPONSE_LENGTH) {
        throwOpaqueException(env, "Invalid registration response length", static_cast<int>(Result::InvalidInput));
        return nullptr;
    }

    auto recordBuffer = std::make_unique<uint8_t[]>(REGISTRATION_RECORD_LENGTH);

    int result = opaque_client_finalize_registration(
        reinterpret_cast<void*>(clientHandle),
        responseData.get(),
        static_cast<size_t>(responseLength),
        reinterpret_cast<void*>(stateHandle),
        recordBuffer.get(),
        REGISTRATION_RECORD_LENGTH
    );

    if (result != static_cast<int>(Result::Success)) {
        throwOpaqueException(env, "Failed to finalize registration", result);
        return nullptr;
    }

    return nativeToByteArray(env, recordBuffer.get(), REGISTRATION_RECORD_LENGTH);
}

/**
 * Generate KE1 message for authentication
 * @param clientHandle Native client handle
 * @param secureKey The user's password/secure key
 * @param stateHandle Native state handle
 * @return KE1 message bytes
 */
JNIEXPORT jbyteArray JNICALL
JNI_FUNC(nativeGenerateKe1)(JNIEnv *env, jclass clazz,
                            jlong clientHandle, jbyteArray secureKey, jlong stateHandle) {
    if (clientHandle == 0 || stateHandle == 0) {
        throwOpaqueException(env, "Invalid handle", static_cast<int>(Result::InvalidInput));
        return nullptr;
    }

    if (secureKey == nullptr) {
        throwOpaqueException(env, "Secure key cannot be null", static_cast<int>(Result::InvalidInput));
        return nullptr;
    }

    jsize keyLength;
    auto keyData = byteArrayToNative(env, secureKey, keyLength);

    auto ke1Buffer = std::make_unique<uint8_t[]>(KE1_LENGTH);

    int result = opaque_client_generate_ke1(
        reinterpret_cast<void*>(clientHandle),
        keyData.get(),
        static_cast<size_t>(keyLength),
        reinterpret_cast<void*>(stateHandle),
        ke1Buffer.get(),
        KE1_LENGTH
    );

    if (result != static_cast<int>(Result::Success)) {
        throwOpaqueException(env, "Failed to generate KE1", result);
        return nullptr;
    }

    return nativeToByteArray(env, ke1Buffer.get(), KE1_LENGTH);
}

/**
 * Generate KE3 message from server's KE2
 * @param clientHandle Native client handle
 * @param ke2 Server's KE2 message
 * @param stateHandle Native state handle
 * @return KE3 message bytes
 */
JNIEXPORT jbyteArray JNICALL
JNI_FUNC(nativeGenerateKe3)(JNIEnv *env, jclass clazz,
                            jlong clientHandle, jbyteArray ke2, jlong stateHandle) {
    if (clientHandle == 0 || stateHandle == 0) {
        throwOpaqueException(env, "Invalid handle", static_cast<int>(Result::InvalidInput));
        return nullptr;
    }

    if (ke2 == nullptr) {
        throwOpaqueException(env, "KE2 cannot be null", static_cast<int>(Result::InvalidInput));
        return nullptr;
    }

    jsize ke2Length;
    auto ke2Data = byteArrayToNative(env, ke2, ke2Length);

    if (static_cast<size_t>(ke2Length) != KE2_LENGTH) {
        throwOpaqueException(env, "Invalid KE2 length", static_cast<int>(Result::InvalidInput));
        return nullptr;
    }

    auto ke3Buffer = std::make_unique<uint8_t[]>(KE3_LENGTH);

    int result = opaque_client_generate_ke3(
        reinterpret_cast<void*>(clientHandle),
        ke2Data.get(),
        static_cast<size_t>(ke2Length),
        reinterpret_cast<void*>(stateHandle),
        ke3Buffer.get(),
        KE3_LENGTH
    );

    if (result != static_cast<int>(Result::Success)) {
        throwOpaqueException(env, "Failed to generate KE3", result);
        return nullptr;
    }

    return nativeToByteArray(env, ke3Buffer.get(), KE3_LENGTH);
}

/**
 * Result class for finish operation containing session and master keys
 */
JNIEXPORT jobject JNICALL
JNI_FUNC(nativeFinish)(JNIEnv *env, jclass clazz, jlong clientHandle, jlong stateHandle) {
    if (clientHandle == 0 || stateHandle == 0) {
        throwOpaqueException(env, "Invalid handle", static_cast<int>(Result::InvalidInput));
        return nullptr;
    }

    auto sessionKeyBuffer = std::make_unique<uint8_t[]>(HASH_LENGTH);
    auto masterKeyBuffer = std::make_unique<uint8_t[]>(MASTER_KEY_LENGTH);

    int result = opaque_client_finish(
        reinterpret_cast<void*>(clientHandle),
        reinterpret_cast<void*>(stateHandle),
        sessionKeyBuffer.get(),
        HASH_LENGTH,
        masterKeyBuffer.get(),
        MASTER_KEY_LENGTH
    );

    if (result != static_cast<int>(Result::Success)) {
        throwOpaqueException(env, "Failed to finish authentication", result);
        return nullptr;
    }

    // Create FinishResult object
    jclass resultClass = env->FindClass("com/ecliptix/security/opaque/FinishResult");
    if (resultClass == nullptr) {
        throwOpaqueException(env, "FinishResult class not found", static_cast<int>(Result::MemoryError));
        return nullptr;
    }

    jmethodID constructor = env->GetMethodID(resultClass, "<init>", "([B[B)V");
    if (constructor == nullptr) {
        throwOpaqueException(env, "FinishResult constructor not found", static_cast<int>(Result::MemoryError));
        return nullptr;
    }

    jbyteArray sessionKeyArray = nativeToByteArray(env, sessionKeyBuffer.get(), HASH_LENGTH);
    jbyteArray masterKeyArray = nativeToByteArray(env, masterKeyBuffer.get(), MASTER_KEY_LENGTH);

    return env->NewObject(resultClass, constructor, sessionKeyArray, masterKeyArray);
}

/**
 * Get protocol constant lengths
 */
JNIEXPORT jint JNICALL
JNI_FUNC(nativeGetKe1Length)(JNIEnv *env, jclass clazz) {
    return static_cast<jint>(opaque_get_ke1_length());
}

JNIEXPORT jint JNICALL
JNI_FUNC(nativeGetKe2Length)(JNIEnv *env, jclass clazz) {
    return static_cast<jint>(opaque_get_ke2_length());
}

JNIEXPORT jint JNICALL
JNI_FUNC(nativeGetKe3Length)(JNIEnv *env, jclass clazz) {
    return static_cast<jint>(opaque_get_ke3_length());
}

JNIEXPORT jint JNICALL
JNI_FUNC(nativeGetRegistrationRecordLength)(JNIEnv *env, jclass clazz) {
    return static_cast<jint>(opaque_get_registration_record_length());
}

JNIEXPORT jint JNICALL
JNI_FUNC(nativeGetPublicKeyLength)(JNIEnv *env, jclass clazz) {
    return static_cast<jint>(PUBLIC_KEY_LENGTH);
}

JNIEXPORT jint JNICALL
JNI_FUNC(nativeGetRegistrationRequestLength)(JNIEnv *env, jclass clazz) {
    return static_cast<jint>(REGISTRATION_REQUEST_LENGTH);
}

JNIEXPORT jint JNICALL
JNI_FUNC(nativeGetRegistrationResponseLength)(JNIEnv *env, jclass clazz) {
    return static_cast<jint>(REGISTRATION_RESPONSE_LENGTH);
}

JNIEXPORT jint JNICALL
JNI_FUNC(nativeGetSessionKeyLength)(JNIEnv *env, jclass clazz) {
    return static_cast<jint>(HASH_LENGTH);
}

JNIEXPORT jint JNICALL
JNI_FUNC(nativeGetMasterKeyLength)(JNIEnv *env, jclass clazz) {
    return static_cast<jint>(MASTER_KEY_LENGTH);
}

} // extern "C"
