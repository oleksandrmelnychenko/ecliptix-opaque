#include <jni.h>
#include <cstdint>
#include <cstring>
#include <memory>

namespace {
    constexpr size_t PUBLIC_KEY_LENGTH = 32;
    constexpr size_t HASH_LENGTH = 64;
    constexpr size_t MASTER_KEY_LENGTH = 32;
    constexpr size_t REGISTRATION_REQUEST_LENGTH = 32;
    constexpr size_t REGISTRATION_RESPONSE_LENGTH = 64;
    constexpr size_t REGISTRATION_RECORD_LENGTH = 168;
    constexpr size_t KE1_LENGTH = 1272;
    constexpr size_t KE2_LENGTH = 1376;
    constexpr size_t KE3_LENGTH = 64;
}

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

    int sodium_init(void);
}

#define JNI_FUNC(name) Java_com_ecliptix_security_opaque_OpaqueNative_##name

namespace {
    void throwOpaqueException(JNIEnv *env, const char *message, int errorCode) {
        jclass exceptionClass = env->FindClass("com/ecliptix/security/opaque/OpaqueException");
        if (exceptionClass != nullptr) {
            jmethodID constructor = env->GetMethodID(exceptionClass, "<init>", "(Ljava/lang/String;I)V");
            if (constructor != nullptr) {
                jstring jMessage = env->NewStringUTF(message);
                jthrowable exception = static_cast<jthrowable>(env->NewObject(exceptionClass, constructor, jMessage, errorCode));
                env->Throw(exception);
                env->DeleteLocalRef(jMessage);
            } else {
                env->ThrowNew(exceptionClass, message);
            }
        } else {
            jclass runtimeException = env->FindClass("java/lang/RuntimeException");
            env->ThrowNew(runtimeException, message);
        }
    }

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

JNIEXPORT jboolean JNICALL
JNI_FUNC(nativeInit)(JNIEnv *, jclass) {
    return sodium_init() >= 0 ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jstring JNICALL
JNI_FUNC(nativeGetVersion)(JNIEnv *env, jclass) {
    const char *version = opaque_client_get_version();
    return env->NewStringUTF(version);
}

JNIEXPORT jlong JNICALL
JNI_FUNC(nativeClientCreate)(JNIEnv *env, jclass, jbyteArray serverPublicKey) {
    if (serverPublicKey == nullptr) {
        throwOpaqueException(env, "Server public key cannot be null", -1);
        return 0;
    }

    jsize keyLength = 0;
    auto keyData = byteArrayToNative(env, serverPublicKey, keyLength);

    if (static_cast<size_t>(keyLength) != PUBLIC_KEY_LENGTH) {
        throwOpaqueException(env, "Invalid server public key length", -1);
        return 0;
    }

    void *handle = nullptr;
    int result = opaque_client_create(keyData.get(), static_cast<size_t>(keyLength), &handle);

    if (result != 0) {
        throwOpaqueException(env, "Failed to create OPAQUE client", result);
        return 0;
    }

    return reinterpret_cast<jlong>(handle);
}

JNIEXPORT void JNICALL
JNI_FUNC(nativeClientDestroy)(JNIEnv *, jclass, jlong handle) {
    if (handle != 0) {
        opaque_client_destroy(reinterpret_cast<void*>(handle));
    }
}

JNIEXPORT jlong JNICALL
JNI_FUNC(nativeStateCreate)(JNIEnv *env, jclass) {
    void *handle = nullptr;
    int result = opaque_client_state_create(&handle);

    if (result != 0) {
        throwOpaqueException(env, "Failed to create client state", result);
        return 0;
    }

    return reinterpret_cast<jlong>(handle);
}

JNIEXPORT void JNICALL
JNI_FUNC(nativeStateDestroy)(JNIEnv *, jclass, jlong handle) {
    if (handle != 0) {
        opaque_client_state_destroy(reinterpret_cast<void*>(handle));
    }
}

JNIEXPORT jbyteArray JNICALL
JNI_FUNC(nativeCreateRegistrationRequest)(JNIEnv *env, jclass,
                                           jlong clientHandle, jbyteArray secureKey, jlong stateHandle) {
    if (clientHandle == 0 || stateHandle == 0) {
        throwOpaqueException(env, "Invalid handle", -1);
        return nullptr;
    }

    if (secureKey == nullptr) {
        throwOpaqueException(env, "Secure key cannot be null", -1);
        return nullptr;
    }

    jsize keyLength = 0;
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

    if (result != 0) {
        throwOpaqueException(env, "Failed to create registration request", result);
        return nullptr;
    }

    return nativeToByteArray(env, requestBuffer.get(), REGISTRATION_REQUEST_LENGTH);
}

JNIEXPORT jbyteArray JNICALL
JNI_FUNC(nativeFinalizeRegistration)(JNIEnv *env, jclass,
                                      jlong clientHandle, jbyteArray response, jlong stateHandle) {
    if (clientHandle == 0 || stateHandle == 0) {
        throwOpaqueException(env, "Invalid handle", -1);
        return nullptr;
    }

    if (response == nullptr) {
        throwOpaqueException(env, "Response cannot be null", -1);
        return nullptr;
    }

    jsize responseLength = 0;
    auto responseData = byteArrayToNative(env, response, responseLength);

    if (static_cast<size_t>(responseLength) != REGISTRATION_RESPONSE_LENGTH) {
        throwOpaqueException(env, "Invalid registration response length", -1);
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

    if (result != 0) {
        throwOpaqueException(env, "Failed to finalize registration", result);
        return nullptr;
    }

    return nativeToByteArray(env, recordBuffer.get(), REGISTRATION_RECORD_LENGTH);
}

JNIEXPORT jbyteArray JNICALL
JNI_FUNC(nativeGenerateKe1)(JNIEnv *env, jclass,
                            jlong clientHandle, jbyteArray secureKey, jlong stateHandle) {
    if (clientHandle == 0 || stateHandle == 0) {
        throwOpaqueException(env, "Invalid handle", -1);
        return nullptr;
    }

    if (secureKey == nullptr) {
        throwOpaqueException(env, "Secure key cannot be null", -1);
        return nullptr;
    }

    jsize keyLength = 0;
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

    if (result != 0) {
        throwOpaqueException(env, "Failed to generate KE1", result);
        return nullptr;
    }

    return nativeToByteArray(env, ke1Buffer.get(), KE1_LENGTH);
}

JNIEXPORT jbyteArray JNICALL
JNI_FUNC(nativeGenerateKe3)(JNIEnv *env, jclass,
                            jlong clientHandle, jbyteArray ke2, jlong stateHandle) {
    if (clientHandle == 0 || stateHandle == 0) {
        throwOpaqueException(env, "Invalid handle", -1);
        return nullptr;
    }

    if (ke2 == nullptr) {
        throwOpaqueException(env, "KE2 cannot be null", -1);
        return nullptr;
    }

    jsize ke2Length = 0;
    auto ke2Data = byteArrayToNative(env, ke2, ke2Length);

    if (static_cast<size_t>(ke2Length) != KE2_LENGTH) {
        throwOpaqueException(env, "Invalid KE2 length", -1);
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

    if (result != 0) {
        throwOpaqueException(env, "Failed to generate KE3", result);
        return nullptr;
    }

    return nativeToByteArray(env, ke3Buffer.get(), KE3_LENGTH);
}

JNIEXPORT jobject JNICALL
JNI_FUNC(nativeFinish)(JNIEnv *env, jclass, jlong clientHandle, jlong stateHandle) {
    if (clientHandle == 0 || stateHandle == 0) {
        throwOpaqueException(env, "Invalid handle", -1);
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

    if (result != 0) {
        throwOpaqueException(env, "Failed to finish authentication", result);
        return nullptr;
    }

    jclass resultClass = env->FindClass("com/ecliptix/security/opaque/FinishResult");
    if (resultClass == nullptr) {
        throwOpaqueException(env, "FinishResult class not found", -3);
        return nullptr;
    }

    jmethodID constructor = env->GetMethodID(resultClass, "<init>", "([B[B)V");
    if (constructor == nullptr) {
        throwOpaqueException(env, "FinishResult constructor not found", -3);
        return nullptr;
    }

    jbyteArray sessionKeyArray = nativeToByteArray(env, sessionKeyBuffer.get(), HASH_LENGTH);
    jbyteArray masterKeyArray = nativeToByteArray(env, masterKeyBuffer.get(), MASTER_KEY_LENGTH);

    return env->NewObject(resultClass, constructor, sessionKeyArray, masterKeyArray);
}

JNIEXPORT jint JNICALL
JNI_FUNC(nativeGetKe1Length)(JNIEnv *, jclass) {
    return static_cast<jint>(opaque_get_ke1_length());
}

JNIEXPORT jint JNICALL
JNI_FUNC(nativeGetKe2Length)(JNIEnv *, jclass) {
    return static_cast<jint>(opaque_get_ke2_length());
}

JNIEXPORT jint JNICALL
JNI_FUNC(nativeGetKe3Length)(JNIEnv *, jclass) {
    return static_cast<jint>(opaque_get_ke3_length());
}

JNIEXPORT jint JNICALL
JNI_FUNC(nativeGetRegistrationRecordLength)(JNIEnv *, jclass) {
    return static_cast<jint>(opaque_get_registration_record_length());
}

JNIEXPORT jint JNICALL
JNI_FUNC(nativeGetPublicKeyLength)(JNIEnv *, jclass) {
    return static_cast<jint>(PUBLIC_KEY_LENGTH);
}

JNIEXPORT jint JNICALL
JNI_FUNC(nativeGetRegistrationRequestLength)(JNIEnv *, jclass) {
    return static_cast<jint>(REGISTRATION_REQUEST_LENGTH);
}

JNIEXPORT jint JNICALL
JNI_FUNC(nativeGetRegistrationResponseLength)(JNIEnv *, jclass) {
    return static_cast<jint>(REGISTRATION_RESPONSE_LENGTH);
}

JNIEXPORT jint JNICALL
JNI_FUNC(nativeGetSessionKeyLength)(JNIEnv *, jclass) {
    return static_cast<jint>(HASH_LENGTH);
}

JNIEXPORT jint JNICALL
JNI_FUNC(nativeGetMasterKeyLength)(JNIEnv *, jclass) {
    return static_cast<jint>(MASTER_KEY_LENGTH);
}

}
