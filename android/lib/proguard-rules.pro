# ProGuard rules for Ecliptix OPAQUE library

# Keep JNI methods
-keepclasseswithmembernames class * {
    native <methods>;
}

# Keep the OpaqueNative class (JNI bridge)
-keep class com.ecliptix.security.opaque.OpaqueNative { *; }

# Keep public API classes
-keep class com.ecliptix.security.opaque.OpaqueClient { *; }
-keep class com.ecliptix.security.opaque.OpaqueClient$* { *; }
-keep class com.ecliptix.security.opaque.OpaqueException { *; }
-keep class com.ecliptix.security.opaque.OpaqueError { *; }
-keep class com.ecliptix.security.opaque.FinishResult { *; }
