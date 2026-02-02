# Consumer ProGuard rules for Ecliptix OPAQUE

# Keep JNI native methods
-keepclasseswithmembernames class * {
    native <methods>;
}

# Keep all classes in our package that might be accessed via reflection
-keep class com.ecliptix.security.opaque.** { *; }
