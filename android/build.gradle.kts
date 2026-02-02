// Top-level build file for Ecliptix OPAQUE Android library
plugins {
    id("com.android.library") version "8.2.0" apply false
    id("org.jetbrains.kotlin.android") version "1.9.21" apply false
    id("maven-publish")
}

group = "com.ecliptix.security"
version = findProperty("VERSION_NAME")?.toString() ?: "1.0.0"

tasks.register("clean", Delete::class) {
    delete(rootProject.layout.buildDirectory)
}
