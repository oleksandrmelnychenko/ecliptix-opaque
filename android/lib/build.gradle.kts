plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
    id("maven-publish")
}

android {
    namespace = "com.ecliptix.security.opaque"
    compileSdk = 34

    defaultConfig {
        minSdk = 24
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        consumerProguardFiles("consumer-rules.pro")

        ndk {
            // Supported ABIs
            abiFilters.addAll(listOf("arm64-v8a", "armeabi-v7a", "x86_64"))
        }

        externalNativeBuild {
            cmake {
                cppFlags += listOf("-std=c++23", "-fexceptions")
                arguments += listOf(
                    "-DBUILD_CLIENT=ON",
                    "-DBUILD_SERVER=OFF",
                    "-DBUILD_ANDROID_JNI=ON",
                    "-DBUILD_TESTS=OFF"
                )
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    // Use pre-built native libraries from dist/android
    sourceSets {
        getByName("main") {
            jniLibs.srcDirs("${rootProject.projectDir}/../dist/android")
        }
    }

    publishing {
        singleVariant("release") {
            withSourcesJar()
        }
    }
}

dependencies {
    implementation("androidx.core:core-ktx:1.12.0")
    implementation("androidx.annotation:annotation:1.7.1")

    testImplementation("junit:junit:4.13.2")
    androidTestImplementation("androidx.test.ext:junit:1.1.5")
    androidTestImplementation("androidx.test.espresso:espresso-core:3.5.1")
}

publishing {
    publications {
        register<MavenPublication>("release") {
            groupId = "com.ecliptix.security"
            artifactId = "opaque"
            version = findProperty("VERSION_NAME")?.toString() ?: "1.0.0"

            afterEvaluate {
                from(components["release"])
            }

            pom {
                val repoSlug = System.getenv("GITHUB_REPOSITORY") ?: "oleksandrmelnychenko/ecliptix-opaque"
                name.set("Ecliptix OPAQUE")
                description.set("OPAQUE Password-Authenticated Key Exchange with Post-Quantum Security")
                url.set("https://github.com/$repoSlug")

                licenses {
                    license {
                        name.set("MIT License")
                        url.set("https://opensource.org/licenses/MIT")
                    }
                }

                developers {
                    developer {
                        id.set("ecliptix")
                        name.set("Ecliptix")
                    }
                }

                scm {
                    connection.set("scm:git:git://github.com/$repoSlug.git")
                    developerConnection.set("scm:git:ssh://github.com:$repoSlug.git")
                    url.set("https://github.com/$repoSlug")
                }
            }
        }
    }

    repositories {
        maven {
            name = "GitHubPackages"
            url = uri("https://maven.pkg.github.com/${System.getenv("GITHUB_REPOSITORY") ?: "oleksandrmelnychenko/ecliptix-opaque"}")
            credentials {
                username = System.getenv("GITHUB_ACTOR") ?: findProperty("gpr.user")?.toString()
                password = System.getenv("GITHUB_TOKEN") ?: findProperty("gpr.key")?.toString()
            }
        }
    }
}
