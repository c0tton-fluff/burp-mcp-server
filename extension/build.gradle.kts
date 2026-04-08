plugins {
    kotlin("jvm") version "1.9.22"
    kotlin("plugin.serialization") version "1.9.22"
    id("com.gradleup.shadow") version "8.3.5"
}

group = "com.burpbridge"
version = System.getenv("BRIDGE_VERSION") ?: "1.0.0"

repositories {
    mavenCentral()
}

dependencies {
    // Burp Montoya API -- provided at runtime by Burp
    compileOnly("net.portswigger.burp.extensions:montoya-api:2025.5")

    // Embedded HTTP server
    implementation("io.ktor:ktor-server-netty:2.3.12")
    implementation("io.ktor:ktor-server-content-negotiation:2.3.12")
    implementation("io.ktor:ktor-serialization-kotlinx-json:2.3.12")

    // JSON serialization
    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.6.3")

    // Logging (Ktor needs SLF4J)
    implementation("org.slf4j:slf4j-simple:2.0.16")

    // Testing
    testImplementation(kotlin("test"))
    testImplementation("net.portswigger.burp.extensions:montoya-api:2025.5")
}

tasks.test {
    useJUnitPlatform()
}

kotlin {
    jvmToolchain(17)
}

tasks.shadowJar {
    archiveBaseName.set("burp-bridge")
    archiveClassifier.set("")
    archiveVersion.set(version.toString())

    // Don't bundle Montoya API -- Burp provides it
    dependencies {
        exclude(dependency("net.portswigger.burp.extensions:montoya-api"))
    }

    mergeServiceFiles()
}
