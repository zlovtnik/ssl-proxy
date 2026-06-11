plugins {
    java
    id("org.springframework.boot") version "3.4.4"
    id("io.spring.dependency-management") version "1.1.7"
    id("org.graalvm.buildtools.native") version "0.10.6"
}

group = "com.sslproxy"
version = "0.1.0"

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(21)
    }
}

repositories {
    mavenCentral()
}

val camelVersion = "4.10.2"
val postgresqlVersion = "42.7.5"
val testcontainersVersion = "1.20.6"

dependencies {
    // Spring Boot
    implementation("org.springframework.boot:spring-boot-starter")
    implementation("org.springframework.boot:spring-boot-starter-web")
    implementation("org.springframework.boot:spring-boot-starter-jdbc")
    implementation("org.springframework.boot:spring-boot-starter-actuator")
    implementation("org.springframework.boot:spring-boot-starter-validation")

    // Apache Camel
    implementation("org.apache.camel.springboot:camel-spring-boot-starter:$camelVersion")
    implementation("org.apache.camel.springboot:camel-timer-starter:$camelVersion")
    implementation("org.apache.camel.springboot:camel-kafka-starter:$camelVersion")
    implementation("org.apache.camel.springboot:camel-direct-starter:$camelVersion")
    implementation("org.apache.camel.springboot:camel-file-starter:$camelVersion")
    implementation("org.apache.camel.springboot:camel-jackson-starter:$camelVersion")
    implementation("org.apache.kafka:kafka-clients")

    // Database
    implementation("org.postgresql:postgresql:$postgresqlVersion")
    implementation("io.minio:minio:8.5.17")

    // Functional primitives
    implementation("io.vavr:vavr:0.10.4")
    implementation("org.jooq:jool:0.9.15")

    // JSON processing
    implementation("com.fasterxml.jackson.core:jackson-databind")

    // Micrometer for Prometheus metrics
    implementation("io.micrometer:micrometer-registry-prometheus")
    implementation("io.micrometer:micrometer-tracing-bridge-otel")
    implementation("io.opentelemetry:opentelemetry-exporter-otlp")

    // Configuration processor
    annotationProcessor("org.springframework.boot:spring-boot-configuration-processor")

    // Testing
    testImplementation("org.springframework.boot:spring-boot-starter-test")
    testImplementation("org.apache.camel:camel-test-spring-junit5:$camelVersion")
    testImplementation("org.testcontainers:testcontainers:$testcontainersVersion")
    testImplementation("org.testcontainers:postgresql:$testcontainersVersion")
    testImplementation("org.testcontainers:kafka:$testcontainersVersion")
    testImplementation("org.testcontainers:junit-jupiter:$testcontainersVersion")
}

tasks.withType<Test> {
    useJUnitPlatform()
}

tasks.bootBuildImage {
    builder = "paketobuildpacks/builder-jammy-tiny"
    imageName = "ssl-proxy/java-coordinator:${project.version}"
    environment.put("BP_JVM_VERSION", "21.*")
    environment.put(
        "BPE_APPEND_JAVA_TOOL_OPTIONS",
        " -XX:+UseZGC -XX:+ZGenerational -XX:InitialRAMPercentage=50 -XX:MaxRAMPercentage=75 -Dspring.aot.enabled=true"
    )
}
