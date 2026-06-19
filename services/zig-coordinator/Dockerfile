# =============================================================================
# Java Coordinator - Dockerfile
# Multi-stage build: Gradle + JDK to slim JRE runtime
# =============================================================================

# ---- Stage 1: Build with Gradle + Azul Zulu JDK 21 ----
FROM azul/zulu-openjdk-alpine:21 AS builder

# Install Gradle
ARG GRADLE_VERSION=9.3.1
RUN apk add --no-cache curl unzip \
    && curl -fsSL "https://services.gradle.org/distributions/gradle-${GRADLE_VERSION}-bin.zip" \
      -o /tmp/gradle.zip \
    && unzip -d /opt /tmp/gradle.zip \
    && ln -s /opt/gradle-${GRADLE_VERSION}/bin/gradle /usr/local/bin/gradle \
    && rm /tmp/gradle.zip

WORKDIR /app
COPY services/zig-coordinator/ ./
RUN gradle build --no-daemon -x test

# ---- Stage 2: Runtime with Azul Zulu JRE 21 (Alpine) ----
FROM azul/zulu-openjdk-alpine:21-jre
ENV TZ=America/New_York
ENV JAVA_TOOL_OPTIONS="-XX:+UseZGC -XX:InitialRAMPercentage=50 -XX:MaxRAMPercentage=75"
ENV TNS_ADMIN="/app/wallet" \
    ORACLE_CONN="mainerc_high" \
    ORACLE_USER="USCIS_APP" \
    ORACLE_PASS_FILE="/run/secrets/oracle_password.txt"

RUN apk add --no-cache \
        bash \
        ca-certificates \
        tzdata

WORKDIR /app

RUN addgroup -S coordinator \
    && adduser -S -G coordinator coordinator

# Copy the built fat JAR
COPY --chown=coordinator:coordinator --from=builder /app/build/libs/*.jar /app/java-coordinator.jar

COPY --chown=coordinator:coordinator docker/redpanda /app/docker/redpanda

RUN mkdir -p /app/wallet \
    && chown coordinator:coordinator /app /app/wallet \
    && chmod 500 /app \
    && chmod 400 /app/java-coordinator.jar \
    && chmod -R a=rX /app/docker/redpanda \
    && chmod 500 /app/wallet

EXPOSE 8081

HEALTHCHECK --interval=30s --timeout=10s --retries=5 --start-period=20s \
  CMD wget -qO- http://localhost:8081/actuator/health || exit 1

USER coordinator

ENTRYPOINT ["java", "-jar", "/app/java-coordinator.jar"]
