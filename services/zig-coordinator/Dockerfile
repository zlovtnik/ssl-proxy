# =============================================================================
# Java Coordinator - Dockerfile
# Multi-stage build: Gradle + JDK to slim JRE runtime
# =============================================================================

# ---- Stage 1: Build with Gradle + JDK 21 ----
FROM gradle:8.12-jdk21 AS builder
WORKDIR /app
COPY services/zig-coordinator/ ./
RUN gradle build --no-daemon -x test

# ---- Stage 2: Runtime with slim JRE ----
FROM eclipse-temurin:21-jre-alpine
ENV TZ=America/New_York
ENV JAVA_TOOL_OPTIONS="-XX:+UseZGC -XX:+ZGenerational -XX:InitialRAMPercentage=50 -XX:MaxRAMPercentage=75 -Dspring.aot.enabled=true"

RUN apk add --no-cache \
        bash \
        ca-certificates \
        postgresql-client \
        tzdata

WORKDIR /app

RUN addgroup -S coordinator \
    && adduser -S -G coordinator coordinator

# Copy the built fat JAR
COPY --chown=coordinator:coordinator --from=builder /app/build/libs/*.jar /app/java-coordinator.jar

# Copy SQL schema (used by the init/healthcheck logic)
COPY --chown=coordinator:coordinator sql /app/sql
COPY --chown=coordinator:coordinator docker/redpanda /app/docker/redpanda

RUN chown coordinator:coordinator /app \
    && chmod 500 /app \
    && chmod 400 /app/java-coordinator.jar \
    && chmod -R a=rX /app/sql /app/docker/redpanda

EXPOSE 8081

HEALTHCHECK --interval=30s --timeout=10s --retries=5 --start-period=20s \
  CMD wget -qO- http://localhost:8081/actuator/health || exit 1

USER coordinator

ENTRYPOINT ["java", "-jar", "/app/java-coordinator.jar"]
