# =============================================================================
# Java Coordinator — Dockerfile
# Multi-stage build: Gradle + JDK → slim JRE runtime
# =============================================================================

# ---- Stage 1: Build with Gradle + JDK 21 ----
FROM gradle:8.12-jdk21 AS builder
WORKDIR /app
COPY services/zig-coordinator/ ./
RUN gradle build --no-daemon -x test

# ---- Stage 2: Runtime with slim JRE ----
FROM eclipse-temurin:21-jre-alpine
ENV TZ=America/New_York

RUN apk add --no-cache \
        bash \
        ca-certificates \
        postgresql-client \
        tzdata

WORKDIR /app

# Copy the built fat JAR
COPY --from=builder /app/build/libs/*.jar /app/java-coordinator.jar

# Copy SQL schema (used by the init/healthcheck logic)
COPY sql /app/sql
COPY docker/redpanda /app/docker/redpanda

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=10s --retries=5 --start-period=20s \
  CMD wget -qO- http://localhost:8080/actuator/health || exit 1

ENTRYPOINT ["java", "-jar", "/app/java-coordinator.jar"]