# syntax=docker/dockerfile:1

# ---------------------------------------------------------------------------
# Build stage -- JDK 25 to match the toolchain in build.gradle.
# The BuildKit cache mount keeps the Gradle distribution and the resolved
# dependencies between builds, so only the first build hits the network.
# ---------------------------------------------------------------------------
FROM eclipse-temurin:25-jdk AS build
WORKDIR /workspace

COPY gradlew ./
COPY gradle ./gradle
COPY build.gradle settings.gradle ./
COPY src ./src

RUN --mount=type=cache,target=/root/.gradle \
    chmod +x gradlew \
 && ./gradlew --no-daemon bootJar \
 && cp build/libs/*-SNAPSHOT.jar /workspace/app.jar

# ---------------------------------------------------------------------------
# Runtime stage.
# curl is here for the compose healthcheck: there is no actuator on the
# classpath, so the probe hits the real /.well-known/openid-configuration
# endpoint -- which also proves the signing keys are loaded before the other
# services are allowed to start.
# ---------------------------------------------------------------------------
FROM eclipse-temurin:25-jre
WORKDIR /app

RUN apt-get update \
 && apt-get install -y --no-install-recommends curl \
 && rm -rf /var/lib/apt/lists/* \
 && useradd -r -u 1001 spring

COPY --from=build /workspace/app.jar app.jar
USER spring

EXPOSE 9000
ENTRYPOINT ["java", "-XX:MaxRAMPercentage=75.0", "-jar", "/app/app.jar"]
