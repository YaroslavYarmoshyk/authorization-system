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
# Runtime stage
# ---------------------------------------------------------------------------
FROM eclipse-temurin:25-jre
WORKDIR /app

RUN useradd -r -u 1001 spring

COPY --from=build /workspace/app.jar app.jar
USER spring

EXPOSE 8080
ENTRYPOINT ["java", "-XX:MaxRAMPercentage=75.0", "-jar", "/app/app.jar"]
