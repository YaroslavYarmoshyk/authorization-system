# syntax=docker/dockerfile:1

# ---------------------------------------------------------------------------
# Build stage -- JDK 25 to match the toolchain in build.gradle.
#
# NOTE: the build context is the repository ROOT, not resource-server/.
# resource-server/settings.gradle declares `includeBuild '../myapp-security-starter'`,
# so both projects have to be present in the same relative layout.
# See the `build.context: .` entry in compose.yaml.
# ---------------------------------------------------------------------------
FROM eclipse-temurin:25-jdk AS build
WORKDIR /workspace

COPY myapp-security-starter/ ./myapp-security-starter/
COPY resource-server/ ./resource-server/

WORKDIR /workspace/resource-server
RUN --mount=type=cache,target=/root/.gradle \
    chmod +x gradlew ../myapp-security-starter/gradlew \
 && ./gradlew --no-daemon bootJar \
 && cp build/libs/*-SNAPSHOT.jar /workspace/app.jar

# ---------------------------------------------------------------------------
# Runtime stage -- the fat jar already embeds myapp-security-starter through
# the composite-build substitution, so nothing else needs to be copied.
# ---------------------------------------------------------------------------
FROM eclipse-temurin:25-jre
WORKDIR /app

RUN useradd -r -u 1001 spring

COPY --from=build /workspace/app.jar app.jar
USER spring

EXPOSE 9001
ENTRYPOINT ["java", "-XX:MaxRAMPercentage=75.0", "-jar", "/app/app.jar"]
