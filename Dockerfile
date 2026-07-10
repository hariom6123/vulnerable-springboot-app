# syntax=docker/dockerfile:1.6
#
# Multi-stage build for the OWASP vulnerability learning lab.
# Builder: compiles the Spring Boot fat JAR with Maven.
# Runtime: minimal JRE image that runs the JAR.
#
# Build:  docker build -t vulnerable-spring-app:ci .
# Run:    docker run --rm -p 8080:8080 vulnerable-spring-app:ci

# ---------- Builder ----------
FROM maven:3.9-eclipse-temurin-17 AS builder
WORKDIR /build

# Cache dependencies first to speed up rebuilds.
COPY pom.xml ./
RUN mvn -B -ntp dependency:go-offline

# Now copy the source and build the fat JAR (skip tests — this lab is
# intentionally insecure and there are no tests; the CI unit-test job runs
# them separately via `mvn test`).
COPY src ./src
RUN mvn -B -ntp -DskipTests package \
 && cp target/vulnerable-spring-app-*.jar /build/app.jar

# ---------- Runtime ----------
FROM eclipse-temurin:17-jre
WORKDIR /app

# Run as a non-root user for a smaller blast radius.
RUN groupadd --system --gid 1001 app \
 && useradd  --system --uid 1001 --gid app --home /app app

COPY --from=builder /build/app.jar /app/app.jar
RUN chown -R app:app /app
USER app

EXPOSE 8080
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
