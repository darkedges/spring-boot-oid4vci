# syntax=docker/dockerfile:1.7-labs
# Builds the bank portal from source, so the image never carries a stale jar from the host. The build context is the oid4vci
# repository root, and the sibling oid4vp repository is the "oid4vp" context (docker-compose.bank.yml sets both).

FROM maven:3.9-eclipse-temurin-21 AS build
# Only POMs and sources are copied: never .env files, keys, Terraform state or the host's target folders.
WORKDIR /build/oid4vp
COPY --from=oid4vp --parents pom.xml */pom.xml */src ./
WORKDIR /build/oid4vci
COPY --parents pom.xml */pom.xml */src ./
# One step, because the second build reads what the first installed into the cached repository. Tests run in `make test`.
RUN --mount=type=cache,target=/root/.m2 \
    mvn -B -q -f /build/oid4vp/pom.xml install -DskipTests \
 && mvn -B -q -f /build/oid4vci/pom.xml -pl bank-onboarding -am package -DskipTests \
 && cp /build/oid4vci/bank-onboarding/target/bank-onboarding-0.1.0-SNAPSHOT.jar /build/bank.jar

FROM eclipse-temurin:21-jre
WORKDIR /app
COPY --from=build /build/bank.jar app.jar
USER 10001
EXPOSE 8094
ENTRYPOINT ["java", "-jar", "/app/app.jar"]
