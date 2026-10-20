# Isolated review-only candidate; never targets victim-RVcdV.
FROM maven:3.8.8-eclipse-temurin-8 AS build

ARG STRUTS_RELEASE
ARG SOURCE_SHA1
WORKDIR /work

# The official source release and its expected SHA-1 are supplied at build time.
# This file deliberately makes no POM or dependency edits.
RUN set -eux; apt-get update; apt-get install -y --no-install-recommends unzip; rm -rf /var/lib/apt/lists/*; \
    curl -fsSLo source.zip "https://archive.apache.org/dist/struts/${STRUTS_RELEASE}/struts-${STRUTS_RELEASE}-src.zip"; \
    echo "${SOURCE_SHA1}  source.zip" | sha1sum -c -; \
    unzip -q source.zip; \
    test -f "struts-${STRUTS_RELEASE}/src/apps/rest-showcase/pom.xml"

WORKDIR /work
RUN cd "struts-${STRUTS_RELEASE}/src/apps/rest-showcase"; \
    mvn -B -DskipTests package; \
    test -f target/struts2-rest-showcase.war

FROM 2d8ru/struts2@sha256:7aa386b4b606bec5f6a7f015bab6bd1cc84169beadb2a632b6939e6e703e47db
RUN rm -rf /usr/local/tomcat/webapps/S2-045 /usr/local/tomcat/webapps/S2-045.war
ARG STRUTS_RELEASE
COPY --from=build /work/struts-${STRUTS_RELEASE}/src/apps/rest-showcase/target/struts2-rest-showcase.war /usr/local/tomcat/webapps/S2-045.war
