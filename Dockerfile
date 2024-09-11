FROM bellsoft/liberica-openjdk-debian:17.0.11-cds

LABEL maintainer="picachu"

RUN mkdir -p /base/oauth2/logs  \
    /base/oauth2/temp  \
    /base/skywalking/agent

WORKDIR /base/oauth2

ENV SERVER_PORT=8080 LANG=C.UTF-8 LC_ALL=C.UTF-8 JAVA_OPTS=""

EXPOSE ${SERVER_PORT}

ADD *.jar ./app.jar

ENTRYPOINT java -Djava.security.egd=file:/dev/./urandom -Dserver.port=${SERVER_PORT} \
           #-Dskywalking.agent.service_name=base-oauth2 \
           #-javaagent:/ruoyi/skywalking/agent/skywalking-agent.jar \
           -XX:+HeapDumpOnOutOfMemoryError -XX:+UseZGC ${JAVA_OPTS} \
           -jar app.jar

