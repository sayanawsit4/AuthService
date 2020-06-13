FROM openjdk:8-jdk-alpine
VOLUME /tmp
COPY target/*.jar app.jar
ARG ARG_PROFILE=test
ENV SPRING_PROFILES_ACTIVE=$ARG_PROFILE
ENTRYPOINT ["java","-jar","/app.jar"]