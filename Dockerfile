# Construccion en dos etapas. La primera compila; la segunda solo lleva el
# resultado. Asi la imagen final no carga con Maven ni con el codigo fuente,
# y el nombre del .jar deja de estar escrito a mano: lo resuelve el comodin.
FROM maven:3.9-eclipse-temurin-21 AS build
WORKDIR /app
COPY pom.xml .
RUN mvn -B -q dependency:go-offline
COPY src ./src
RUN mvn -B -q package -DskipTests

FROM eclipse-temurin:21-jre-alpine
WORKDIR /app
COPY --from=build /app/target/*.jar app.jar
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "app.jar"]
