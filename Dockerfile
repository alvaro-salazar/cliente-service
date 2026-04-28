# ── Etapa 1: compilación ─────────────────────────────────────────────────────
FROM maven:3.9-eclipse-temurin-21-alpine AS build
WORKDIR /workspace

# Copiamos pom.xml primero — si no cambian las dependencias, Docker reutiliza
# esta capa en caché y no vuelve a descargar internet entero en cada build
COPY pom.xml .
RUN mvn dependency:go-offline -q

# Ahora sí copiamos el código fuente y compilamos
COPY src ./src
RUN mvn package -DskipTests -q

# ── Etapa 2: imagen de runtime ───────────────────────────────────────────────
FROM eclipse-temurin:21-jre-alpine
WORKDIR /app

# Buena práctica: correr la app como usuario no-root
RUN addgroup -S spring && adduser -S spring -G spring
USER spring:spring

# Copiamos únicamente el JAR generado en la etapa anterior
COPY --from=build /workspace/target/*.jar app.jar

EXPOSE 8080 8081

ENTRYPOINT ["java", "-jar", "app.jar"]
