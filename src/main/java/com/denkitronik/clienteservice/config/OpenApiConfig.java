package com.denkitronik.clienteservice.config;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
import io.swagger.v3.oas.annotations.info.Info;
import io.swagger.v3.oas.annotations.security.SecurityScheme;
import org.springframework.context.annotation.Configuration;

/**
 * Configura la documentación OpenAPI 3 (Swagger UI) del microservicio.
 *
 * <p>Define el esquema de seguridad "bearerAuth" de tipo HTTP Bearer con formato JWT.
 * Este esquema se referencia en cada endpoint del controlador mediante
 * {@code @SecurityRequirement(name = "bearerAuth")}, lo que hace que Swagger UI
 * muestre el candado y el botón "Authorize" para ingresar el token.
 */
@Configuration
@OpenAPIDefinition(info = @Info(
        title       = "Cliente Service API",
        version     = "1.0",
        description = "API REST para gestión de clientes — protegida con OAuth2/JWT (Keycloak). " +
                      "Para probar endpoints protegidos: obten un token de Keycloak con " +
                      "POST /realms/curso-springboot/protocol/openid-connect/token y " +
                      "pégalo en el botón Authorize."
))
@SecurityScheme(
        name         = "bearerAuth",
        type         = SecuritySchemeType.HTTP,
        scheme       = "bearer",
        bearerFormat = "JWT",
        description  = "Token JWT emitido por Keycloak. " +
                       "Obtenlo con: curl -d 'grant_type=password&client_id=cliente-service" +
                       "&username=alice&password=alice123' " +
                       "http://localhost:8090/realms/curso-springboot/protocol/openid-connect/token"
)
public class OpenApiConfig {}
