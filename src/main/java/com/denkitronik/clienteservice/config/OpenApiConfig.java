package com.denkitronik.clienteservice.config;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
import io.swagger.v3.oas.annotations.info.Info;
import io.swagger.v3.oas.annotations.security.SecurityScheme;
import org.springframework.context.annotation.Configuration;

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
        description  = "Token JWT emitido por Keycloak."
)
public class OpenApiConfig {}
