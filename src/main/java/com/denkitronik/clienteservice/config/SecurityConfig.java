package com.denkitronik.clienteservice.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Configuración de Spring Security para cliente-service como Resource Server OAuth2.
 *
 * <p>Un Resource Server es el servidor que protege los recursos (los endpoints REST).
 * No emite tokens — eso lo hace Keycloak. Solo valida que el token que llega en cada
 * petición sea válido y que el usuario tenga los roles necesarios.
 *
 * <p>Flujo de una petición protegida:
 * <pre>
 *   Cliente → [Authorization: Bearer &lt;token&gt;] → SecurityFilterChain
 *                                                       ↓
 *                                              JwtDecoder valida firma
 *                                              y vigencia del token
 *                                                       ↓
 *                                          KeycloakJwtConverter extrae roles
 *                                                       ↓
 *                                         @PreAuthorize verifica el rol
 *                                                       ↓
 *                                              Controlador REST
 * </pre>
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity   // habilita @PreAuthorize en los controladores
public class SecurityConfig {

    private final KeycloakJwtConverter keycloakJwtConverter;

    public SecurityConfig(KeycloakJwtConverter keycloakJwtConverter) {
        this.keycloakJwtConverter = keycloakJwtConverter;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                // Actuator y Swagger UI expuestos sin autenticación
                .requestMatchers("/actuator/**",
                                 "/swagger-ui/**",
                                 "/swagger-ui.html",
                                 "/v3/api-docs/**").permitAll()
                // Todo lo demás requiere token válido
                .anyRequest().authenticated()
            )
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> jwt.jwtAuthenticationConverter(keycloakJwtConverter))
            )
            // REST APIs son stateless: no necesitan sesión HTTP
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            )
            // CSRF no aplica en APIs REST stateless
            .csrf(csrf -> csrf.disable());

        return http.build();
    }
}
