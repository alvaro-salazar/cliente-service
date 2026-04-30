package com.denkitronik.clienteservice.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Configura Spring Security como Resource Server OAuth2.
 *
 * <p>Un Resource Server valida tokens JWT entrantes. No emite tokens
 * — eso lo hace Keycloak. Solo verifica que el token sea válido y
 * que el usuario tenga los roles necesarios.
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
                // Todo lo demás requiere un token JWT válido
                .anyRequest().authenticated()
            )
            .oauth2ResourceServer(oauth2 -> oauth2
                // Le decimos a Spring que use nuestro converter para extraer roles
                .jwt(jwt -> jwt.jwtAuthenticationConverter(keycloakJwtConverter))
            )
            // REST APIs son stateless: cada petición trae su propio token,
            // no necesitamos sesión HTTP
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            )
            // CSRF no aplica en APIs REST stateless
            .csrf(csrf -> csrf.disable());

        return http.build();
    }
}
