package com.denkitronik.clienteservice.config;

import java.util.List;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

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
            // Habilita el filtro CORS de Spring Security, que toma su
            // configuración del bean corsConfigurationSource de más abajo.
            // Va antes de la autenticación: el preflight OPTIONS no trae token.
            .cors(Customizer.withDefaults())
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

    /**
     * Permite que el navegador llame a esta API desde otro origen.
     *
     * <p>El front de Angular se sirve en http://localhost:4200 y la API en
     * http://localhost:8080: para el navegador son dos orígenes distintos.
     * Antes de cada petición con cabeceras propias —como Authorization—
     * el navegador manda un OPTIONS de comprobación (preflight). Si la
     * respuesta no lleva los encabezados CORS, el navegador descarta la
     * petición real y la aplicación no ve ningún dato.
     */
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(List.of("http://localhost:4200"));
        config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        config.setAllowedHeaders(List.of("Authorization", "Content-Type"));
        config.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }
}
