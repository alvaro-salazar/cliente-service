package com.denkitronik.clienteservice.config;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Convierte el JWT de Keycloak en un objeto de autenticación de Spring Security.
 *
 * <p>Los tokens de Keycloak almacenan los roles del realm en el claim {@code realm_access.roles}.
 * Spring Security por defecto busca los roles en el claim {@code scope} o {@code authorities},
 * por eso necesitamos este converter personalizado que:
 * <ol>
 *   <li>Extrae los roles estándar del JWT (scope, etc.) con el converter por defecto.</li>
 *   <li>Extrae los roles de Keycloak desde {@code realm_access.roles} y les agrega el prefijo ROLE_.</li>
 *   <li>Los combina en un solo conjunto de autoridades.</li>
 * </ol>
 */
@Component
public class KeycloakJwtConverter implements Converter<Jwt, AbstractAuthenticationToken> {

    private final JwtGrantedAuthoritiesConverter defaultConverter = new JwtGrantedAuthoritiesConverter();

    @Override
    public AbstractAuthenticationToken convert(Jwt jwt) {
        Collection<GrantedAuthority> authorities = Stream.concat(
                defaultConverter.convert(jwt).stream(),
                extractRealmRoles(jwt).stream()
        ).collect(Collectors.toSet());

        // preferred_username es el nombre de usuario en Keycloak (ej. "alice")
        String username = jwt.getClaimAsString("preferred_username");
        return new JwtAuthenticationToken(jwt, authorities, username);
    }

    /**
     * Extrae los roles del realm de Keycloak y los convierte en GrantedAuthority con prefijo ROLE_.
     * <p>
     * Ejemplo: el rol "ADMIN" en Keycloak → SimpleGrantedAuthority("ROLE_ADMIN") en Spring.
     */
    @SuppressWarnings("unchecked")
    private Collection<GrantedAuthority> extractRealmRoles(Jwt jwt) {
        Map<String, Object> realmAccess = jwt.getClaimAsMap("realm_access");
        if (realmAccess == null || !realmAccess.containsKey("roles")) {
            return Collections.emptySet();
        }
        List<String> roles = (List<String>) realmAccess.get("roles");
        return roles.stream()
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                .collect(Collectors.toSet());
    }
}
