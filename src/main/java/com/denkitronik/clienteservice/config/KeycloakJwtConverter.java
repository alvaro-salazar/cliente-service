package com.denkitronik.clienteservice.config;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Converter que transforma un JWT de Keycloak en un Authentication de Spring Security.
 *
 * <p>Keycloak coloca los roles del usuario en el claim "realm_access.roles":
 * <pre>
 * {
 *   "realm_access": {
 *     "roles": ["ADMIN", "USER"]
 *   }
 * }
 * </pre>
 *
 * <p>Spring Security espera GrantedAuthority con prefijo "ROLE_", por ejemplo "ROLE_ADMIN".
 * Este converter extrae los roles y añade el prefijo.
 */
@Component
public class KeycloakJwtConverter implements Converter<Jwt, AbstractAuthenticationToken> {

    // Converter por defecto: extrae claims "scope"/"scp" como SCOPE_xxx
    private final JwtGrantedAuthoritiesConverter defaultConverter =
            new JwtGrantedAuthoritiesConverter();

    @Override
    public AbstractAuthenticationToken convert(Jwt jwt) {
        // Combina las authorities del converter por defecto
        // con los roles de Keycloak (realm_access.roles)
        Collection<GrantedAuthority> authorities = Stream.concat(
                defaultConverter.convert(jwt).stream(),
                extractRealmRoles(jwt).stream()
        ).collect(Collectors.toSet());

        // Usamos "preferred_username" como nombre principal (más legible que "sub")
        String username = jwt.getClaimAsString("preferred_username");

        return new JwtAuthenticationToken(jwt, authorities, username);
    }

    /**
     * Extrae los roles del claim realm_access.roles y los convierte a
     * SimpleGrantedAuthority con prefijo "ROLE_".
     *
     * <p>Ejemplo: "ADMIN" → SimpleGrantedAuthority("ROLE_ADMIN")
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
