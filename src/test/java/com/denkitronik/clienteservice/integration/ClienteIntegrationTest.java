package com.denkitronik.clienteservice.integration;

import com.denkitronik.clienteservice.domain.entities.Cliente;
import com.denkitronik.clienteservice.domain.entities.Region;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.springframework.http.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Testcontainers
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
@DisplayName("ClienteIntegration — pruebas end-to-end con PostgreSQL real (Testcontainers)")
class ClienteIntegrationTest {

    @Container
    @ServiceConnection
    static PostgreSQLContainer<?> postgres =
            new PostgreSQLContainer<>("postgres:16-alpine");

    @Autowired
    private TestRestTemplate restTemplate;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    // JwtDecoder mockeado para que el contexto no contacte a Keycloak
    @MockBean
    private JwtDecoder jwtDecoder;

    private static final String BASE = "/api/v1/cliente-service";
    private static final AtomicBoolean seeded = new AtomicBoolean(false);
    private static Long regionId;
    private static Long idCreado;

    @BeforeEach
    void setUp() {
        // Configurar JwtDecoder mock para devolver un JWT con roles ADMIN y USER
        Jwt jwt = Jwt.withTokenValue("test-token")
                .header("alg", "RS256")
                .claim("sub", "admin_user")
                .claim("preferred_username", "admin_user")
                .claim("realm_access", Map.of("roles", List.of("ADMIN", "USER")))
                .build();
        when(jwtDecoder.decode(anyString())).thenReturn(jwt);

        // Añadir cabecera Authorization a todas las peticiones de TestRestTemplate
        restTemplate.getRestTemplate().setInterceptors(List.of(
                (request, body, execution) -> {
                    request.getHeaders().add("Authorization", "Bearer test-token");
                    return execution.execute(request, body);
                }
        ));

        // Sembrar datos una sola vez
        if (seeded.compareAndSet(false, true)) {
            jdbcTemplate.execute("INSERT INTO regiones(nombre) VALUES ('América del Sur')");
            regionId = jdbcTemplate.queryForObject(
                    "SELECT id FROM regiones WHERE nombre='América del Sur'", Long.class);
        }
    }

    // ─── POST — crear cliente ───────────────────────────────────────────────

    @Test
    @Order(1)
    @DisplayName("POST /clientes → 201 y devuelve el cliente creado")
    void crearCliente_debeRetornar201() {
        Region region = new Region();
        region.setId(regionId);

        Cliente nuevo = new Cliente();
        nuevo.setNombre("Margaret");
        nuevo.setApellido("Hamilton");
        nuevo.setEmail("margaret@apollo.nasa");
        nuevo.setRegion(region);

        ResponseEntity<Cliente> respuesta =
                restTemplate.postForEntity(BASE + "/clientes", nuevo, Cliente.class);

        assertThat(respuesta.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        assertThat(respuesta.getBody()).isNotNull();
        assertThat(respuesta.getBody().getId()).isNotNull();
        assertThat(respuesta.getBody().getNombre()).isEqualTo("Margaret");

        idCreado = respuesta.getBody().getId();
    }

    // ─── GET — buscar por ID ────────────────────────────────────────────────

    @Test
    @Order(2)
    @DisplayName("GET /clientes/{id} → 200 con el cliente creado")
    void buscarCliente_idCreado_debeRetornar200() {
        ResponseEntity<Cliente> respuesta =
                restTemplate.getForEntity(BASE + "/clientes/" + idCreado, Cliente.class);

        assertThat(respuesta.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(respuesta.getBody().getEmail()).isEqualTo("margaret@apollo.nasa");
    }

    // ─── GET — listar todos ─────────────────────────────────────────────────

    @Test
    @Order(3)
    @DisplayName("GET /clientes → 200 con al menos un cliente")
    void listarClientes_debeRetornar200() {
        ResponseEntity<Cliente[]> respuesta =
                restTemplate.getForEntity(BASE + "/clientes", Cliente[].class);

        assertThat(respuesta.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(respuesta.getBody()).isNotEmpty();
    }

    // ─── GET — listar regiones ──────────────────────────────────────────────

    @Test
    @Order(4)
    @DisplayName("GET /clientes/regiones → 200 con regiones sembradas")
    void listarRegiones_debeRetornar200() {
        ResponseEntity<Region[]> respuesta =
                restTemplate.getForEntity(BASE + "/clientes/regiones", Region[].class);

        assertThat(respuesta.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(respuesta.getBody()).isNotEmpty();
    }

    // ─── PUT — actualizar cliente ───────────────────────────────────────────

    @Test
    @Order(5)
    @DisplayName("PUT /clientes/{id} → 201 con datos actualizados")
    void actualizarCliente_debeRetornar201() {
        Region region = new Region();
        region.setId(regionId);

        Cliente actualizado = new Cliente();
        actualizado.setNombre("Margaret");
        actualizado.setApellido("Hamilton-Updated");
        actualizado.setEmail("margaret@apollo.nasa");
        actualizado.setRegion(region);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        HttpEntity<Cliente> entity = new HttpEntity<>(actualizado, headers);

        ResponseEntity<Cliente> respuesta =
                restTemplate.exchange(BASE + "/clientes/" + idCreado,
                        HttpMethod.PUT, entity, Cliente.class);

        assertThat(respuesta.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        assertThat(respuesta.getBody().getApellido()).isEqualTo("Hamilton-Updated");
    }

    // ─── GET — buscar ID inexistente ────────────────────────────────────────

    @Test
    @Order(6)
    @DisplayName("GET /clientes/9999 → 404")
    void buscarCliente_idInexistente_debeRetornar404() {
        ResponseEntity<String> respuesta =
                restTemplate.getForEntity(BASE + "/clientes/9999", String.class);

        assertThat(respuesta.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
    }

    // ─── DELETE — eliminar cliente ──────────────────────────────────────────

    @Test
    @Order(7)
    @DisplayName("DELETE /clientes/{id} → 204 y GET confirma 404")
    void eliminarCliente_debeRetornar204() {
        restTemplate.delete(BASE + "/clientes/" + idCreado);

        ResponseEntity<String> respuesta =
                restTemplate.getForEntity(BASE + "/clientes/" + idCreado, String.class);

        assertThat(respuesta.getStatusCode()).isEqualTo(HttpStatus.NOT_FOUND);
    }
}
