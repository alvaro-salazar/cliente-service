package com.denkitronik.clienteservice.delivery.rest;

import com.denkitronik.clienteservice.delivery.exception.ClienteNotFoundException;
import com.denkitronik.clienteservice.domain.entities.Cliente;
import com.denkitronik.clienteservice.domain.entities.Region;
import com.denkitronik.clienteservice.domain.services.IClienteService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Import;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.http.MediaType;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.web.servlet.MockMvc;

import java.util.List;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(ClienteRestController.class)
@Import(ClienteRestControllerTest.MethodSecurityTestConfig.class)
@DisplayName("ClienteRestController — pruebas de capa web con MockMvc")
class ClienteRestControllerTest {

    /** Activa @PreAuthorize en el slice @WebMvcTest (no incluido por defecto) */
    @TestConfiguration
    @EnableMethodSecurity
    static class MethodSecurityTestConfig {}

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private IClienteService clienteService;

    // JwtDecoder se mockea para que @WebMvcTest no intente contactar a Keycloak
    @MockBean
    private JwtDecoder jwtDecoder;

    @Autowired
    private ObjectMapper objectMapper;

    private Cliente cliente;
    private Region region;

    private static final String BASE = "/api/v1/cliente-service";

    @BeforeEach
    void setUp() {
        region = new Region();
        region.setId(4L);
        region.setNombre("Europa");

        cliente = new Cliente();
        cliente.setId(1L);
        cliente.setNombre("Ada");
        cliente.setApellido("Lovelace");
        cliente.setEmail("ada@babbage.uk");
        cliente.setRegion(region);
    }

    // ─── GET /clientes ──────────────────────────────────────────────────────

    @Test
    @DisplayName("GET /clientes con ROLE_USER → 200 con lista")
    void listarClientes_conRoleUser_debeRetornar200() throws Exception {
        when(clienteService.findAll()).thenReturn(List.of(cliente));

        mockMvc.perform(get(BASE + "/clientes")
                        .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_USER"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].nombre").value("Ada"))
                .andExpect(jsonPath("$[0].email").value("ada@babbage.uk"));
    }

    @Test
    @DisplayName("GET /clientes sin token → 401")
    void listarClientes_sinToken_debeRetornar401() throws Exception {
        mockMvc.perform(get(BASE + "/clientes"))
                .andExpect(status().isUnauthorized());
    }

    // ─── GET /clientes/page/{page} ──────────────────────────────────────────

    @Test
    @DisplayName("GET /clientes/page/0 con ROLE_USER → 200 con página")
    void listarPaginado_debeRetornar200() throws Exception {
        var pageable = PageRequest.of(0, 4);
        var pagina = new PageImpl<>(List.of(cliente), pageable, 1);
        when(clienteService.findAll(pageable)).thenReturn(pagina);

        mockMvc.perform(get(BASE + "/clientes/page/0")
                        .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_USER"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.totalElements").value(1))
                .andExpect(jsonPath("$.content[0].nombre").value("Ada"));
    }

    // ─── GET /clientes/{id} ─────────────────────────────────────────────────

    @Test
    @DisplayName("GET /clientes/1 con ROLE_USER → 200 con cliente")
    void buscarCliente_idExistente_debeRetornar200() throws Exception {
        when(clienteService.findById(1L)).thenReturn(cliente);

        mockMvc.perform(get(BASE + "/clientes/1")
                        .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_USER"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.apellido").value("Lovelace"));
    }

    @Test
    @DisplayName("GET /clientes/999 → 404")
    void buscarCliente_idInexistente_debeRetornar404() throws Exception {
        when(clienteService.findById(999L)).thenThrow(new ClienteNotFoundException(999L));

        mockMvc.perform(get(BASE + "/clientes/999")
                        .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_USER"))))
                .andExpect(status().isNotFound());
    }

    // ─── POST /clientes ─────────────────────────────────────────────────────

    @Test
    @DisplayName("POST /clientes con ROLE_ADMIN y datos válidos → 201")
    void crearCliente_conRoleAdmin_debeRetornar201() throws Exception {
        when(clienteService.save(any(Cliente.class))).thenReturn(cliente);

        mockMvc.perform(post(BASE + "/clientes")
                        .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_ADMIN")))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(cliente)))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.nombre").value("Ada"));
    }

    @Test
    @DisplayName("POST /clientes con ROLE_USER → 403 Forbidden")
    void crearCliente_conRoleUser_debeRetornar403() throws Exception {
        mockMvc.perform(post(BASE + "/clientes")
                        .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_USER")))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(cliente)))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("POST /clientes con nombre vacío → 400")
    void crearCliente_nombreVacio_debeRetornar400() throws Exception {
        cliente.setNombre("");

        mockMvc.perform(post(BASE + "/clientes")
                        .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_ADMIN")))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(cliente)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.errors").isArray());
    }

    @Test
    @DisplayName("POST /clientes con email inválido → 400")
    void crearCliente_emailInvalido_debeRetornar400() throws Exception {
        cliente.setEmail("no-es-email");

        mockMvc.perform(post(BASE + "/clientes")
                        .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_ADMIN")))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(cliente)))
                .andExpect(status().isBadRequest());
    }

    // ─── PUT /clientes/{id} ─────────────────────────────────────────────────

    @Test
    @DisplayName("PUT /clientes/1 con ROLE_ADMIN → 201")
    void actualizarCliente_conRoleAdmin_debeRetornar201() throws Exception {
        when(clienteService.findById(1L)).thenReturn(cliente);
        when(clienteService.save(any(Cliente.class))).thenReturn(cliente);

        mockMvc.perform(put(BASE + "/clientes/1")
                        .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_ADMIN")))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(cliente)))
                .andExpect(status().isCreated());
    }

    @Test
    @DisplayName("PUT /clientes/1 con ROLE_USER → 403 Forbidden")
    void actualizarCliente_conRoleUser_debeRetornar403() throws Exception {
        mockMvc.perform(put(BASE + "/clientes/1")
                        .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_USER")))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(cliente)))
                .andExpect(status().isForbidden());
    }

    // ─── DELETE /clientes/{id} ──────────────────────────────────────────────

    @Test
    @DisplayName("DELETE /clientes/1 con ROLE_ADMIN → 204")
    void eliminarCliente_conRoleAdmin_debeRetornar204() throws Exception {
        doNothing().when(clienteService).delete(1L);

        mockMvc.perform(delete(BASE + "/clientes/1")
                        .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_ADMIN"))))
                .andExpect(status().isNoContent());
    }

    @Test
    @DisplayName("DELETE /clientes/999 → 404")
    void eliminarCliente_idInexistente_debeRetornar404() throws Exception {
        doThrow(new ClienteNotFoundException(999L)).when(clienteService).delete(999L);

        mockMvc.perform(delete(BASE + "/clientes/999")
                        .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_ADMIN"))))
                .andExpect(status().isNotFound());
    }

    // ─── GET /clientes/regiones ─────────────────────────────────────────────

    @Test
    @DisplayName("GET /clientes/regiones con ROLE_USER → 200 con lista")
    void listarRegiones_debeRetornar200() throws Exception {
        when(clienteService.findAllRegiones()).thenReturn(List.of(region));

        mockMvc.perform(get(BASE + "/clientes/regiones")
                        .with(jwt().authorities(new SimpleGrantedAuthority("ROLE_USER"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].nombre").value("Europa"));
    }
}
