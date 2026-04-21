package com.denkitronik.clienteservice.domain.services;

import com.denkitronik.clienteservice.delivery.exception.ClienteNotFoundException;
import com.denkitronik.clienteservice.domain.entities.Cliente;
import com.denkitronik.clienteservice.domain.entities.Region;
import com.denkitronik.clienteservice.domain.repositories.IClienteDao;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("ClienteServiceImpl — pruebas unitarias con Mockito")
class ClienteServiceImplTest {

    @Mock
    private IClienteDao clienteDao;

    @InjectMocks
    private ClienteServiceImpl clienteService;

    private Cliente cliente;
    private Region region;

    @BeforeEach
    void setUp() {
        region = new Region();
        region.setId(1L);
        region.setNombre("Sudamérica");

        cliente = new Cliente();
        cliente.setId(1L);
        cliente.setNombre("Linus");
        cliente.setApellido("Torvalds");
        cliente.setEmail("linus@kernel.org");
        cliente.setRegion(region);
    }

    // ─── findAll() lista completa ───────────────────────────────────────────

    @Test
    @DisplayName("findAll() devuelve todos los clientes")
    void findAll_debeRetornarLista() {
        when(clienteDao.findAll()).thenReturn(List.of(cliente));

        List<Cliente> resultado = clienteService.findAll();

        assertThat(resultado).hasSize(1);
        assertThat(resultado.get(0).getNombre()).isEqualTo("Linus");
        verify(clienteDao).findAll();
    }

    // ─── findAll(Pageable) ──────────────────────────────────────────────────

    @Test
    @DisplayName("findAll(Pageable) devuelve página correcta")
    void findAll_paginado_debeRetornarPage() {
        PageRequest pageable = PageRequest.of(0, 4);
        Page<Cliente> pagina = new PageImpl<>(List.of(cliente), pageable, 1);
        when(clienteDao.findAll(pageable)).thenReturn(pagina);

        Page<Cliente> resultado = clienteService.findAll(pageable);

        assertThat(resultado.getTotalElements()).isEqualTo(1);
        assertThat(resultado.getContent().get(0).getEmail()).isEqualTo("linus@kernel.org");
    }

    // ─── findById ──────────────────────────────────────────────────────────

    @Test
    @DisplayName("findById con ID existente devuelve el cliente")
    void findById_idExistente_debeRetornarCliente() {
        when(clienteDao.findById(1L)).thenReturn(Optional.of(cliente));

        Cliente resultado = clienteService.findById(1L);

        assertThat(resultado.getId()).isEqualTo(1L);
        assertThat(resultado.getNombre()).isEqualTo("Linus");
    }

    @Test
    @DisplayName("findById con ID inexistente lanza ClienteNotFoundException")
    void findById_idInexistente_debeLanzarExcepcion() {
        when(clienteDao.findById(999L)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> clienteService.findById(999L))
                .isInstanceOf(ClienteNotFoundException.class)
                .hasMessageContaining("999");
    }

    // ─── save ──────────────────────────────────────────────────────────────

    @Test
    @DisplayName("save persiste y devuelve el cliente")
    void save_clienteValido_debeRetornarClienteGuardado() {
        when(clienteDao.save(cliente)).thenReturn(cliente);

        Cliente resultado = clienteService.save(cliente);

        assertThat(resultado.getEmail()).isEqualTo("linus@kernel.org");
        verify(clienteDao).save(cliente);
    }

    @Test
    @DisplayName("save con email duplicado lanza ClienteServiceException")
    void save_emailDuplicado_debeLanzarExcepcion() {
        when(clienteDao.save(cliente))
                .thenThrow(new DataIntegrityViolationException("duplicate key"));

        assertThatThrownBy(() -> clienteService.save(cliente))
                .isInstanceOf(com.denkitronik.clienteservice.delivery.exception.ClienteServiceException.class)
                .hasMessageContaining("duplicados");
    }

    // ─── delete ────────────────────────────────────────────────────────────

    @Test
    @DisplayName("delete con ID existente llama deleteById")
    void delete_idExistente_debeEliminar() {
        when(clienteDao.existsById(1L)).thenReturn(true);

        clienteService.delete(1L);

        verify(clienteDao).deleteById(1L);
    }

    @Test
    @DisplayName("delete con ID inexistente lanza ClienteNotFoundException")
    void delete_idInexistente_debeLanzarExcepcion() {
        when(clienteDao.existsById(999L)).thenReturn(false);

        assertThatThrownBy(() -> clienteService.delete(999L))
                .isInstanceOf(ClienteNotFoundException.class);

        verify(clienteDao, never()).deleteById(any());
    }

    // ─── findAllRegiones ───────────────────────────────────────────────────

    @Test
    @DisplayName("findAllRegiones devuelve la lista de regiones")
    void findAllRegiones_debeRetornarLista() {
        when(clienteDao.findAllRegiones()).thenReturn(List.of(region));

        List<Region> resultado = clienteService.findAllRegiones();

        assertThat(resultado).hasSize(1);
        assertThat(resultado.get(0).getNombre()).isEqualTo("Sudamérica");
    }
}
