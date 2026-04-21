package com.denkitronik.clienteservice.domain.repositories;

import com.denkitronik.clienteservice.domain.entities.Cliente;
import com.denkitronik.clienteservice.domain.entities.Region;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.autoconfigure.orm.jpa.TestEntityManager;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;

import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.*;

@DataJpaTest
@DisplayName("IClienteDao — pruebas de repositorio con H2 en memoria")
class IClienteDaoTest {

    @Autowired
    private TestEntityManager em;

    @Autowired
    private IClienteDao clienteDao;

    private Region region;
    private Cliente cliente;

    @BeforeEach
    void setUp() {
        region = new Region();
        region.setNombre("Asia");
        em.persist(region);

        cliente = new Cliente();
        cliente.setNombre("Grace");
        cliente.setApellido("Hopper");
        cliente.setEmail("grace@navy.mil");
        cliente.setRegion(region);
        em.persist(cliente);

        em.flush();
    }

    // ─── findById ──────────────────────────────────────────────────────────

    @Test
    @DisplayName("findById con ID existente devuelve el cliente")
    void findById_idExistente_debeRetornarCliente() {
        Optional<Cliente> resultado = clienteDao.findById(cliente.getId());

        assertThat(resultado).isPresent();
        assertThat(resultado.get().getNombre()).isEqualTo("Grace");
    }

    @Test
    @DisplayName("findById con ID inexistente devuelve Optional.empty()")
    void findById_idInexistente_debeRetornarVacio() {
        Optional<Cliente> resultado = clienteDao.findById(9999L);

        assertThat(resultado).isEmpty();
    }

    // ─── save ──────────────────────────────────────────────────────────────

    @Test
    @DisplayName("save persiste un cliente nuevo y genera ID")
    void save_clienteNuevo_debeGenerarId() {
        Cliente nuevo = new Cliente();
        nuevo.setNombre("Alan");
        nuevo.setApellido("Turing");
        nuevo.setEmail("alan@bletchley.uk");
        nuevo.setRegion(region);

        Cliente guardado = clienteDao.save(nuevo);

        assertThat(guardado.getId()).isNotNull().isPositive();
        assertThat(em.find(Cliente.class, guardado.getId())).isNotNull();
    }

    // ─── findAll (paginado) ─────────────────────────────────────────────────

    @Test
    @DisplayName("findAll paginado devuelve página con el cliente persistido")
    void findAll_paginado_debeRetornarPagina() {
        Page<Cliente> pagina = clienteDao.findAll(PageRequest.of(0, 4));

        assertThat(pagina.getTotalElements()).isGreaterThanOrEqualTo(1);
    }

    // ─── delete ────────────────────────────────────────────────────────────

    @Test
    @DisplayName("deleteById elimina el cliente de la BD")
    void deleteById_debeEliminarCliente() {
        Long id = cliente.getId();
        clienteDao.deleteById(id);
        em.flush();

        assertThat(em.find(Cliente.class, id)).isNull();
    }

    // ─── findAllRegiones (query personalizada) ──────────────────────────────

    @Test
    @DisplayName("findAllRegiones devuelve las regiones persistidas")
    void findAllRegiones_debeRetornarLista() {
        List<Region> regiones = clienteDao.findAllRegiones();

        assertThat(regiones).isNotEmpty();
        assertThat(regiones.get(0).getNombre()).isEqualTo("Asia");
    }
}
