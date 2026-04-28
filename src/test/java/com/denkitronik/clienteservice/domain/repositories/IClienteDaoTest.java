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
@DisplayName("Integration tests (data slice) — IClienteDao con H2")
class IClienteDaoTest {

    @Autowired
    private TestEntityManager em;     // para preparar datos de prueba

    @Autowired
    private IClienteDao clienteDao;   // el repositorio que estamos probando

    private Region region;
    private Cliente cliente;

    @BeforeEach
    void setUp() {
        // Preparamos datos con TestEntityManager, no con el repositorio bajo prueba
        region = new Region();
        region.setNombre("Asia");
        em.persist(region);

        cliente = new Cliente();
        cliente.setNombre("Grace");
        cliente.setApellido("Hopper");
        cliente.setEmail("grace@navy.mil");
        cliente.setRegion(region);
        em.persist(cliente);

        em.flush();  // fuerza el INSERT antes de que los tests lean datos
    }

    @Test
    @DisplayName("findAll() — devuelve los clientes persistidos")
    void findAll_debeRetornarClientesPersistidos() {
        List<Cliente> clientes = clienteDao.findAll();

        assertThat(clientes).isNotEmpty();
        assertThat(clientes.get(0).getNombre()).isEqualTo("Grace");
    }

    @Test
    @DisplayName("findAll(Pageable) — devuelve página de clientes")
    void findAll_conPageable_debeRetornarPagina() {
        Page<Cliente> pagina = clienteDao.findAll(PageRequest.of(0, 4));

        assertThat(pagina.getContent()).isNotEmpty();
        assertThat(pagina.getTotalElements()).isGreaterThanOrEqualTo(1);
    }

    @Test
    @DisplayName("findById — devuelve el cliente por ID")
    void findById_debeRetornarCliente() {
        Optional<Cliente> resultado = clienteDao.findById(cliente.getId());

        assertThat(resultado).isPresent();
        assertThat(resultado.get().getEmail()).isEqualTo("grace@navy.mil");
    }

    @Test
    @DisplayName("findAllRegiones — devuelve las regiones persistidas")
    void findAllRegiones_debeRetornarListaDeRegiones() {
        // Act: llamamos a nuestra query personalizada
        List<Region> regiones = clienteDao.findAllRegiones();

        // Assert
        assertThat(regiones).hasSize(1);
        assertThat(regiones.get(0).getNombre()).isEqualTo("Asia");
    }

    @Test
    @DisplayName("save — persiste un nuevo cliente")
    void save_debeGuardarNuevoCliente() {
        Cliente nuevo = new Cliente();
        nuevo.setNombre("Alan");
        nuevo.setApellido("Turing");
        nuevo.setEmail("alan@bletchley.uk");
        nuevo.setRegion(region);

        Cliente guardado = clienteDao.save(nuevo);

        assertThat(guardado.getId()).isNotNull();
        assertThat(guardado.getNombre()).isEqualTo("Alan");
    }

    @Test
    @DisplayName("deleteById — elimina el cliente verificado con em.find")
    void deleteById_debeEliminarElCliente() {
        Long id = cliente.getId();

        clienteDao.deleteById(id);
        em.flush();

        // Verificamos directamente en el contexto de persistencia
        // (más confiable que llamar findById nuevamente)
        assertThat(em.find(Cliente.class, id)).isNull();
    }
}
