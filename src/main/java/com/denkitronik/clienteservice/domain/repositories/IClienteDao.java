package com.denkitronik.clienteservice.domain.repositories;

import com.denkitronik.clienteservice.domain.entities.Cliente;
import com.denkitronik.clienteservice.domain.entities.Region;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import java.util.List;

public interface IClienteDao extends JpaRepository<Cliente, Long> {

    // JpaRepository ya incluye:
    // Page<Cliente> findAll(Pageable pageable);
    // Optional<Cliente> findById(Long id);
    // Cliente save(Cliente cliente);
    // void deleteById(Long id);
    // long count();
    // boolean existsById(Long id);

    @Query("from Region")
    List<Region> findAllRegiones();
}
