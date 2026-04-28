package com.denkitronik.clienteservice.repositories;

import com.denkitronik.clienteservice.entities.Cliente;
import com.denkitronik.clienteservice.entities.Region;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import java.util.List;

public interface IClienteDao extends JpaRepository<Cliente, Long> {

    // Consulta JPQL personalizada para obtener todas las regiones
    // JPQL usa el nombre de la clase Java, no el nombre de la tabla SQL
    @Query("from Region")
    List<Region> findAllRegiones();
}
