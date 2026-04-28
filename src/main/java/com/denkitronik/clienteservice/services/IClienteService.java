package com.denkitronik.clienteservice.services;

import com.denkitronik.clienteservice.entities.Cliente;
import com.denkitronik.clienteservice.entities.Region;

import java.util.List;
import java.util.Optional;

public interface IClienteService {

    List<Cliente> findAll();

    Optional<Cliente> findById(Long id);

    Cliente save(Cliente cliente);

    Cliente update(Cliente cliente);

    void delete(Cliente cliente);

    List<Region> findAllRegiones();
}
