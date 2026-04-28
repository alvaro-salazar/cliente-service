package com.denkitronik.clienteservice.services;

import com.denkitronik.clienteservice.entities.Cliente;
import com.denkitronik.clienteservice.entities.Region;
import com.denkitronik.clienteservice.repositories.IClienteDao;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
public class ClienteServiceImpl implements IClienteService {

    @Autowired
    private IClienteDao clienteDao;

    @Override
    public List<Cliente> findAll() {
        return clienteDao.findAll();
    }

    @Override
    public Optional<Cliente> findById(Long id) {
        return clienteDao.findById(id);
    }

    @Override
    public Cliente save(Cliente cliente) {
        return clienteDao.save(cliente);
    }

    @Override
    public Cliente update(Cliente cliente) {
        // save() de JPA hace INSERT si no tiene ID, UPDATE si lo tiene
        return clienteDao.save(cliente);
    }

    @Override
    public void delete(Cliente cliente) {
        clienteDao.delete(cliente);
    }

    @Override
    public List<Region> findAllRegiones() {
        return clienteDao.findAllRegiones();
    }
}
