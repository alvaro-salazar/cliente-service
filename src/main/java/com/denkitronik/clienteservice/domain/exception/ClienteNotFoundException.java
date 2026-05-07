package com.denkitronik.clienteservice.domain.exception;

public class ClienteNotFoundException extends RuntimeException {

    private final Long id;

    public ClienteNotFoundException(Long id) {
        super("Cliente con id " + id + " no encontrado");
        this.id = id;
    }

    public Long getId() {
        return id;
    }
}
