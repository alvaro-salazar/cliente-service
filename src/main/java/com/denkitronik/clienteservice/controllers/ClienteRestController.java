package com.denkitronik.clienteservice.controllers;

import com.denkitronik.clienteservice.entities.Cliente;
import com.denkitronik.clienteservice.entities.Region;
import com.denkitronik.clienteservice.services.IClienteService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Optional;

// @RestController = @Controller + @ResponseBody
// @Controller     -> registra esta clase como un controlador Spring MVC
// @ResponseBody   -> serializa automáticamente el retorno a JSON
@RestController

// Todos los endpoints de esta clase empiezan con esta URL base
// ${api.version} toma el valor de api.version en application.properties
@RequestMapping("/api/${api.version}/cliente-service")

// Permite peticiones desde el frontend Angular en puerto 4200
@CrossOrigin(origins = {"http://localhost:4200"})
public class ClienteRestController {

    @Autowired
    private IClienteService clienteService;

    // ── GET /clientes ────────────────────────────────────────────────────────
    @GetMapping("/clientes")
    public ResponseEntity<List<Cliente>> listarClientes() {
        List<Cliente> clientes = clienteService.findAll();
        return ResponseEntity.ok(clientes);
    }

    // ── GET /clientes/{id} ───────────────────────────────────────────────────
    @GetMapping("/clientes/{id}")
    public ResponseEntity<?> buscarCliente(@PathVariable Long id) {
        Optional<Cliente> cliente = clienteService.findById(id);
        if (cliente.isPresent()) {
            return ResponseEntity.ok(cliente.get());
        }
        return ResponseEntity.notFound().build();
    }

    // ── POST /clientes ───────────────────────────────────────────────────────
    @PostMapping("/clientes")
    public ResponseEntity<Cliente> crearCliente(@RequestBody Cliente cliente) {
        Cliente nuevo = clienteService.save(cliente);
        return ResponseEntity.status(HttpStatus.CREATED).body(nuevo);
    }

    // ── PUT /clientes ────────────────────────────────────────────────────────
    // El ID del cliente a actualizar viene dentro del body JSON
    @PutMapping("/clientes")
    public ResponseEntity<Cliente> actualizarCliente(@RequestBody Cliente cliente) {
        Cliente actualizado = clienteService.update(cliente);
        return ResponseEntity.ok(actualizado);
    }

    // ── DELETE /clientes ─────────────────────────────────────────────────────
    // El cliente a eliminar viene en el body JSON
    @DeleteMapping("/clientes")
    public ResponseEntity<Void> eliminarCliente(@RequestBody Cliente cliente) {
        clienteService.delete(cliente);
        return ResponseEntity.noContent().build();
    }

    // ── GET /clientes/regiones ───────────────────────────────────────────────
    @GetMapping("/clientes/regiones")
    public ResponseEntity<List<Region>> listarRegiones() {
        List<Region> regiones = clienteService.findAllRegiones();
        return ResponseEntity.ok(regiones);
    }
}
