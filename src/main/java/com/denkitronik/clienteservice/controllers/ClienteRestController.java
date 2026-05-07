package com.denkitronik.clienteservice.controllers;

import com.denkitronik.clienteservice.entities.Cliente;
import com.denkitronik.clienteservice.entities.Region;
import com.denkitronik.clienteservice.services.IClienteService;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataAccessException;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/${api.version}/cliente-service")
@CrossOrigin(origins = {"http://localhost:4200"})
public class ClienteRestController {

    @Autowired
    private IClienteService clienteService;

    // GET /clientes — lista sin paginar (compatible con el frontend)
    @GetMapping("/clientes")
    public ResponseEntity<List<Cliente>> listarClientes() {
        return ResponseEntity.ok(clienteService.findAll());
    }

    // GET /clientes/page/{page} — lista paginada, 4 elementos por página
    @GetMapping("/clientes/page/{page}")
    public ResponseEntity<Page<Cliente>> listarClientesPaginado(@PathVariable Integer page) {
        Page<Cliente> clientes = clienteService.findAll(PageRequest.of(page, 4));
        return ResponseEntity.ok(clientes);
    }

    // GET /clientes/{id}
    @GetMapping("/clientes/{id}")
    public ResponseEntity<?> buscarCliente(@PathVariable Long id) {
        Optional<Cliente> cliente = clienteService.findById(id);
        if (!cliente.isPresent()) {
            Map<String, Object> error = new HashMap<>();
            error.put("mensaje", "El cliente ID: ".concat(id.toString())
                      .concat(" no existe en la base de datos"));
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(error);
        }
        return ResponseEntity.ok(cliente.get());
    }

    // POST /clientes
    @PostMapping("/clientes")
    public ResponseEntity<?> crearCliente(@Valid @RequestBody Cliente cliente,
                                          BindingResult result) {
        if (result.hasErrors()) {
            return ResponseEntity.badRequest().body(construirErrores(result));
        }
        try {
            Cliente nuevo = clienteService.save(cliente);
            return ResponseEntity.status(HttpStatus.CREATED).body(nuevo);
        } catch (DataAccessException e) {
            Map<String, Object> error = new HashMap<>();
            error.put("mensaje", "Error al guardar el cliente en la base de datos");
            error.put("error", e.getMostSpecificCause().getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(error);
        }
    }

    // PUT /clientes/{id}
    @PutMapping("/clientes/{id}")
    public ResponseEntity<?> actualizarCliente(@Valid @RequestBody Cliente cliente,
                                               BindingResult result,
                                               @PathVariable Long id) {
        if (result.hasErrors()) {
            return ResponseEntity.badRequest().body(construirErrores(result));
        }
        if (!clienteService.findById(id).isPresent()) {
            Map<String, Object> error = new HashMap<>();
            error.put("mensaje", "El cliente ID: ".concat(id.toString())
                      .concat(" no existe en la base de datos"));
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(error);
        }
        try {
            return ResponseEntity.status(HttpStatus.CREATED).body(clienteService.update(id, cliente));
        } catch (DataAccessException e) {
            Map<String, Object> error = new HashMap<>();
            error.put("mensaje", "Error al actualizar el cliente en la base de datos");
            error.put("error", e.getMostSpecificCause().getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(error);
        }
    }

    // DELETE /clientes/{id}
    @DeleteMapping("/clientes/{id}")
    public ResponseEntity<?> eliminarCliente(@PathVariable Long id) {
        try {
            clienteService.delete(id);
            return ResponseEntity.noContent().build();
        } catch (DataAccessException e) {
            Map<String, Object> error = new HashMap<>();
            error.put("mensaje", "Error al eliminar el cliente en la base de datos");
            error.put("error", e.getMostSpecificCause().getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(error);
        }
    }

    // GET /clientes/regiones
    @GetMapping("/clientes/regiones")
    public ResponseEntity<List<Region>> listarRegiones() {
        return ResponseEntity.ok(clienteService.findAllRegiones());
    }

    // ── Método auxiliar ───────────────────────────────────────────────────────
    private Map<String, Object> construirErrores(BindingResult result) {
        Map<String, Object> errores = new HashMap<>();
        List<String> listaErrores = result.getFieldErrors()
            .stream()
            .map(fe -> "El campo '" + fe.getField() + "' " + fe.getDefaultMessage())
            .collect(Collectors.toList());
        errores.put("errors", listaErrores);
        return errores;
    }
}
