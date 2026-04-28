package com.denkitronik.clienteservice.delivery.rest;

import com.denkitronik.clienteservice.domain.entities.Cliente;
import com.denkitronik.clienteservice.domain.entities.Region;
import com.denkitronik.clienteservice.domain.services.IClienteService;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/${api.version}/cliente-service")
@CrossOrigin(origins = {"http://localhost:4200"})
public class ClienteRestController {

    @Autowired
    private IClienteService clienteService;

    @GetMapping("/clientes")
    public ResponseEntity<List<Cliente>> listarClientes() {
        return ResponseEntity.ok(clienteService.findAll());
    }

    @GetMapping("/clientes/page/{page}")
    public ResponseEntity<Page<Cliente>> listarClientesPaginado(@PathVariable Integer page) {
        return ResponseEntity.ok(clienteService.findAll(PageRequest.of(page, 4)));
    }

    @GetMapping("/clientes/{id}")
    public ResponseEntity<Cliente> buscarCliente(@PathVariable Long id) {
        // Si no existe: ClienteNotFoundException -> GlobalExceptionHandler -> 404
        return ResponseEntity.ok(clienteService.findById(id));
    }

    @PostMapping("/clientes")
    public ResponseEntity<?> crearCliente(@Valid @RequestBody Cliente cliente,
                                          BindingResult result) {
        if (result.hasErrors()) {
            return ResponseEntity.badRequest().body(construirErrores(result));
        }
        // Si falla el guardado: ClienteServiceException -> GlobalExceptionHandler -> 500
        return ResponseEntity.status(HttpStatus.CREATED).body(clienteService.save(cliente));
    }

    @PutMapping("/clientes/{id}")
    public ResponseEntity<?> actualizarCliente(@Valid @RequestBody Cliente cliente,
                                               BindingResult result,
                                               @PathVariable Long id) {
        if (result.hasErrors()) {
            return ResponseEntity.badRequest().body(construirErrores(result));
        }
        // findById lanza ClienteNotFoundException si no existe -> 404 automático
        Cliente actual = clienteService.findById(id);
        actual.setNombre(cliente.getNombre());
        actual.setApellido(cliente.getApellido());
        actual.setEmail(cliente.getEmail());
        actual.setRegion(cliente.getRegion());
        actual.setFoto(cliente.getFoto());
        return ResponseEntity.status(HttpStatus.CREATED).body(clienteService.save(actual));
    }

    @DeleteMapping("/clientes/{id}")
    public ResponseEntity<Void> eliminarCliente(@PathVariable Long id) {
        // delete lanza ClienteNotFoundException si no existe -> 404 automático
        clienteService.delete(id);
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/clientes/regiones")
    public ResponseEntity<List<Region>> listarRegiones() {
        return ResponseEntity.ok(clienteService.findAllRegiones());
    }

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
