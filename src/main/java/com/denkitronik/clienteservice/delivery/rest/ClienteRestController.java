package com.denkitronik.clienteservice.delivery.rest;

import com.denkitronik.clienteservice.delivery.exception.ApiErrorResponse;
import com.denkitronik.clienteservice.domain.entities.Cliente;
import com.denkitronik.clienteservice.domain.entities.Region;
import com.denkitronik.clienteservice.domain.services.IClienteService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/${api.version}/cliente-service")
@CrossOrigin(origins = {"http://localhost:4200"})
@Tag(name = "Clientes", description = "CRUD de clientes y consulta de regiones")
@SecurityRequirement(name = "bearerAuth")
public class ClienteRestController {

    @Autowired
    private IClienteService clienteService;

    // ─── GET /clientes ────────────────────────────────────────────────────────

    @Operation(summary = "Listar todos los clientes",
               description = "Devuelve la lista completa de clientes. Requiere rol USER o ADMIN.")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Lista de clientes"),
        @ApiResponse(responseCode = "401", description = "Token JWT ausente o inválido",
                     content = @Content(schema = @Schema(implementation = ApiErrorResponse.class))),
        @ApiResponse(responseCode = "403", description = "Rol insuficiente",
                     content = @Content(schema = @Schema(implementation = ApiErrorResponse.class)))
    })
    @GetMapping("/clientes")
    @PreAuthorize("hasAnyRole('USER','ADMIN')")
    public ResponseEntity<List<Cliente>> listarClientes() {
        return ResponseEntity.ok(clienteService.findAll());
    }

    // ─── GET /clientes/page/{page} ────────────────────────────────────────────

    @Operation(summary = "Listar clientes paginado",
               description = "Devuelve 4 clientes por página. page=0 es la primera página.")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Página de clientes"),
        @ApiResponse(responseCode = "401", description = "Token JWT ausente o inválido",
                     content = @Content(schema = @Schema(implementation = ApiErrorResponse.class)))
    })
    @GetMapping("/clientes/page/{page}")
    @PreAuthorize("hasAnyRole('USER','ADMIN')")
    public ResponseEntity<Page<Cliente>> listarClientesPaginado(
            @Parameter(description = "Número de página (0-based)", example = "0")
            @PathVariable Integer page) {
        return ResponseEntity.ok(clienteService.findAll(PageRequest.of(page, 4)));
    }

    // ─── GET /clientes/{id} ───────────────────────────────────────────────────

    @Operation(summary = "Buscar cliente por ID")
    @ApiResponses({
        @ApiResponse(responseCode = "200", description = "Cliente encontrado"),
        @ApiResponse(responseCode = "404", description = "Cliente no encontrado",
                     content = @Content(schema = @Schema(implementation = ApiErrorResponse.class))),
        @ApiResponse(responseCode = "401", description = "Token JWT ausente o inválido",
                     content = @Content(schema = @Schema(implementation = ApiErrorResponse.class)))
    })
    @GetMapping("/clientes/{id}")
    @PreAuthorize("hasAnyRole('USER','ADMIN')")
    public ResponseEntity<Cliente> buscarCliente(
            @Parameter(description = "ID del cliente", example = "1")
            @PathVariable Long id) {
        return ResponseEntity.ok(clienteService.findById(id));
    }

    // ─── POST /clientes ───────────────────────────────────────────────────────

    @Operation(summary = "Crear nuevo cliente",
               description = "Crea un cliente. Requiere rol ADMIN.")
    @ApiResponses({
        @ApiResponse(responseCode = "201", description = "Cliente creado",
                     content = @Content(mediaType = MediaType.APPLICATION_JSON_VALUE,
                                        schema = @Schema(implementation = Cliente.class))),
        @ApiResponse(responseCode = "400", description = "Datos de entrada inválidos"),
        @ApiResponse(responseCode = "401", description = "Token JWT ausente o inválido",
                     content = @Content(schema = @Schema(implementation = ApiErrorResponse.class))),
        @ApiResponse(responseCode = "403", description = "Se requiere rol ADMIN",
                     content = @Content(schema = @Schema(implementation = ApiErrorResponse.class)))
    })
    @PostMapping("/clientes")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> crearCliente(@Valid @RequestBody Cliente cliente,
                                          BindingResult result) {
        if (result.hasErrors()) {
            return ResponseEntity.badRequest().body(construirErrores(result));
        }
        return ResponseEntity.status(HttpStatus.CREATED).body(clienteService.save(cliente));
    }

    // ─── PUT /clientes/{id} ───────────────────────────────────────────────────

    @Operation(summary = "Actualizar cliente",
               description = "Actualiza los datos de un cliente existente. Requiere rol ADMIN.")
    @ApiResponses({
        @ApiResponse(responseCode = "201", description = "Cliente actualizado"),
        @ApiResponse(responseCode = "400", description = "Datos de entrada inválidos"),
        @ApiResponse(responseCode = "401", description = "Token JWT ausente o inválido",
                     content = @Content(schema = @Schema(implementation = ApiErrorResponse.class))),
        @ApiResponse(responseCode = "403", description = "Se requiere rol ADMIN",
                     content = @Content(schema = @Schema(implementation = ApiErrorResponse.class))),
        @ApiResponse(responseCode = "404", description = "Cliente no encontrado",
                     content = @Content(schema = @Schema(implementation = ApiErrorResponse.class)))
    })
    @PutMapping("/clientes/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> actualizarCliente(@Valid @RequestBody Cliente cliente,
                                               BindingResult result,
                                               @Parameter(description = "ID del cliente", example = "1")
                                               @PathVariable Long id) {
        if (result.hasErrors()) {
            return ResponseEntity.badRequest().body(construirErrores(result));
        }
        Cliente actual = clienteService.findById(id);
        actual.setNombre(cliente.getNombre());
        actual.setApellido(cliente.getApellido());
        actual.setEmail(cliente.getEmail());
        actual.setRegion(cliente.getRegion());
        actual.setFoto(cliente.getFoto());
        return ResponseEntity.status(HttpStatus.CREATED).body(clienteService.save(actual));
    }

    // ─── DELETE /clientes/{id} ────────────────────────────────────────────────

    @Operation(summary = "Eliminar cliente",
               description = "Elimina un cliente por ID. Requiere rol ADMIN.")
    @ApiResponses({
        @ApiResponse(responseCode = "204", description = "Cliente eliminado"),
        @ApiResponse(responseCode = "401", description = "Token JWT ausente o inválido",
                     content = @Content(schema = @Schema(implementation = ApiErrorResponse.class))),
        @ApiResponse(responseCode = "403", description = "Se requiere rol ADMIN",
                     content = @Content(schema = @Schema(implementation = ApiErrorResponse.class))),
        @ApiResponse(responseCode = "404", description = "Cliente no encontrado",
                     content = @Content(schema = @Schema(implementation = ApiErrorResponse.class)))
    })
    @DeleteMapping("/clientes/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<Void> eliminarCliente(
            @Parameter(description = "ID del cliente", example = "1")
            @PathVariable Long id) {
        clienteService.delete(id);
        return ResponseEntity.noContent().build();
    }

    // ─── GET /clientes/regiones ───────────────────────────────────────────────

    @Operation(summary = "Listar regiones disponibles",
               description = "Devuelve todas las regiones. Necesaria para asignar región al crear un cliente.")
    @ApiResponse(responseCode = "200", description = "Lista de regiones")
    @GetMapping("/clientes/regiones")
    @PreAuthorize("hasAnyRole('USER','ADMIN')")
    public ResponseEntity<List<Region>> listarRegiones() {
        return ResponseEntity.ok(clienteService.findAllRegiones());
    }

    // ─── Helpers ──────────────────────────────────────────────────────────────

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
