package com.denkitronik.clienteservice.delivery.exception;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import java.util.HashMap;
import java.util.Map;

@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    // ── 404 Not Found ─────────────────────────────────────────
    @ExceptionHandler(ClienteNotFoundException.class)
    public ResponseEntity<ApiErrorResponse> manejarNotFound(
            ClienteNotFoundException ex) {

        log.warn("Cliente no encontrado: id={}", ex.getId());

        ApiErrorResponse respuesta = new ApiErrorResponse(
                HttpStatus.NOT_FOUND.value(),
                "Not Found",
                ex.getMessage()
        );
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(respuesta);
    }

    // ── 500 Internal Server Error ─────────────────────────────
    @ExceptionHandler(ClienteServiceException.class)
    public ResponseEntity<ApiErrorResponse> manejarServiceException(
            ClienteServiceException ex) {

        log.error("Error en el servicio de clientes", ex);

        ApiErrorResponse respuesta = new ApiErrorResponse(
                HttpStatus.INTERNAL_SERVER_ERROR.value(),
                "Internal Server Error",
                "Error interno del servidor. Por favor intenta más tarde."
        );
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(respuesta);
    }

    // ── 400 Bad Request (validaciones @Valid) ─────────────────
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<Map<String, String>> manejarValidacion(
            MethodArgumentNotValidException ex) {

        Map<String, String> errores = new HashMap<>();
        ex.getBindingResult()
          .getAllErrors()
          .forEach(error -> {
              String campo   = ((FieldError) error).getField();
              String mensaje = error.getDefaultMessage();
              errores.put(campo, mensaje);
          });

        log.debug("Errores de validación: {}", errores);

        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errores);
    }

    // ── 403 Forbidden — @PreAuthorize denegó el acceso ───────
    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ApiErrorResponse> manejarAccesoDenegado(AccessDeniedException ex) {
        log.warn("Acceso denegado: {}", ex.getMessage());
        return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(new ApiErrorResponse(403, "Forbidden",
                      "No tienes permiso para realizar esta operación."));
    }

    // ── 401 Unauthorized — token ausente o inválido ───────────
    @ExceptionHandler(AuthenticationException.class)
    public ResponseEntity<ApiErrorResponse> manejarAutenticacion(AuthenticationException ex) {
        log.warn("Autenticación requerida: {}", ex.getMessage());
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(new ApiErrorResponse(401, "Unauthorized", "Autenticación requerida."));
    }

    // ── 500 genérico para cualquier excepción no manejada ─────
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiErrorResponse> manejarExcepcionGenerica(
            Exception ex) {

        log.error("Excepción no manejada", ex);

        ApiErrorResponse respuesta = new ApiErrorResponse(
                HttpStatus.INTERNAL_SERVER_ERROR.value(),
                "Internal Server Error",
                "Error inesperado. Por favor contacta al administrador."
        );
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(respuesta);
    }
}
