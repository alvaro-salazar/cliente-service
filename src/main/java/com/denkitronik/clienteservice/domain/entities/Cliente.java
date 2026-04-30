package com.denkitronik.clienteservice.domain.entities;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.persistence.*;
import jakarta.validation.constraints.*;
import lombok.Getter;
import lombok.Setter;
import java.util.Date;

@Entity
@Table(name = "clientes")
@Getter
@Setter
@Schema(description = "Entidad cliente")
public class Cliente {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Schema(description = "ID generado automáticamente", example = "1",
            accessMode = Schema.AccessMode.READ_ONLY)
    private Long id;

    @NotEmpty(message = "El nombre no puede estar vacío")
    @Size(min = 2, max = 20, message = "El nombre debe tener entre 2 y 20 caracteres")
    @Column(nullable = false)
    @Schema(description = "Nombre del cliente", example = "Ada")
    private String nombre;

    @NotEmpty(message = "El apellido no puede estar vacío")
    @Schema(description = "Apellido del cliente", example = "Lovelace")
    private String apellido;

    @NotEmpty(message = "El email no puede estar vacío")
    @Email(message = "Debe ser una dirección de email válida")
    @Column(nullable = false, unique = true)
    @Schema(description = "Email único del cliente", example = "ada@babbage.uk")
    private String email;

    @Column(name = "create_at")
    @Temporal(TemporalType.DATE)
    @Schema(description = "Fecha de creación (asignada automáticamente)",
            accessMode = Schema.AccessMode.READ_ONLY)
    private Date createAt;

    @Schema(description = "Nombre del archivo de foto", example = "ada.jpg")
    private String foto;

    @NotNull(message = "La región es obligatoria")
    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "region_id")
    @JsonIgnoreProperties({"hibernateLazyInitializer", "handler"})
    @Schema(description = "Región a la que pertenece el cliente")
    private Region region;

    @PrePersist
    public void prePersist() {
        createAt = new Date();
    }
}
