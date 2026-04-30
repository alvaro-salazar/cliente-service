package com.denkitronik.clienteservice.domain.entities;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

@Entity
@Table(name = "regiones")
@Getter
@Setter
@Schema(description = "Región geográfica")
public class Region {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Schema(description = "ID de la región", example = "1")
    private Long id;

    @Schema(description = "Nombre de la región", example = "América del Sur")
    private String nombre;
}
