# Rama de archivo: arquitectura limpia sobre Spring Boot 3.3.5

Esta rama **no es una version anterior de `main`**: es una base de codigo distinta que
comparte nombre de repositorio y raiz de paquetes. Confundirlas es facil, asi que conviene
tener claro que es cada una antes de tocar nada.

| | `main` | esta rama |
|---|---|---|
| Spring Boot | 4.1.2 | 3.3.5 |
| Estructura | por capas: `controllers/`, `entities/`, `services/` | limpia: `delivery/`, `domain/` |
| Configuracion | lee `DB_URL`, `KEYCLOAK_ISSUER_URI`, `JPA_DDL`… del entorno | valores fijos apuntando a `localhost` |
| Pruebas | una, con Testcontainers | cinco: unitarias, web, JPA e integracion |
| Realm de Keycloak | no incluido | `keycloak/realm-export.json` |

**Las imagenes publicadas en Docker Hub (`cliente-service:keycloak`, `codelab-06` y sus
variantes) salen de `main`, no de aqui.** Se comprueba mirando las variables de entorno: los
manifiestos del codelab de Kubernetes inyectan `DB_URL`, `DB_USERNAME`, `DB_PASSWORD`,
`JPA_DDL`, `KEYCLOAK_ISSUER_URI` y `KEYCLOAK_JWK_SET_URI`, y solo `main` las lee. Esta rama
tiene la base de datos escrita a mano contra `localhost`, de modo que no funcionaria dentro
del cluster.

**Por que se conserva.** Dos cosas de aqui no existen en `main` y valen por si mismas:

1. `keycloak/realm-export.json` — el realm `curso-springboot` completo, con los clientes
   `cliente-service` y `angular-client` y los roles `ADMIN` y `USER`. El codelab de
   Kubernetes crea todo eso con una decena de ordenes de `kcadm.sh`; este archivo lo deja en
   una importacion.
2. La suite de pruebas en cuatro niveles, que es material de ensenanza para un codelab de
   pruebas que todavia no existe.

**Esta rama no se fusiona con `main`.** No comparten historia ni estructura, y un merge
destruiria la que funciona en el cluster.
