/*
  sistema_contratos.c
  Sistema simple de gestión de Clientes, Servicios y Contratos usando CSV.
  - Archivos: clientes.csv, servicios.csv, contratos.csv, contrato_servicios.csv, usuarios.csv
  - Autenticación: usuarios.csv (user,hash_salt_hex)
  - Relación N:N contratos<->servicios via contrato_servicios.csv
  - Validación de fechas YYYY-MM-DD (fecha_fin > fecha_inicio)
  - Evita duplicados de ID
  - Backup simple opcional
  ------------------------------
  NOTA: El "hash" usado aquí (djb2 + sal) es para evitar texto plano, pero NO sustituye
  a soluciones criptográficas modernas. Para producción use bcrypt/argon2/OpenSSL.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifdef _WIN32
#include <direct.h> /* _mkdir */
#else
#include <sys/types.h>
#include <sys/stat.h> /* mkdir */
#endif

#define MAX_NOMBRE 100
#define MAX_ID 30
#define MAX_LINEA 512
#define SALT_LEN 8

/* ESTRUCTURAS  */
typedef struct {
    char id[MAX_ID];
    char nombre[MAX_NOMBRE];
    char contacto[MAX_NOMBRE];
    char telefono[30];
    char correo[80];
    char direccion[150];
} Cliente;

typedef struct {
    char id[MAX_ID];
    char nombre[MAX_NOMBRE];
    char descripcion[200];
    float costo;
    char estado[30]; 
} Servicio;

typedef struct {
    char id[MAX_ID];
    char idCliente[MAX_ID];
    char fechaInicio[11]; // YYYY-MM-DD
    char fechaFin[11];
} Contrato;

/*UTILIDADES */

void limpiarBuffer() {
    int c;
    while ((c = getchar()) != '\n' && c != EOF);
}

void trim_newline(char *s) {
    size_t L = strlen(s);
    while (L > 0 && (s[L-1] == '\n' || s[L-1] == '\r')) {
        s[L-1] = '\0';
        L--;
    }
}

unsigned long djb2_hash(const char *str) {
    unsigned long hash = 5381;
    int c;
    while ((c = *str++))
        hash = ((hash << 5) + hash) + c;
    return hash;
}

/* genera sal aleatoria simple (hex) */
void generar_salt_hex(char *out_hex) {
    const char *hex = "0123456789abcdef";
    for (int i = 0; i < SALT_LEN; i++) {
        unsigned int r = rand() % 16;
        out_hex[i*2] = hex[r];
        r = rand() % 16;
        out_hex[i*2+1] = hex[r];
    }
    out_hex[SALT_LEN*2] = '\0';
}

void hash_password_with_salt(const char *pass, const char *salt_hex, char *out_hash_hex) {
    char buff[512];
    snprintf(buff, sizeof(buff), "%s%s", pass, salt_hex);
    unsigned long h = djb2_hash(buff);
    // convertir a hex
    snprintf(out_hash_hex, 32, "%lx", h);
}

int check_password(const char *password, const char *stored_hash_hex, const char *stored_salt_hex) {
    char computed[32];
    hash_password_with_salt(password, stored_salt_hex, computed);
    return strcmp(computed, stored_hash_hex) == 0;
}

/* FECHAS */

/* parsea "YYYY-MM-DD" -> tm struct (ignora hora) */
int parse_fecha(const char *s, struct tm *out) {
    if (!s || strlen(s) != 10) return 0;
    int y,m,d;
    if (sscanf(s, "%4d-%2d-%2d", &y, &m, &d) != 3) return 0;
    if (m < 1 || m > 12 || d < 1 || d > 31) return 0;
    memset(out, 0, sizeof(struct tm));
    out->tm_year = y - 1900;
    out->tm_mon = m - 1;
    out->tm_mday = d;
    return 1;
}

/* retorna 1 si fecha2 > fecha1 */
int fecha_menor(const char *fecha1, const char *fecha2) {
    struct tm t1, t2;
    if (!parse_fecha(fecha1, &t1) || !parse_fecha(fecha2, &t2))
        return 0; // invalidas -> false
    time_t a = mktime(&t1);
    time_t b = mktime(&t2);
    return difftime(b,a) > 0;
}

/* valida formato YYYY-MM-DD */
int fecha_valida(const char *s) {
    struct tm t;
    return parse_fecha(s, &t);
}

/* CARGA Y GUARDADO CSV */

/* Clientes */
int cargarClientes(Cliente clientes[], int max) {
    FILE *f = fopen("clientes.csv", "r");
    if (!f) return 0;
    char linea[MAX_LINEA];
    int n = 0;
    fgets(linea, MAX_LINEA, f); // header
    while (fgets(linea, MAX_LINEA, f) && n < max) {
        trim_newline(linea);
        sscanf(linea, "%29[^,],%99[^,],%79[^,],%29[^,],%149[^\n]",
               clientes[n].id,
               clientes[n].nombre,
               clientes[n].correo,
               clientes[n].telefono,
               clientes[n].direccion);
        
        n++;
    }
    fclose(f);
    return n;
}

void guardarClientesCSV(Cliente clientes[], int n) {
    FILE *f = fopen("clientes.csv", "w");
    if (!f) { printf("Error guardando clientes.\n"); return; }
    fprintf(f, "ID,Nombre,Correo,Telefono,Direccion\n");
    for (int i = 0; i < n; i++) {
        fprintf(f, "%s,%s,%s,%s,%s\n",
                clientes[i].id,
                clientes[i].nombre,
                clientes[i].correo,
                clientes[i].telefono,
                clientes[i].direccion);
    }
    fclose(f);
}

/* Servicios */
int cargarServicios(Servicio servicios[], int max) {
    FILE *f = fopen("servicios.csv", "r");
    if (!f) return 0;
    char linea[MAX_LINEA];
    int n = 0;
    fgets(linea, MAX_LINEA, f); // header
    while (fgets(linea, MAX_LINEA, f) && n < max) {
        trim_newline(linea);
        // id,nombre,descripcion,costo,estado
        char costo_str[40];
        sscanf(linea, "%29[^,],%99[^,],%199[^,],%39[^,],%29[^\n]",
               servicios[n].id,
               servicios[n].nombre,
               servicios[n].descripcion,
               costo_str,
               servicios[n].estado);
        servicios[n].costo = atof(costo_str);
        n++;
    }
    fclose(f);
    return n;
}

void guardarServiciosCSV(Servicio servicios[], int n) {
    FILE *f = fopen("servicios.csv", "w");
    if (!f) { printf("Error guardando servicios.\n"); return; }
    fprintf(f, "ID,Nombre,Descripcion,Costo,Estado\n");
    for (int i = 0; i < n; i++) {
        fprintf(f, "%s,%s,%s,%.2f,%s\n",
                servicios[i].id,
                servicios[i].nombre,
                servicios[i].descripcion,
                servicios[i].costo,
                servicios[i].estado);
    }
    fclose(f);
}

/* Contratos */
int cargarContratos(Contrato contratos[], int max) {
    FILE *f = fopen("contratos.csv", "r");
    if (!f) return 0;
    char linea[MAX_LINEA];
    int n = 0;
    fgets(linea, MAX_LINEA, f);
    while (fgets(linea, MAX_LINEA, f) && n < max) {
        trim_newline(linea);
        sscanf(linea, "%29[^,],%29[^,],%10[^,],%10[^\n]",
               contratos[n].id,
               contratos[n].idCliente,
               contratos[n].fechaInicio,
               contratos[n].fechaFin);
        n++;
    }
    fclose(f);
    return n;
}

void guardarContratosCSV(Contrato contratos[], int n) {
    FILE *f = fopen("contratos.csv", "w");
    if (!f) { printf("Error guardando contratos.\n"); return; }
    fprintf(f, "ID,IDCliente,FechaInicio,FechaFin\n");
    for (int i = 0; i < n; i++) {
        fprintf(f, "%s,%s,%s,%s\n",
                contratos[i].id,
                contratos[i].idCliente,
                contratos[i].fechaInicio,
                contratos[i].fechaFin);
    }
    fclose(f);
}

/* contrato_servicios.csv -> líneas: idContrato,idServicio */
int asociarServicioAContrato(const char *idContrato, const char *idServicio) {
    FILE *f = fopen("contrato_servicios.csv", "a");
    if (!f) return 0;
    // si archivo vacío, escribir header
    long pos = ftell(f);
    if (pos == 0) fprintf(f, "IDContrato,IDServicio\n");
    fprintf(f, "%s,%s\n", idContrato, idServicio);
    fclose(f);
    return 1;
}

/* verifica si contrato tiene al menos un servicio */
int contrato_tiene_servicio(const char *idContrato) {
    FILE *f = fopen("contrato_servicios.csv", "r");
    if (!f) return 0;
    char linea[MAX_LINEA];
    fgets(linea, MAX_LINEA, f); // header maybe
    while (fgets(linea, MAX_LINEA, f)) {
        char c1[MAX_ID], c2[MAX_ID];
        trim_newline(linea);
        if (sscanf(linea, "%29[^,],%29[^\n]", c1, c2) == 2) {
            if (strcmp(c1, idContrato) == 0) {
                fclose(f);
                return 1;
            }
        }
    }
    fclose(f);
    return 0;
}

/* elimina asociaciones de un contrato (al eliminar contrato) */
void eliminar_asociaciones_contrato(const char *idContrato) {
    FILE *f = fopen("contrato_servicios.csv", "r");
    if (!f) return;
    FILE *tmp = fopen("tmp_cs.csv", "w");
    char linea[MAX_LINEA];
    if (!tmp) { fclose(f); return; }
    fgets(linea, MAX_LINEA, f); // header
    fprintf(tmp, "IDContrato,IDServicio\n");
    while (fgets(linea, MAX_LINEA, f)) {
        char c1[MAX_ID], c2[MAX_ID];
        trim_newline(linea);
        if (sscanf(linea, "%29[^,],%29[^\n]", c1, c2) == 2) {
            if (strcmp(c1, idContrato) != 0)
                fprintf(tmp, "%s,%s\n", c1, c2);
        }
    }
    fclose(f);
    fclose(tmp);
    remove("contrato_servicios.csv");
    rename("tmp_cs.csv", "contrato_servicios.csv");
}

/*AUTENTICACIÓN (usuarios.csv) */
/* formato usuarios.csv:
   usuario,hash_hex,salt_hex
*/
int existe_usuario(const char *usuario) {
    FILE *f = fopen("usuarios.csv", "r");
    if (!f) return 0;
    char linea[MAX_LINEA];
    fgets(linea, MAX_LINEA, f);
    while (fgets(linea, MAX_LINEA, f)) {
        char user[80], hash[40], salt[40];
        trim_newline(linea);
        if (sscanf(linea, "%79[^,],%39[^,],%39[^\n]", user, hash, salt) == 3) {
            if (strcmp(user, usuario) == 0) { fclose(f); return 1; }
        }
    }
    fclose(f);
    return 0;
}

/* registrar usuario (crea usuarios.csv si no existe) */
int registrar_usuario(const char *usuario, const char *password) {
    if (existe_usuario(usuario)) return 0;
    FILE *f = fopen("usuarios.csv", "a");
    if (!f) return 0;
    long pos = ftell(f);
    if (pos == 0) fprintf(f, "usuario,hash,salt\n");
    char salt_hex[SALT_LEN*2+1];
    generar_salt_hex(salt_hex);
    char hash_hex[32];
    hash_password_with_salt(password, salt_hex, hash_hex);
    fprintf(f, "%s,%s,%s\n", usuario, hash_hex, salt_hex);
    fclose(f);
    return 1;
}

int autenticar() {
    char usuario[80];
    char password[80];
    printf("=== ACCESO AL SISTEMA ===\n");
    printf("Usuario: ");
    if (!fgets(usuario, sizeof(usuario), stdin)) return 0;
    trim_newline(usuario);
    printf("Contrasena: ");
    if (!fgets(password, sizeof(password), stdin)) return 0;
    trim_newline(password);

    FILE *f = fopen("usuarios.csv", "r");
    if (!f) {
        printf("No existe archivo de usuarios.\n");
        registrar_usuario("admin", "1234");
        f = fopen("usuarios.csv", "r");
        if (!f) return 0;
    }

    char linea[MAX_LINEA];
    fgets(linea, MAX_LINEA, f); // header
    while (fgets(linea, MAX_LINEA, f)) {
        char user[80], hash[40], salt[40];
        trim_newline(linea);
        if (sscanf(linea, "%79[^,],%39[^,],%39[^\n]", user, hash, salt) == 3) {
            if (strcmp(user, usuario) == 0) {
                fclose(f);
                if (check_password(password, hash, salt)) return 1;
                else return 0;
            }
        }
    }
    fclose(f);
    return 0;
}

/*CRUD CLIENTES*/

void crear_cliente() {
    Cliente clientes[1000];
    int n = cargarClientes(clientes, 1000);

    Cliente c;
    printf("ID (alfanumerico): ");
    fgets(c.id, MAX_ID, stdin); trim_newline(c.id);

    // evita duplicados
    for (int i = 0; i < n; i++) {
        if (strcmp(clientes[i].id, c.id) == 0) {
            printf("ID ya existe. Operacion cancelada.\n");
            return;
        }
    }

    printf("Nombre: ");
    fgets(c.nombre, MAX_NOMBRE, stdin); trim_newline(c.nombre);
    printf("Correo: ");
    fgets(c.correo, sizeof(c.correo), stdin); trim_newline(c.correo);
    printf("Telefono: ");
    fgets(c.telefono, sizeof(c.telefono), stdin); trim_newline(c.telefono);
    printf("Direccion: ");
    fgets(c.direccion, sizeof(c.direccion), stdin); trim_newline(c.direccion);

    clientes[n++] = c;
    guardarClientesCSV(clientes, n);
    printf("Cliente registrado.\n");
}

void listar_clientes() {
    Cliente clientes[1000];
    int n = cargarClientes(clientes, 1000);
    if (n == 0) { printf("No hay clientes.\n"); return; }
    printf("=== Clientes ===\n");
    for (int i = 0; i < n; i++) {
        printf("%s | %s | %s | %s | %s\n", clientes[i].id, clientes[i].nombre, clientes[i].correo, clientes[i].telefono, clientes[i].direccion);
    }
}

void eliminar_cliente() {
    Cliente clientes[1000];
    int n = cargarClientes(clientes, 1000);
    char id[MAX_ID];
    printf("ID cliente a eliminar: ");
    fgets(id, sizeof(id), stdin); trim_newline(id);

    // verificar que no exista contrato asociado
    Contrato contratos[1000];
    int m = cargarContratos(contratos, 1000);
    for (int i = 0; i < m; i++) {
        if (strcmp(contratos[i].idCliente, id) == 0) {
            printf("No se puede eliminar: cliente tiene contratos asociados.\n");
            return;
        }
    }

    int j = 0;
    int found = 0;
    for (int i = 0; i < n; i++) {
        if (strcmp(clientes[i].id, id) != 0) clientes[j++] = clientes[i];
        else found = 1;
    }
    if (!found) { printf("Cliente no encontrado.\n"); return; }
    guardarClientesCSV(clientes, j);
    printf("Cliente eliminado.\n");
}

/* CRUD SERVICIOS */

void crear_servicio() {
    Servicio servicios[1000];
    int n = cargarServicios(servicios, 1000);
    Servicio s;
    printf("ID servicio: ");
    fgets(s.id, MAX_ID, stdin); trim_newline(s.id);
    for (int i = 0; i < n; i++) if (strcmp(servicios[i].id, s.id) == 0) {
        printf("ID ya existe.\n"); return;
    }
    printf("Nombre: ");
    fgets(s.nombre, MAX_NOMBRE, stdin); trim_newline(s.nombre);
    printf("Descripcion: ");
    fgets(s.descripcion, sizeof(s.descripcion), stdin); trim_newline(s.descripcion);
    printf("Costo: ");
    char tmp[40]; fgets(tmp, sizeof(tmp), stdin); s.costo = atof(tmp);
    printf("Estado (activo/inactivo): ");
    fgets(s.estado, sizeof(s.estado), stdin); trim_newline(s.estado);

    servicios[n++] = s;
    guardarServiciosCSV(servicios, n);
    printf("Servicio creado.\n");
}

void listar_servicios() {
    Servicio servicios[1000];
    int n = cargarServicios(servicios, 1000);
    if (n == 0) { printf("No hay servicios.\n"); return; }

    printf("=== Servicios ===\n");

    for (int i = 0; i < n; i++) {
        printf("%s | %s | %.2f | %s | %s\n",
               servicios[i].id,
               servicios[i].nombre,
               servicios[i].costo,
               servicios[i].descripcion,  
               servicios[i].estado);       
    }
}

void eliminar_servicio() {
    Servicio servicios[1000];
    int n = cargarServicios(servicios, 1000);
    char id[MAX_ID];
    printf("ID servicio a eliminar: ");
    fgets(id, sizeof(id), stdin); trim_newline(id);

    // verificar que no esté en contrato y servicios
    FILE *f = fopen("contrato_servicios.csv", "r");
    if (f) {
        char linea[MAX_LINEA];
        fgets(linea, MAX_LINEA, f);
        while (fgets(linea, MAX_LINEA, f)) {
            char c1[MAX_ID], c2[MAX_ID];
            trim_newline(linea);
            if (sscanf(linea, "%29[^,],%29[^\n]", c1, c2) == 2) {
                if (strcmp(c2, id) == 0) {
                    fclose(f);
                    printf("No se puede eliminar: servicio asociado a contratos.\n");
                    return;
                }
            }
        }
        fclose(f);
    }

    int j = 0; int found = 0;
    for (int i = 0; i < n; i++) {
        if (strcmp(servicios[i].id, id) != 0) servicios[j++] = servicios[i];
        else found = 1;
    }
    if (!found) { printf("Servicio no encontrado.\n"); return; }
    guardarServiciosCSV(servicios, j);
    printf("Servicio eliminado.\n");
}

/* CRUD CONTRATOS */

void crear_contrato() {
    Contrato contratos[1000];
    int n = cargarContratos(contratos, 1000);

    Cliente clientes[1000];
    int ccount = cargarClientes(clientes, 1000);
    if (ccount == 0) {
        printf("Primero registre clientes.\n");
        return;
    }

    Servicio servicios[1000];
    int scount = cargarServicios(servicios, 1000);
    if (scount == 0) {
        printf("Primero registre servicios.\n");
        return;
    }

    Contrato cont;

    // --- ID del contrato ---
    printf("ID contrato: ");

    fgets(cont.id, MAX_ID, stdin);
    trim_newline(cont.id);

    // Evitar duplicado
    for (int i = 0; i < n; i++) {
        if (strcmp(contratos[i].id, cont.id) == 0) {
            printf("ID ya existe.\n");
            return;
        }
    }

    // --- ID cliente ---
    printf("ID Cliente asociado: ");
  
    fgets(cont.idCliente, MAX_ID, stdin);
    trim_newline(cont.idCliente);

    int cliente_ok = 0;
    for (int i = 0; i < ccount; i++)
        if (strcmp(clientes[i].id, cont.idCliente) == 0)
            cliente_ok = 1;

    if (!cliente_ok) {
        printf("Cliente no existe.\n");
        return;
    }

    // --- Fecha inicio ---
    printf("Fecha inicio (AAAA-MM-DD): ");
   
    fgets(cont.fechaInicio, sizeof(cont.fechaInicio), stdin);
    trim_newline(cont.fechaInicio);

    if (!fecha_valida(cont.fechaInicio)) {
        printf("Fecha inicio invalida.\n");
        return;
    }

    // --- Fecha fin ---
    printf("Fecha fin (AAAA-MM-DD): ");
     limpiarBuffer();  
    fgets(cont.fechaFin, sizeof(cont.fechaFin), stdin);
    trim_newline(cont.fechaFin);

    if (!fecha_valida(cont.fechaFin)) {
        printf("Fecha fin invalida.\n");
        return;
    }

    if (!fecha_menor(cont.fechaInicio, cont.fechaFin)) {
        printf("Fecha fin debe ser posterior a inicio.\n");
        return;
    }

    // --- Servicios asociados ---
    printf("Asociar servicios al contrato (ej: S01,S02): ");
    limpiarBuffer();   // NECESARIO
    char linea[MAX_LINEA];
    fgets(linea, MAX_LINEA, stdin);
    trim_newline(linea);

    if (strlen(linea) == 0) {
        printf("Debe asociar al menos un servicio.\n");
        return;
    }

    // Verificar servicios existentes
    char linea_copy[MAX_LINEA];
    strcpy(linea_copy, linea);

    char *token = strtok(linea_copy, ",");
    int any = 0;

    while (token != NULL) {
        while (*token == ' ') token++;  // eliminar espacios
        int existe = 0;
        for (int i = 0; i < scount; i++)
            if (strcmp(servicios[i].id, token) == 0)
                existe = 1;

        if (!existe) {
            printf("Servicio %s no existe. Operacion cancelada.\n", token);
            return;
        }

        token = strtok(NULL, ",");
        any = 1;
    }

    if (!any) {
        printf("Debe agregar al menos un servicio.\n");
        return;
    }

    // Guardar contrato
    contratos[n++] = cont;
    guardarContratosCSV(contratos, n);

    // Guardar asociaciones
    printf("Repita los servicios para guardar (S01,S02): ");
    char servicios_line[MAX_LINEA];
    fgets(servicios_line, MAX_LINEA, stdin);
    trim_newline(servicios_line);

    token = strtok(servicios_line, ",");
    while (token != NULL) {
        while (*token == ' ') token++;
        asociarServicioAContrato(cont.id, token);
        token = strtok(NULL, ",");
    }

    printf("Contrato creado y servicios asociados.\n");
}

void listar_contratos() {
    Contrato contratos[1000];
    int n = cargarContratos(contratos, 1000);
    if (n == 0) { printf("No hay contratos.\n"); return; }
    printf("=== Contratos ===\n");
    for (int i = 0; i < n; i++) {
        printf("%s | Cliente: %s | %s -> %s\n", contratos[i].id, contratos[i].idCliente, contratos[i].fechaInicio, contratos[i].fechaFin);
    }
}

/* eliminar contrato y sus asociaciones */
void eliminar_contrato() {
    Contrato contratos[1000];
    int n = cargarContratos(contratos, 1000);
    char id[MAX_ID];
    printf("ID contrato a eliminar: ");
    fgets(id, sizeof(id), stdin); trim_newline(id);

    int j = 0; int found = 0;
    for (int i = 0; i < n; i++) {
        if (strcmp(contratos[i].id, id) != 0) contratos[j++] = contratos[i];
        else found = 1;
    }
    if (!found) { printf("Contrato no encontrado.\n"); return; }
    guardarContratosCSV(contratos, j);
    eliminar_asociaciones_contrato(id);
    printf("Contrato y asociaciones eliminadas.\n");
}

/* consulta si servicio pertenece a contrato activo */
int servicio_en_contrato_activo(const char *idServicio) {
    // recorrer contrato_servicios y contratos; verificar si algun contrato que contenga idServicio está activo hoy
    FILE *f = fopen("contrato_servicios.csv", "r");
    if (!f) return 0;
    char linea[MAX_LINEA];
    fgets(linea, MAX_LINEA, f);
    time_t now = time(NULL);
    struct tm *tn = localtime(&now);
    char hoy[11];
    snprintf(hoy, sizeof(hoy), "%04d-%02d-%02d", tn->tm_year+1900, tn->tm_mon+1, tn->tm_mday);

    while (fgets(linea, MAX_LINEA, f)) {
        char idC[MAX_ID], idS[MAX_ID];
        trim_newline(linea);
        if (sscanf(linea, "%29[^,],%29[^\n]", idC, idS) == 2) {
            if (strcmp(idS, idServicio) == 0) {
                // buscar contrato
                Contrato contratos[1000];
                int n = cargarContratos(contratos, 1000);
                for (int i = 0; i < n; i++) {
                    if (strcmp(contratos[i].id, idC) == 0) {
                        // si hoy está entre inicio y fin inclusive
                        if ((fecha_menor(contratos[i].fechaInicio, hoy) || strcmp(contratos[i].fechaInicio, hoy) == 0)
                            && (fecha_menor(hoy, contratos[i].fechaFin) || strcmp(hoy, contratos[i].fechaFin) == 0)) {
                            fclose(f);
                            return 1;
                        }
                    }
                }
            }
        }
    }
    fclose(f);
    return 0;
}

/* BACKUP SIMPLE */
void respaldo_simple() {
    time_t now = time(NULL);
    struct tm *t = localtime(&now);
    char carpeta[128];
    snprintf(carpeta, sizeof(carpeta), "respaldo_%04d%02d%02d_%02d%02d%02d",
             t->tm_year+1900, t->tm_mon+1, t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec);

#ifdef _WIN32
    _mkdir(carpeta);  // PARA WINDOWS
#else
    mkdir(carpeta, 0755);
#endif

    const char *files[] = {"clientes.csv","servicios.csv","contratos.csv",
                           "contrato_servicios.csv","usuarios.csv"};

    for (int i = 0; i < 5; i++) {
        FILE *or = fopen(files[i], "r");
        if (!or) continue;

        char destino[256];
        snprintf(destino, sizeof(destino), "%s/%s", carpeta, files[i]);

        FILE *dest = fopen(destino, "w");
        char linea[512];

        while (fgets(linea, 512, or))
            fputs(linea, dest);

        fclose(or);
        fclose(dest);
    }

    printf("Respaldo creado en carpeta %s\n", carpeta);
}


/* MENÚ PRINCIPAL */

void menu_clientes() {
    int op;
    do {
        printf("\n--- CLIENTES ---\n1. Crear cliente\n2. Listar clientes\n3. Eliminar cliente\n0. Volver\nElija: ");
        if (scanf("%d", &op) != 1) { limpiarBuffer(); op = -1; }
        limpiarBuffer();
        switch(op) {
            case 1: crear_cliente(); break;
            case 2: listar_clientes(); break;
            case 3: eliminar_cliente(); break;
            case 0: break;
            default: printf("Opcion inválida.\n");
        }
    } while (op != 0);
}

void menu_servicios() {
    int op;
    do {
        printf("\n--- SERVICIOS ---\n1. Crear servicio\n2. Listar servicios\n3. Eliminar servicio\n0. Volver\nElija: ");
        if (scanf("%d", &op) != 1) { limpiarBuffer(); op = -1; }
        limpiarBuffer();
        switch(op) {
            case 1: crear_servicio(); break;
            case 2: listar_servicios(); break;
            case 3: eliminar_servicio(); break;
            case 0: break;
            default: printf("Opcion inválida.\n");
        }
    } while (op != 0);
}

void menu_contratos() {
    int op;
    do {
        printf("\n--- CONTRATOS ---\n1. Crear contrato\n2. Listar contratos\n3. Eliminar contrato\n0. Volver\nElija: ");
        if (scanf("%d", &op) != 1) { limpiarBuffer(); op = -1; }
        limpiarBuffer();
        switch(op) {
            case 1: crear_contrato(); break;
            case 2: listar_contratos(); break;
            case 3: eliminar_contrato(); break;
            case 0: break;
            default: printf("Opcion inválida.\n");
        }
    } while (op != 0);
}

int main() {
    srand((unsigned int) time(NULL));
    if (!autenticar()) {
        printf("Acceso denegado.\n");
        return 0;
    }
    int opc; //opcion de menu principal
    do {
        printf("\n==== SISTEMA GESTION CONTRATOS ====\n");
        printf("1. Clientes\n2. Servicios\n3. Contratos\n4. Consultas rapidas\n5. Respaldo\n0. Salir\nSeleccione: ");
        if (scanf("%d", &opc) != 1) { limpiarBuffer(); opc = -1; }
        limpiarBuffer();
        switch (opc) {
            case 1: menu_clientes(); break;
            case 2: menu_servicios(); break;
            case 3: menu_contratos(); break;
            case 4: {
                printf("\n--- CONSULTAS ---\n1. Ver si servicio esta en contrato activo\n0. Volver\nElija: ");
                int s;
                if (scanf("%d", &s) != 1) { limpiarBuffer(); s = -1; }
                limpiarBuffer();
                if (s == 1) {
                    char idS[MAX_ID];
                    printf("ID servicio: ");
                    fgets(idS, sizeof(idS), stdin); trim_newline(idS);
                    if (servicio_en_contrato_activo(idS)) printf("El servicio %s se encuentra en al menos un contrato activo.\n", idS);
                    else printf("No se encontró contrato activo con ese servicio.\n");
                }
                break;
            }
            case 5: respaldo_simple(); break;
            case 0: printf("Saliendo...\n"); break;
            default: printf("Opcion invalida.\n");
        }
    } while (opc != 0);

    return 0;
}


