#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
 * Programa para demo.
 * Requiere gcc
 *
 * Compilación:
 *   gcc -O0 -g -Wall -Wextra -o vuln_demo vuln_demo.c
 *
 * Uso sin que crashee:
 *   ./vuln_demo --name Alice --fmt "Hola %s\n" --cmd "echo OK" --file ./README.txt --count 8
 */

static void usage(const char *prog) {
    printf("Uso:\n");
    printf("  %s --name <str> --fmt <str> --cmd <str> --file <path> --count <n>\n", prog);
    printf("\nEjemplo:\n");
    printf("  %s --name Alice --fmt \"Hola mundo\\n\" --cmd \"echo OK\" --file ./README.txt --count 8\n", prog);
}

int main(int argc, char **argv) {
    const char *name_arg = NULL;
    const char *fmt_arg  = NULL;
    const char *cmd_arg  = NULL;
    const char *file_arg = NULL;
    const char *count_arg = NULL;

    // VULN #1 (Input validation / OOB read): asume que cada flag tiene un valor.
    // Si alguien pasa "--name" al final, argv[i+1] puede no existir.
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--name") == 0)  name_arg  = argv[i + 1];
        if (strcmp(argv[i], "--fmt") == 0)   fmt_arg   = argv[i + 1];
        if (strcmp(argv[i], "--cmd") == 0)   cmd_arg   = argv[i + 1];
        if (strcmp(argv[i], "--file") == 0)  file_arg  = argv[i + 1];
        if (strcmp(argv[i], "--count") == 0) count_arg = argv[i + 1];
    }

    if (!name_arg || !fmt_arg || !cmd_arg || !file_arg || !count_arg) {
        usage(argv[0]);
        return 1;
    }

    // -----------------------------
    // VULN #2 (Stack-based buffer overflow): copia sin límites.
    // CWE-121 / CWE-120
    char name_buf[32];
    strcpy(name_buf, name_arg); // <-- overflow si name_arg > 31 chars

    // -----------------------------
    // VULN #3 (Format string vulnerability): user-controlled format string.
    // CWE-134
    printf(fmt_arg);            // <-- si fmt_arg contiene %x/%n/etc, es peligroso
    printf("\n");

    // -----------------------------
    // VULN #4 (Command injection): ejecuta un comando controlado por el usuario.
    // CWE-78
    int rc = system(cmd_arg);   // <-- cmd_arg puede incluir operadores de shell
    printf("system() retorno: %d\n", rc);

    // -----------------------------
    // VULN #5 (Arbitrary file read / Path traversal): abre cualquier ruta sin validar.
    // CWE-22 (Path Traversal), CWE-73 (External Control of File Name or Path)
    FILE *f = fopen(file_arg, "r"); // <-- permite leer archivos arbitrarios
    if (f) {
        char line[256];
        printf("Contenido de '%s' (primeras lineas):\n", file_arg);
        for (int i = 0; i < 3 && fgets(line, sizeof(line), f); i++) {
            fputs(line, stdout);
        }
        fclose(f);
    } else {
        perror("fopen");
    }

    // -----------------------------
    // VULN #6 (Integer overflow + Heap overflow): tamaño calculado sin checks
    // + copia sin límites al heap.
    // CWE-190 (Integer Overflow), CWE-122 (Heap-based Buffer Overflow)
    int count = atoi(count_arg);          // sin validación (negativo, enorme, etc.)
    int bytes = count * 4;                // puede overflowear
    char *heap_buf = (char *)malloc(bytes); // bytes puede ser chico o incluso negativo interpretado como size_t grande
    if (!heap_buf) {
        puts("malloc fallo");
        return 1;
    }

    char tmp[1024];
    printf("\nEscribi un texto (hasta 1023 chars). Se copiara al heap buffer:\n");
    if (fgets(tmp, sizeof(tmp), stdin)) {
        // Copia sin límite: si bytes < strlen(tmp)+1 => overflow del heap_buf
        memcpy(heap_buf, tmp, strlen(tmp) + 1);
        printf("Guardado en heap_buf: %s\n", heap_buf);
    }

    free(heap_buf);

    puts("\nFin.");
    return 0;
}
