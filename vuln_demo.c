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

int process_inputs(const char *name_arg,
                   const char *fmt_arg,
                   const char *cmd_arg,
                   const char *file_arg,
                   const char *count_arg) {
    // VULN #2 (Stack-based buffer overflow): copia sin límites.
    // CWE-121 / CWE-120
    char name_buf[32];
    strcpy(name_buf, name_arg);

    // VULN #3 (Format string): user-controlled format string.
    // CWE-134
    printf(fmt_arg);
    printf("\n");

    // VULN #4 (Command injection): ejecuta comando controlado por usuario.
    // CWE-78
    int rc = system(cmd_arg);
    printf("system() retorno: %d\n", rc);

    // VULN #5 (Arbitrary file read / Path traversal): ruta sin validar.
    // CWE-22 / CWE-73
    FILE *f = fopen(file_arg, "r");
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

    // VULN #6 (Integer overflow + Heap overflow): tamaño calculado sin checks
    // y copia sin límites al heap.
    // CWE-190 / CWE-122
    int count = atoi(count_arg);
    int bytes = count * 4;
    char *heap_buf = (char *)malloc((size_t)bytes);
    if (!heap_buf) {
        puts("malloc fallo");
        return 1;
    }

    char tmp[1024];
    strncpy(tmp, name_arg, sizeof(tmp) - 1);
    tmp[sizeof(tmp) - 1] = '\0';

    // Vulnerabilidad intencional: posible heap overflow si bytes < strlen(tmp)
    memcpy(heap_buf, tmp, strlen(tmp) + 1);
    printf("Guardado en heap_buf: %s\n", heap_buf);

    free(heap_buf);

    puts("\nFin.");
    return 0;
}

#ifndef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
int main(int argc, char **argv) {
    const char *name_arg = NULL;
    const char *fmt_arg  = NULL;
    const char *cmd_arg  = NULL;
    const char *file_arg = NULL;
    const char *count_arg = NULL;

    // VULN #1 (Input validation / OOB read): asume que cada flag tiene un valor (argv[i+1]).
    // CWE-20 / (posible) CWE-125
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

    return process_inputs(name_arg, fmt_arg, cmd_arg, file_arg, count_arg);
}
#endif
