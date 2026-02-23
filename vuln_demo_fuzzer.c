#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

/* Declarada en vuln_demo.c (lógica del programa) */
int process_inputs(const char *name_arg,
                   const char *fmt_arg,
                   const char *cmd_arg,
                   const char *file_arg,
                   const char *count_arg);

static void split_5_fields(char *buf, size_t n,
                           char **a, char **b, char **c, char **d, char **e) {
    // Separador simple: '\n'. Genera 5 strings null-terminated.
    *a = buf;
    *b = *c = *d = *e = buf;

    int field = 0;
    for (size_t i = 0; i < n; i++) {
        if (buf[i] == '\n') {
            buf[i] = '\0';
            field++;
            if (field == 1) *b = &buf[i + 1];
            else if (field == 2) *c = &buf[i + 1];
            else if (field == 3) *d = &buf[i + 1];
            else if (field == 4) { *e = &buf[i + 1]; break; }
        } else if (buf[i] == '\0') {
            buf[i] = 'A'; // evitamos cortes prematuros
        }
    }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 8) return 0;

    // Copiamos input y lo hacemos string-safe.
    char *buf = (char *)malloc(size + 1);
    if (!buf) return 0;
    memcpy(buf, data, size);
    buf[size] = '\0';

    // Partimos en 5 campos: name, fmt, cmd, file, count
    char *name_arg, *fmt_arg, *cmd_arg, *file_arg, *count_arg;
    split_5_fields(buf, size, &name_arg, &fmt_arg, &cmd_arg, &file_arg, &count_arg);

    // Defaults para que siempre haya algo útil
    if (!*name_arg)  name_arg  = "Alice";
    if (!*fmt_arg)   fmt_arg   = "Hola\n";
    if (!*cmd_arg)   cmd_arg   = "echo OK";
    if (!*file_arg)  file_arg  = "vuln_demo.c";
    if (!*count_arg) count_arg = "8";

    // Llamamos a la lógica vulnerable
    (void)process_inputs(name_arg, fmt_arg, cmd_arg, file_arg, count_arg);

    free(buf);
    return 0;
}
