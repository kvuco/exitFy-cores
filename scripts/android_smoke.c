#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef char *(*start_core_fn)(const char *);
typedef void (*stop_core_fn)(void);

static char *read_config(const char *path) {
    FILE *source = fopen(path, "rb");
    if (source == NULL) return NULL;
    if (fseek(source, 0, SEEK_END) != 0) {
        fclose(source);
        return NULL;
    }
    long size = ftell(source);
    if (size <= 0 || size > 1024 * 1024 || fseek(source, 0, SEEK_SET) != 0) {
        fclose(source);
        return NULL;
    }
    char *value = calloc((size_t) size + 1U, 1U);
    if (value == NULL || fread(value, 1U, (size_t) size, source) != (size_t) size) {
        free(value);
        fclose(source);
        return NULL;
    }
    fclose(source);
    return value;
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "usage: %s CORE CONFIG\n", argv[0]);
        return 2;
    }
    char *config = read_config(argv[2]);
    if (config == NULL) {
        fprintf(stderr, "cannot read smoke config: %s\n", strerror(errno));
        return 3;
    }
    void *handle = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    if (handle == NULL) {
        fprintf(stderr, "dlopen failed: %s\n", dlerror());
        free(config);
        return 4;
    }
    dlerror();
    start_core_fn start = (start_core_fn) dlsym(handle, "StartCore");
    const char *start_error = dlerror();
    dlerror();
    stop_core_fn stop = (stop_core_fn) dlsym(handle, "StopCore");
    const char *stop_error = dlerror();
    if (start == NULL || start_error != NULL || stop == NULL || stop_error != NULL) {
        fprintf(stderr, "required exports are missing\n");
        free(config);
        return 5;
    }
    char *error = start(config);
    free(config);
    if (error != NULL) {
        fprintf(stderr, "StartCore failed: %s\n", error);
        free(error);
        return 6;
    }
    usleep(250000U);
    stop();
    stop();
    puts("Android StartCore/StopCore smoke test passed");
    return 0;
}
