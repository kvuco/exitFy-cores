#include <dlfcn.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef char *(*start_core_fn)(const char *);
typedef char *(*stop_core_fn)(void);

#define MAX_ERROR_BYTES 4096U

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

static int report_error(const char *label, char *error) {
    size_t length = 0U;
    while (length <= MAX_ERROR_BYTES && error[length] != '\0') length++;
    if (length == 0U || length > MAX_ERROR_BYTES) {
        fprintf(stderr, "%s returned an invalid or oversized error\n", label);
        free(error);
        return 0;
    }
    fprintf(stderr, "%s: %.*s\n", label, (int) length, error);
    free(error);
    return 1;
}

static int stop_twice(stop_core_fn stop) {
    char *error = stop();
    if (error != NULL) {
        report_error("StopCore failed", error);
        return 0;
    }
    error = stop();
    if (error != NULL) {
        report_error("repeated StopCore failed", error);
        return 0;
    }
    return 1;
}

int main(int argc, char **argv) {
    int expect_start_error = argc == 4 && strcmp(argv[3], "expect-start-error") == 0;
    if (argc != 3 && !expect_start_error) {
        fprintf(stderr, "usage: %s CORE CONFIG [expect-start-error]\n", argv[0]);
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
    if (expect_start_error) {
        if (error == NULL) {
            fprintf(stderr, "StartCore unexpectedly accepted an invalid config\n");
            stop_twice(stop);
            return 6;
        }
        if (!report_error("StartCore rejected invalid config", error)) {
            stop_twice(stop);
            return 7;
        }
        if (!stop_twice(stop)) return 8;
        puts("Android expected-error and repeated StopCore smoke test passed");
        return 0;
    }
    if (error != NULL) {
        report_error("StartCore failed", error);
        stop_twice(stop);
        return 6;
    }
    usleep(250000U);
    if (!stop_twice(stop)) return 7;
    puts("Android StartCore/StopCore smoke test passed");
    return 0;
}
