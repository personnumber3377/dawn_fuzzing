#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#define MUTATOR_FILENAME "./libdarthshader_mutator.so"

/* Function pointer types */
typedef int (*mutate_fn)(
    const uint8_t* data,
    size_t size,
    uint64_t seed,
    uint8_t** out_data,
    size_t* out_size
);

typedef void (*free_fn)(uint8_t* ptr, size_t size);

static uint8_t* read_file(const char* path, size_t* out_size) {
    FILE* f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "fopen(%s): %s\n", path, strerror(errno));
        return NULL;
    }

    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    rewind(f);

    if (sz <= 0) {
        fclose(f);
        return NULL;
    }

    uint8_t* buf = (uint8_t*)malloc(sz);
    if (!buf) {
        fclose(f);
        return NULL;
    }

    if (fread(buf, 1, sz, f) != (size_t)sz) {
        fclose(f);
        free(buf);
        return NULL;
    }

    fclose(f);
    *out_size = (size_t)sz;
    return buf;
}

int main(int argc, char** argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <shader.wgsl>\n", argv[0]);
        return 1;
    }

    size_t in_size = 0;
    uint8_t* in = read_file(argv[1], &in_size);
    if (!in) {
        fprintf(stderr, "Failed to read input file\n");
        return 1;
    }

    void* handle = dlopen(MUTATOR_FILENAME, RTLD_NOW);
    if (!handle) {
        fprintf(stderr, "dlopen failed: %s\n", dlerror());
        return 1;
    }

    mutate_fn darthshader_mutate =
        (mutate_fn)dlsym(handle, "darthshader_mutate");
    free_fn darthshader_free =
        (free_fn)dlsym(handle, "darthshader_free");

    if (!darthshader_mutate || !darthshader_free) {
        fprintf(stderr, "dlsym failed\n");
        return 1;
    }

    uint8_t* out = NULL;
    size_t out_size = 0;

    int ret = darthshader_mutate(
        in,
        in_size,
        0x1337,
        &out,
        &out_size
    );

    if (ret != 0) {
        fprintf(stderr, "Mutation failed: %d\n", ret);
        return 1;
    }

    printf("=== Mutated WGSL (%zu bytes) ===\n", out_size);
    fwrite(out, 1, out_size, stdout);
    printf("\n===============================\n");

    darthshader_free(out, out_size);
    dlclose(handle);
    free(in);
    return 0;
}