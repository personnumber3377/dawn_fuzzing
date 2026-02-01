#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// ------------------------------------------------------------
// libFuzzer default mutator (provided by libFuzzer)
// ------------------------------------------------------------
extern "C" size_t LLVMFuzzerMutate(uint8_t *Data,
                                  size_t Size,
                                  size_t MaxSize);

// ------------------------------------------------------------
// DarthShader ABI
// ------------------------------------------------------------
typedef int (*darth_mutate_fn)(
    const uint8_t* data,
    size_t size,
    uint64_t seed,
    uint8_t** out_data,
    size_t* out_size
);

typedef void (*darth_free_fn)(uint8_t* ptr, size_t size);

// ------------------------------------------------------------
// Globals (intentionally leaked for fuzzing safety)
// ------------------------------------------------------------
static void*            gHandle        = nullptr;
static darth_mutate_fn  gMutate         = nullptr;
static darth_free_fn    gFree           = nullptr;
static bool             gInitAttempted  = false;

// ------------------------------------------------------------
// Initialization (once)
// ------------------------------------------------------------
static void InitDarthShaderOnce() {
    if (gInitAttempted)
        return;

    gInitAttempted = true;

    const char* libname =
        getenv("DARTHSHADER_MUTATOR_SO")
            ? getenv("DARTHSHADER_MUTATOR_SO")
            : "./libdarthshader_mutator.so";

    gHandle = dlopen(libname, RTLD_NOW | RTLD_LOCAL);
    if (!gHandle) {
        fprintf(stderr, "[darthshader] dlopen failed: %s\n", dlerror());
        return;
    }

    gMutate = (darth_mutate_fn)dlsym(gHandle, "darthshader_mutate");
    gFree   = (darth_free_fn)dlsym(gHandle, "darthshader_free");

    if (!gMutate || !gFree) {
        fprintf(stderr, "[darthshader] dlsym failed\n");
        gMutate = nullptr;
        gFree   = nullptr;
        return;
    }

    fprintf(stderr, "[darthshader] mutator loaded successfully\n");
}

// ------------------------------------------------------------
// Custom mutator entry point
// ------------------------------------------------------------
extern "C"
size_t LLVMFuzzerCustomMutator(uint8_t *Data,
                               size_t Size,
                               size_t MaxSize,
                               unsigned int Seed) {
    InitDarthShaderOnce();

    // If shader mutator missing → fallback
    if (!gMutate || !gFree) {
        return LLVMFuzzerMutate(Data, Size, MaxSize);
    }

    uint8_t* out_data = nullptr;
    size_t   out_size = 0;

    int ret = gMutate(
        Data,
        Size,
        (uint64_t)Seed,
        &out_data,
        &out_size
    );

    if (ret != 0 || !out_data) {
        // Shader mutator failed → fallback
        return LLVMFuzzerMutate(Data, Size, MaxSize);
    }

    if (out_size > MaxSize)
        out_size = MaxSize;

    memcpy(Data, out_data, out_size);
    gFree(out_data, out_size);

    // Optional: chain default mutator afterward
    if (!getenv("FUZZ_ONLY_CUSTOM")) {
        return LLVMFuzzerMutate(Data, out_size, MaxSize);
    }

    return out_size;
}

// ------------------------------------------------------------
// (Optional) stub crossover — safe no-op for now
// ------------------------------------------------------------
extern "C"
size_t LLVMFuzzerCustomCrossOver(const uint8_t* Data1,
                                 size_t Size1,
                                 const uint8_t* Data2,
                                 size_t Size2,
                                 uint8_t* Out,
                                 size_t MaxOutSize,
                                 unsigned int Seed) {
    size_t n = Size1 < MaxOutSize ? Size1 : MaxOutSize;
    memcpy(Out, Data1, n);
    return n;
}