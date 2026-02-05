




// fuzz_wgsl_combo_pipeline.cpp
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

#include <unistd.h>

#include "dawn/dawn_proc.h"
#include "dawn/native/DawnNative.h"
#include "dawn/common/GPUInfo.h"
#include "dawn/utils/ComboRenderPipelineDescriptor.h"
#include "dawn/utils/WGPUHelpers.h"
#include "webgpu/webgpu_cpp.h"

#include "tint/tint.h"
#include "tint/lang/wgsl/reader/reader.h"
// #include "tint/diagnostic/formatter.h"




#include "src/tint/api/common/binding_point.h"
#include "src/tint/lang/core/type/external_texture.h"
#include "src/tint/lang/wgsl/ast/module.h"
// #include "src/tint/lang/wgsl/helpers/apply_substitute_overrides.h"
// #include "src/tint/lang/wgsl/helpers/flatten_bindings.h"
#include "src/tint/lang/wgsl/program/program.h"
#include "src/tint/lang/wgsl/sem/variable.h"


// writer/writer.h

#include "tint/lang/hlsl/writer/writer.h"

#include "src/tint/utils/diagnostic/formatter.h"
#include "src/tint/utils/text/styled_text_printer.h"
#include "src/tint/utils/math/hash.h"










/*

#include "src/tint/fuzzers/fuzzer_init.h"
#include "src/tint/fuzzers/random_generator.h"
#include "src/tint/fuzzers/tint_common_fuzzer.h"
#include "src/tint/fuzzers/transform_builder.h"
*/


#include "src/tint/api/common/binding_point.h"
#include "src/tint/lang/core/type/external_texture.h"
#include "src/tint/lang/wgsl/ast/module.h"
// #include "src/tint/lang/wgsl/helpers/apply_substitute_overrides.h"
// #include "src/tint/lang/wgsl/helpers/flatten_bindings.h"
#include "src/tint/lang/wgsl/program/program.h"
#include "src/tint/lang/wgsl/sem/variable.h"
#include "src/tint/utils/diagnostic/formatter.h"
#include "src/tint/utils/text/styled_text_printer.h"
#include "src/tint/utils/math/hash.h"

// #include "src/tint/lang/spirv/writer/helpers/generate_bindings.h"
// #include "src/tint/lang/msl/writer/helpers/generate_bindings.h"
// #include "src/tint/lang/spirv/writer/helpers/ast_generate_bindings.h"
// #include "spirv-tools/libspirv.hpp"

// #include "src/tint/fuzzers/tint_wgsl_reader_all_writer_fuzzer.h"








// -------------------------
// Debug logging
// -------------------------

#define DEBUGGING 1

static void log(const char* msg) {
#ifdef DEBUGGING
    write(2, msg, strlen(msg));
#else
    (void)msg;
#endif
}

// -------------------------
// Global WebGPU objects
// -------------------------

static bool gInitialized = false;

// Keep the instance alive for the life of the process.
// (Your earlier version deleted it, which can subtly break things.)
static dawn::native::Instance gInstance;

static wgpu::Adapter gAdapter;
static wgpu::Device gDevice;

// extern IDxcCompiler3* mDxcCompiler;

#include <dlfcn.h>
#include <cstdio>
#include <cstdlib>

// This is needed for the DXC stuff...

#include "dxc_utils.cpp"


// Forward declarations from your DXC header
/*
extern "C" {
    typedef HRESULT(*DxcCreateInstanceProc)(REFCLSID rclsid,
                                            REFIID riid,
                                            LPVOID* ppv);
}
*/

// Global compiler instance (reused forever)
IDxcCompiler3* mDxcCompiler = nullptr;

// Keep handle alive so the library is never unloaded
static void* gDxCompilerLib = nullptr;


extern "C" int LLVMFuzzerInitialize(int* argc, char*** argv) {
    (void)argc;
    (void)argv;

    // Load DXC shared library
    gDxCompilerLib = dlopen("libdxcompiler.so", RTLD_NOW | RTLD_GLOBAL);
    if (!gDxCompilerLib) {
        fprintf(stderr, "[DXC] dlopen failed: %s\n", dlerror());
        abort();  // hard fail: fuzzing without DXC makes no sense
    }

    // Resolve factory function
    auto dxcCreateInstance =
        reinterpret_cast<DxcCreateInstanceProc>(
            dlsym(gDxCompilerLib, "DxcCreateInstance"));

    if (!dxcCreateInstance) {
        fprintf(stderr, "[DXC] dlsym(DxcCreateInstance) failed\n");
        abort();
    }

    // Create compiler instance
    HRESULT hr = dxcCreateInstance(
        CLSID_DxcCompiler,
        IID_PPV_ARGS(&mDxcCompiler));

    if (hr != 0 || !mDxcCompiler) {
        fprintf(stderr, "[DXC] DxcCreateInstance failed (hr=0x%x)\n", hr);
        abort();
    }

    fprintf(stderr, "[DXC] Compiler initialized: %p\n", mDxcCompiler);

    // Initialize the tint parser too...

    tint::Initialize();

    fprintf(stderr, "Initialized the tint parser too...\n");

    return 0;
}


// -------------------------
// LibFuzzer entry
// -------------------------

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size == 0 || size > (1 << 20)) {
        return -1;
    }

    if (!mDxcCompiler) {
        return -1;
    }

    // tint::Initialize();
    // tint::SetInternalCompilerErrorReporter(&TintInternalCompilerErrorReporter);

    // ---- WGSL parse ----
    std::string src(reinterpret_cast<const char*>(data), size);
    auto file = std::make_unique<tint::Source::File>("fuzz.wgsl", src);
    tint::Program program = tint::wgsl::reader::Parse(file.get());
    if (!program.IsValid()) return -1;

    // ---- HLSL generation ----
    tint::hlsl::writer::Options options;
    
    // auto result = tint::hlsl::writer::Generate(program, options);
    // if (result != tint::Success) return -1;

    // IR
    
    /*
    auto ir_result = tint::wgsl::reader::ProgramToLoweredIR(program);
    if (ir_result != tint::Success) {
        return -1; // or just skip input
    }

    tint::core::ir::Module& ir = ir_result.Get();
    */


    // Stuff...
    // tint::hlsl::writer::Options options;

    auto ir = tint::wgsl::reader::ProgramToLoweredIR(program);
    if (ir != tint::Success) return 0;
    auto result = tint::hlsl::writer::Generate(ir.Get(), options);


    // auto result = tint::hlsl::writer::Generate(ir, options);

    // auto result = tint::hlsl::writer::Generate(program, options);

    /*
    if (result != tint::Success) {
        return 0;
    }
    */

    if (result != tint::Success) {
        const auto& diag = result.Failure();
        fprintf(stderr, "HLSL writer failed:\n%s\n",
                diag.reason.c_str());
        return 0;
    }

    abort();
    std::string& hlsl = result->hlsl;

    // ---- DXC compile ----
    /*
    for (auto& [entry, stage] : result->entry_points) {
        std::wstring entryW = utf8_to_utf16(entry);

        std::vector<const wchar_t*> args = {
            L"-T",
            stage == tint::ast::PipelineStage::kCompute ? L"cs_6_6" :
            stage == tint::ast::PipelineStage::kVertex  ? L"vs_6_6" :
                                                          L"ps_6_6",
            L"-E", entryW.c_str(),
            L"-HV", L"2018",
            L"/O0",
        };

        DxcBuffer buf;
        buf.Ptr = hlsl.data();
        buf.Size = hlsl.size();
        buf.Encoding = DXC_CP_UTF8;

        IUnknown* resultObj = nullptr;
        mDxcCompiler->Compile(
            &buf,
            args.data(),
            args.size(),
            nullptr,
            __uuidof(IDxcResult),
            (void**)&resultObj
        );
        if (resultObj) resultObj->Release();
    }
    */


    const std::string& entry = result->entry_point_name;
    auto stage = result->pipeline_stage;

    const wchar_t* stage_prefix = L"";
    switch (stage) {
        case tint::core::ir::Function::PipelineStage::kVertex:
            stage_prefix = L"vs";
            break;
        case tint::core::ir::Function::PipelineStage::kFragment:
            stage_prefix = L"ps";
            break;
        case tint::core::ir::Function::PipelineStage::kCompute:
            stage_prefix = L"cs";
            break;
        default:
            return 0;
    }

    std::wstring profile = std::wstring(stage_prefix) + L"_6_6";
    std::wstring entry_w(entry.begin(), entry.end());

    std::vector<const wchar_t*> args = {
        L"-T", profile.c_str(),
        L"-E", entry_w.c_str(),
        L"-HV", L"2018",
        L"/Zpr",
        L"/Gis",
    };

    DxcBuffer buf;
    buf.Ptr = result->hlsl.c_str();
    buf.Size = result->hlsl.size();
    buf.Encoding = DXC_CP_UTF8;

    IUnknown* pResult = nullptr;
    abort();
    mDxcCompiler->Compile(
        &buf,
        args.data(),
        static_cast<UINT32>(args.size()),
        nullptr,
        __uuidof(IDxcResult),
        reinterpret_cast<void**>(&pResult)
    );

    if (pResult) {
        pResult->Release();
    }

    return 0;
}