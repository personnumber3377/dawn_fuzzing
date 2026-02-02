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

// -------------------------
// Optional fallback WGSL
// (Only used if input is missing a stage but you still want to make a pipeline.)
// -------------------------

static const char* kDefaultVertexWGSL = R"(
@vertex
fn main(@builtin(vertex_index) i : u32) -> @builtin(position) vec4f {
    let pos = array(
        vec2f(-1.0, -1.0),
        vec2f( 1.0, -1.0),
        vec2f(-1.0,  1.0));
    return vec4f(pos[i], 0.0, 1.0);
}
)";

static const char* kDefaultFragmentWGSL = R"(
@fragment
fn main() -> @location(0) vec4f {
    return vec4f(1.0, 0.0, 0.0, 1.0);
}
)";

static const char* kDefaultComputeWGSL = R"(
@compute @workgroup_size(1)
fn main() {
}
)";

// Cheap stage detection (only used to decide whether to build compute / render pipelines)
// NOTE: We do NOT try to infer entry point names here.
struct Stages {
    bool hasVertex   = false;
    bool hasFragment = false;
    bool hasCompute  = false;
};

static Stages DetectStages(const std::string& src) {
    Stages s;
    s.hasVertex   = src.find("@vertex")   != std::string::npos;
    s.hasFragment = src.find("@fragment") != std::string::npos;
    s.hasCompute  = src.find("@compute")  != std::string::npos;
    return s;
}

/*
static wgpu::ShaderModule CompileWGSL(const char* wgsl) {
    return dawn::utils::CreateShaderModule(gDevice, wgsl);
}
*/

static wgpu::ShaderModule CompileWGSL(wgpu::Device& device, const char* wgsl) {
    return dawn::utils::CreateShaderModule(device, wgsl);
}

// -------------------------
// Device init (once per process)
// -------------------------

static void InitDeviceOnce() {
    if (gInitialized) return;

    DawnProcTable procs = dawn::native::GetProcs();
    dawnProcSetProcs(&procs);

    // Pick SwiftShader if present (as you were doing).
    for (auto& nativeAdapter : gInstance.EnumerateAdapters()) {
        wgpu::Adapter adapter(nativeAdapter.Get());
        wgpu::AdapterInfo info;
        adapter.GetInfo(&info);
        if (dawn::gpu_info::IsGoogleSwiftshader(info.vendorID, info.deviceID)) {
            gAdapter = adapter;
            break;
        }
    }

    // If you want “any adapter” fallback, uncomment this:
    // if (!gAdapter) {
    //     auto adapters = gInstance.EnumerateAdapters();
    //     if (!adapters.empty()) gAdapter = wgpu::Adapter(adapters[0].Get());
    // }

    wgpu::DeviceDescriptor desc = {};
    gDevice = gAdapter.CreateDevice(&desc);

    gInitialized = true;
}

// Parse the (assumed) wgsl code using tint.

static bool ParseWithTint(const uint8_t* data, size_t size, tint::Program& out_program) {
    tint::Initialize();

    std::string src(reinterpret_cast<const char*>(data), size);
    auto file = std::make_unique<tint::Source::File>("fuzz.wgsl", src);

    out_program = tint::wgsl::reader::Parse(file.get());

    if (!out_program.IsValid()) {
        // Optional: drop diagnostics silently (fuzzer-friendly)
        // tint::diag::Formatter fmt;
        // fmt.Format(out_program.Diagnostics(), std::cerr);
        return false;
    }

    return true;
}

/*
extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
    // ReadAndMaybeModify(argc, argv);
    
    InitDeviceOnce();
    
    return 0;
}
*/

static bool InitDeviceLocal(wgpu::Device& outDevice) {
    dawn::native::Instance instance;

    DawnProcTable procs = dawn::native::GetProcs();
    dawnProcSetProcs(&procs);

    wgpu::Adapter adapter;

    for (auto& nativeAdapter : instance.EnumerateAdapters()) {
        wgpu::Adapter a(nativeAdapter.Get());
        wgpu::AdapterInfo info;
        a.GetInfo(&info);
        if (dawn::gpu_info::IsGoogleSwiftshader(info.vendorID, info.deviceID)) {
            adapter = a;
            break;
        }
    }

    if (!adapter) {
        return false;
    }

    wgpu::DeviceDescriptor desc = {};
    outDevice = adapter.CreateDevice(&desc);
    return static_cast<bool>(outDevice);
}

// -------------------------
// LibFuzzer entry
// -------------------------

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size == 0 || size > (1u << 20)) {
        return 0;
    }

    // -------------------------
    // Step 1: Parse with Tint
    // -------------------------
    tint::Program program;
    if (!ParseWithTint(data, size, program)) {
        return 0;
    }

    // -------------------------
    // Step 2: Init Dawn device (LOCAL, per-iteration)
    // -------------------------
    wgpu::Device device;
    if (!InitDeviceLocal(device)) {
        return 0;
    }

    std::string inputWGSL(reinterpret_cast<const char*>(data), size);
    Stages stages = DetectStages(inputWGSL);

    // -------------------------
    // Step 3: Compile WGSL
    // -------------------------
    wgpu::ShaderModule inputModule =
        dawn::utils::CreateShaderModule(device, inputWGSL.c_str());

    if (!inputModule) {
        return 0;
    }

    // Optional fallback modules
    wgpu::ShaderModule defaultVert, defaultFrag;

    if (!stages.hasVertex && stages.hasFragment) {
        defaultVert = CompileWGSL(device, kDefaultVertexWGSL);
        if (!defaultVert) return 0;
    }

    if (!stages.hasFragment && stages.hasVertex) {
        defaultFrag = CompileWGSL(device, kDefaultFragmentWGSL);
    }

    // -------------------------
    // Step 4: Compute pipeline
    // -------------------------
    if (stages.hasCompute) {
        wgpu::ComputePipelineDescriptor desc = {};
        desc.compute.module = inputModule;
        desc.compute.entryPoint = nullptr;

        wgpu::ComputePipeline pipeline =
            device.CreateComputePipeline(&desc);
        (void)pipeline;
    }

    // -------------------------
    // Step 5: Render pipeline
    // -------------------------
    if (stages.hasVertex || stages.hasFragment) {
        dawn::utils::ComboRenderPipelineDescriptor desc;

        desc.vertex.module = stages.hasVertex ? inputModule : defaultVert;
        if (!desc.vertex.module) {
            return 0;
        }
        desc.vertex.entryPoint = nullptr;

        if (stages.hasFragment) {
            desc.cFragment.module = inputModule;
            desc.cFragment.entryPoint = nullptr;
            desc.cTargets[0].format = wgpu::TextureFormat::RGBA8Unorm;
            desc.cFragment.targetCount = 1;
        } else if (defaultFrag) {
            desc.cFragment.module = defaultFrag;
            desc.cFragment.entryPoint = nullptr;
            desc.cTargets[0].format = wgpu::TextureFormat::RGBA8Unorm;
            desc.cFragment.targetCount = 1;
        } else {
            desc.cFragment.module = nullptr;
            desc.cFragment.entryPoint = nullptr;
            desc.cFragment.targetCount = 0;
        }

        wgpu::RenderPipeline pipeline =
            device.CreateRenderPipeline(&desc);
        (void)pipeline;
    }

    // Let device + instance destruct naturally here
    return 0;
}
