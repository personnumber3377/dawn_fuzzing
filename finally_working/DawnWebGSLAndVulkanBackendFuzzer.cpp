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

static wgpu::ShaderModule CompileWGSL(const char* wgsl) {
    return dawn::utils::CreateShaderModule(gDevice, wgsl);
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

// -------------------------
// LibFuzzer entry
// -------------------------

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Keep this lightweight.
    if (size == 0 || size > (1u << 20)) return 0;

    InitDeviceOnce();
    if (!gDevice) return 0;

    // Treat input bytes as WGSL (not necessarily NUL-terminated)
    std::string inputWGSL(reinterpret_cast<const char*>(data), size);

    // Determine which pipelines we *attempt* to build.
    // (Entry points are NOT inferred; Dawn will default them when entryPoint is undefined.)
    Stages stages = DetectStages(inputWGSL);

    // Compile main shader module
    wgpu::ShaderModule inputModule = dawn::utils::CreateShaderModule(gDevice, inputWGSL.c_str());
    if (!inputModule) {
        // Compilation failed; nothing more to do.
        return 0;
    }

    // Optional fallback modules (only created if needed)
    wgpu::ShaderModule defaultVert, defaultFrag, defaultComp;
    if (!stages.hasVertex && (stages.hasFragment)) {
        // If they have fragment but not vertex, you can't build a render pipeline without a vertex stage.
        defaultVert = CompileWGSL(kDefaultVertexWGSL);
        if (!defaultVert) return 0;
    }
    if (!stages.hasFragment && (stages.hasVertex)) {
        // If they have vertex but not fragment, you can still build a render pipeline (fragment optional),
        // but you might want to force a fragment stage for coverage.
        defaultFrag = CompileWGSL(kDefaultFragmentWGSL);
        // If it fails, we can still proceed without fragment.
    }
    if (!stages.hasCompute) {
        // Only needed if you want to always try compute too; currently we only do compute if input has it.
        // defaultComp = CompileWGSL(kDefaultComputeWGSL);
    }

    // -------------------------
    // Compute pipeline
    // -------------------------
    if (stages.hasCompute) {
        wgpu::ComputePipelineDescriptor desc = {};
        desc.compute.module = inputModule;

        // KEY: leave entryPoint undefined -> Dawn picks the default compute entry point
        // (i.e., the first @compute entry point in the module)
        desc.compute.entryPoint = nullptr;

        // Optional: allow implicit layout
        // desc.layout = nullptr;

        wgpu::ComputePipeline pipeline = gDevice.CreateComputePipeline(&desc);
        (void)pipeline;

        // If you want to execute (slower):
        // if (pipeline) {
        //     wgpu::CommandEncoder enc = gDevice.CreateCommandEncoder();
        //     wgpu::ComputePassEncoder pass = enc.BeginComputePass();
        //     pass.SetPipeline(pipeline);
        //     pass.DispatchWorkgroups(1);
        //     pass.End();
        //     wgpu::CommandBuffer cb = enc.Finish();
        //     gDevice.GetQueue().Submit(1, &cb);
        // }
    }

    // -------------------------
    // Render pipeline
    // -------------------------
    if (stages.hasVertex || stages.hasFragment) {
        dawn::utils::ComboRenderPipelineDescriptor desc;

        // Always set module attributes. Entry points are left undefined for Dawn to infer.
        // Vertex is required.
        desc.vertex.module = stages.hasVertex ? inputModule : defaultVert;
        if (!desc.vertex.module) {
            // No vertex stage available at all -> can't make render pipeline.
            // (If input had fragment only and defaultVert failed, we land here.)
            return 0;
        }
        desc.vertex.entryPoint = nullptr;  // KEY: default vertex entry point

        // Fragment is optional in WebGPU, but SwiftShader / backend coverage can be better if present.
        // If input has fragment, use it. Else optionally use defaultFrag if we compiled it.
        if (stages.hasFragment) {
            desc.cFragment.module = inputModule;
            desc.cFragment.entryPoint = nullptr;  // KEY: default fragment entry point
            desc.cTargets[0].format = wgpu::TextureFormat::RGBA8Unorm;
            desc.cFragment.targetCount = 1;
        } else if (defaultFrag) {
            desc.cFragment.module = defaultFrag;
            desc.cFragment.entryPoint = nullptr;
            desc.cTargets[0].format = wgpu::TextureFormat::RGBA8Unorm;
            desc.cFragment.targetCount = 1;
        } else {
            // No fragment stage: you may keep it absent.
            // ComboRenderPipelineDescriptor defaults might leave cFragment in a safe state,
            // but to be explicit:
            desc.cFragment.module = nullptr;
            desc.cFragment.entryPoint = nullptr;
            desc.cFragment.targetCount = 0;
        }

        // Color target format only matters if we have a fragment stage / targets.
        if (desc.cFragment.targetCount > 0) {
            desc.cTargets[0].format = wgpu::TextureFormat::RGBA8Unorm;
        }

        wgpu::RenderPipeline pipeline = gDevice.CreateRenderPipeline(&desc);
        (void)pipeline;

        // If you want to execute (slower):
        // if (pipeline) {
        //     wgpu::TextureDescriptor texDesc = {};
        //     texDesc.size = {4, 4, 1};
        //     texDesc.format = wgpu::TextureFormat::RGBA8Unorm;
        //     texDesc.usage = wgpu::TextureUsage::RenderAttachment;
        //
        //     wgpu::Texture tex = gDevice.CreateTexture(&texDesc);
        //     wgpu::TextureView view = tex.CreateView();
        //
        //     wgpu::RenderPassColorAttachment ca = {};
        //     ca.view = view;
        //     ca.loadOp = wgpu::LoadOp::Clear;
        //     ca.storeOp = wgpu::StoreOp::Store;
        //
        //     wgpu::RenderPassDescriptor rp = {};
        //     rp.colorAttachmentCount = 1;
        //     rp.colorAttachments = &ca;
        //
        //     wgpu::CommandEncoder enc = gDevice.CreateCommandEncoder();
        //     wgpu::RenderPassEncoder pass = enc.BeginRenderPass(&rp);
        //     pass.SetPipeline(pipeline);
        //     pass.Draw(3);
        //     pass.End();
        //     wgpu::CommandBuffer cb = enc.Finish();
        //     gDevice.GetQueue().Submit(1, &cb);
        // }
    }

    // Keep device alive; do NOT destroy per-iteration (major perf killer).
    // Tick helps process internal work; cheap enough to keep.
    gDevice.Tick();

    return 0;
}