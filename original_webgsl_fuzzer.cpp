// fuzz_wgsl_combo_pipeline.cpp
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>

// Needed for the file communication and spawning processes...

#include <unistd.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <vector>
#include <sstream>

#include "dawn/dawn_proc.h"
#include "dawn/native/DawnNative.h"

#include "dawn/utils/ComboRenderPipelineDescriptor.h"
#include "dawn/utils/WGPUHelpers.h"  // utils::CreateShaderModule
#include "dawn/common/GPUInfo.h"
#include "webgpu/webgpu_cpp.h"

static std::unique_ptr<dawn::native::Instance> gInstance;

// static wgpu::Adapter gAdapter;
// static wgpu::Device gDevice;

// Start with Null backend for stability; switch later to Vulkan/D3D12/Metal.
// static constexpr wgpu::BackendType kBackend = wgpu::BackendType::Null;

// Debugging

#define DEBUGGING 1

void log(const char* msg) {
    /*
    FILE* fp = fopen("/home/oof/angle_log.txt", "w");
    fwrite(msg, strlen(msg), 1, fp);
    fclose(fp);
    */
#ifdef DEBUGGING
    // fprintf(stderr, "%s", msg);
    //std::cerr << msg << "\n";
    write(2, msg, strlen(msg));
#endif
    return;
}

void log(const std::string msg) {
#ifdef DEBUGGING
    // fprintf(stderr, "%s", msg.c_str()); // Convert to cstring...
    std::cerr << msg << "\n";
#endif
    return;
}

const char* kDefaultVertexWGSL = R"(
@vertex
fn main(@builtin(vertex_index) i : u32)
     -> @builtin(position) vec4f {
    let pos = array(
        vec2f(-1.0, -1.0),
        vec2f( 1.0, -1.0),
        vec2f(-1.0,  1.0));
    return vec4f(pos[i], 0.0, 1.0);
}
)";

const char* kDefaultFragmentWGSL = R"(
@fragment
fn main() -> @location(0) vec4f {
    return vec4f(1.0, 0.0, 0.0, 1.0);
}
)";

const char* kDefaultComputeWGSL = R"(
@compute @workgroup_size(1)
fn main() {
}
)";

// wgpu::ShaderModule vert = dawn::utils::CreateShaderModule(gDevice, vertexWGSL); // This is the thing...

/*

static bool InitDeviceOnce() {
    gInstance = std::make_unique<dawn::native::Instance>();

    DawnProcTable procs = dawn::native::GetProcs();
    dawnProcSetProcs(&procs);


    gAdapter = wgpu::Adapter(gInstance->EnumerateAdapters()[0].Get()); // Just get the first one...

    if (!gAdapter) return false;

    wgpu::DeviceDescriptor desc = {};
    gDevice = gAdapter.CreateDevice(&desc);

    // Add error callback shit...

    // This next thing wont work...
    gDevice.SetUncapturedErrorCallback(
    [](wgpu::ErrorType type, const char* message) {
        write(2, message, strlen(message));
        write(2, "\n", 1);
    });
    

    gDevice.SetLoggingCallback([](wgpu::LoggingType type, wgpu::StringView message) {
        std::string_view view = {message.data, message.length};
        std::cerr << view << "\n";
    });

    return static_cast<bool>(gDevice);
}

*/


/*
static bool InitDeviceOnce() {
    gInstance = std::make_unique<dawn::native::Instance>();

    DawnProcTable procs = dawn::native::GetProcs();
    dawnProcSetProcs(&procs);

    wgpu::Adapter selected;

    for (auto& nativeAdapter : gInstance->EnumerateAdapters()) {
        wgpu::Adapter adapter(nativeAdapter.Get());

        wgpu::AdapterInfo info;
        adapter.GetInfo(&info);

        if (dawn::gpu_info::IsGoogleSwiftshader(info.vendorID, info.deviceID)) {
            selected = adapter;
            break;
        }
    }

    if (!selected) {
        return false;
    }

    gAdapter = selected;

    wgpu::DeviceDescriptor desc = {};
    gDevice = gAdapter.CreateDevice(&desc);

    gDevice.SetLoggingCallback([](wgpu::LoggingType type, wgpu::StringView message) {
        std::cerr << std::string_view{message.data, message.length} << "\n";
    });

    return static_cast<bool>(gDevice);
}
*/


static dawn::native::Instance* gInstanceRaw = nullptr;
static wgpu::Device gDevice;
static wgpu::Adapter gAdapter;

static bool InitDeviceOnce() {

    if (gInstanceRaw) return 1;

    gInstanceRaw = new dawn::native::Instance();

    DawnProcTable procs = dawn::native::GetProcs();
    dawnProcSetProcs(&procs);

    wgpu::Adapter selected;
    for (auto& nativeAdapter : gInstanceRaw->EnumerateAdapters()) {
        wgpu::Adapter adapter(nativeAdapter.Get());
        wgpu::AdapterInfo info;
        adapter.GetInfo(&info);
        if (dawn::gpu_info::IsGoogleSwiftshader(info.vendorID, info.deviceID)) {
            selected = adapter;
            break;
        }
    }
    // Delete this since otherwise we get problems...
    delete gInstanceRaw;
    gInstanceRaw = nullptr; // Also null out the pointer...
    if (!selected) return 1;
    gAdapter = selected;

    wgpu::DeviceDescriptor desc = {};
    gDevice = gAdapter.CreateDevice(&desc);
    return static_cast<bool>(gDevice);
}


struct Stages {
    bool hasVertex   = false;
    bool hasFragment = false;
    bool hasCompute  = false;
};

Stages DetectStages(const std::string& src) {
    Stages s;
    s.hasVertex   = src.find("@vertex")   != std::string::npos;
    s.hasFragment = src.find("@fragment") != std::string::npos;
    s.hasCompute  = src.find("@compute")  != std::string::npos;
    return s;
}

wgpu::ShaderModule Compile(const char* src) {
    return dawn::utils::CreateShaderModule(gDevice, src);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    log("Start...\n");

    // Try to init...
    // gDevice = InitDeviceOnce();

    InitDeviceOnce();

    if (!gDevice) return 0;
    if (size == 0 || size > (1u << 20)) return 0;
    
    log("Poopoo...\n");

    // Treat fuzzer input as WGSL
    std::string inputWGSL(reinterpret_cast<const char*>(data), size);

    // Detect stages
    Stages stages = DetectStages(inputWGSL);

    // Compile shader modules
    wgpu::ShaderModule inputModule =
        dawn::utils::CreateShaderModule(gDevice, inputWGSL.c_str());

    if (!inputModule) {
        log("Input WGSL failed to compile\n");
        return 0;
    }

    // Compile fallbacks (only if needed)
    wgpu::ShaderModule defaultVert, defaultFrag, defaultComp;

    if (!stages.hasVertex)
        defaultVert = Compile(kDefaultVertexWGSL);
    if (!stages.hasFragment)
        defaultFrag = Compile(kDefaultFragmentWGSL);
    if (!stages.hasCompute)
        defaultComp = Compile(kDefaultComputeWGSL);

    // -------------------------
    // COMPUTE PIPELINE
    // -------------------------
    if (stages.hasCompute) {
        wgpu::ComputePipelineDescriptor desc = {};
        desc.compute.module = inputModule;
        desc.compute.entryPoint = "main";

        wgpu::ComputePipeline pipeline =
            gDevice.CreateComputePipeline(&desc);

        if (pipeline) {
            wgpu::CommandEncoder enc = gDevice.CreateCommandEncoder();
            wgpu::ComputePassEncoder pass = enc.BeginComputePass();
            pass.SetPipeline(pipeline);
            pass.DispatchWorkgroups(1);
            pass.End();
            wgpu::CommandBuffer cb = enc.Finish();
            gDevice.GetQueue().Submit(1, &cb);
        }
    }

    // -------------------------
    // RENDER PIPELINE
    // -------------------------
    if (stages.hasVertex || stages.hasFragment) {
        dawn::utils::ComboRenderPipelineDescriptor desc;

        // Vertex is mandatory → fallback if missing
        desc.vertex.module =
            stages.hasVertex ? inputModule : defaultVert;
        desc.vertex.entryPoint = "main";

        // Fragment is optional
        if (stages.hasFragment || defaultFrag) {
            desc.cFragment.module =
                stages.hasFragment ? inputModule : defaultFrag;
            desc.cFragment.entryPoint = "main";
            desc.cTargets[0].format = wgpu::TextureFormat::RGBA8Unorm;
            desc.cFragment.targetCount = 1;
        }

        wgpu::RenderPipeline pipeline =
            gDevice.CreateRenderPipeline(&desc);

        if (pipeline) {
            // Minimal render pass (same as before)
            wgpu::TextureDescriptor texDesc = {};
            texDesc.size = {4, 4, 1};
            texDesc.format = wgpu::TextureFormat::RGBA8Unorm;
            texDesc.usage = wgpu::TextureUsage::RenderAttachment;

            wgpu::Texture tex = gDevice.CreateTexture(&texDesc);
            wgpu::TextureView view = tex.CreateView();

            wgpu::RenderPassColorAttachment ca = {};
            ca.view = view;
            ca.loadOp = wgpu::LoadOp::Clear;
            ca.storeOp = wgpu::StoreOp::Store;

            wgpu::RenderPassDescriptor rp = {};
            rp.colorAttachmentCount = 1;
            rp.colorAttachments = &ca;

            wgpu::CommandEncoder enc = gDevice.CreateCommandEncoder();
            wgpu::RenderPassEncoder pass = enc.BeginRenderPass(&rp);
            pass.SetPipeline(pipeline);
            pass.Draw(3);
            pass.End();
            wgpu::CommandBuffer cb = enc.Finish();
            gDevice.GetQueue().Submit(1, &cb);
        }
    }

    log("paskaaaaaa\n");

    gDevice.Tick();

    gDevice.Destroy();
    gDevice = nullptr; // Reset the thing...
    return 0;
}
