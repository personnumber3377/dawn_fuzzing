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

// These helpers here are for inferring the "main" function from the webgsl snippet. The custom mutator may not necessarily generate a function named "main":

static inline bool IsIdentStart(char c) {
    return (c >= 'A' && c <= 'Z') ||
           (c >= 'a' && c <= 'z') ||
           c == '_';
}

static inline bool IsIdentChar(char c) {
    return IsIdentStart(c) || (c >= '0' && c <= '9');
}

static void SkipWhitespace(const char*& p, const char* end) {
    while (p < end && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r'))
        ++p;
}

enum class ShaderStage {
    Vertex,
    Fragment,
    Compute
};

struct EntryPoint {
    ShaderStage stage;
    std::string name;
};

std::vector<EntryPoint> ExtractEntryPoints(const std::string& src) {
    std::vector<EntryPoint> result;

    const char* p   = src.data();
    const char* end = p + src.size();

    ShaderStage pendingStage;
    bool haveStage = false;

    while (p < end) {
        // Look for '@'
        if (*p != '@') {
            ++p;
            continue;
        }
        ++p;

        // Parse attribute name
        if (p >= end || !IsIdentStart(*p))
            continue;

        const char* attrStart = p;
        while (p < end && IsIdentChar(*p))
            ++p;

        std::string attr(attrStart, p - attrStart);

        if (attr == "vertex") {
            pendingStage = ShaderStage::Vertex;
            haveStage = true;
        } else if (attr == "fragment") {
            pendingStage = ShaderStage::Fragment;
            haveStage = true;
        } else if (attr == "compute") {
            pendingStage = ShaderStage::Compute;
            haveStage = true;
        } else {
            continue; // Not a stage attribute
        }

        // After stage attribute, scan forward for `fn`
        const char* q = p;
        while (q < end) {
            SkipWhitespace(q, end);

            // Look for "fn"
            if (q + 2 <= end && q[0] == 'f' && q[1] == 'n' &&
                (q + 2 == end || !IsIdentChar(q[2]))) {

                q += 2;
                SkipWhitespace(q, end);

                // Parse function name
                if (q < end && IsIdentStart(*q)) {
                    const char* nameStart = q;
                    while (q < end && IsIdentChar(*q))
                        ++q;

                    result.push_back({
                        pendingStage,
                        std::string(nameStart, q - nameStart)
                    });
                }
                break;
            }

            // Stop if we hit another attribute (avoid runaway scan)
            if (*q == '@')
                break;

            ++q;
        }

        haveStage = false;
    }

    return result;
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

    if (size == 0 || size > (1u << 20)) return 0;

    // Treat fuzzer input as WGSL
    std::string inputWGSL(reinterpret_cast<const char*>(data), size);

    auto eps = ExtractEntryPoints(inputWGSL);

    // If no entrypoint found, then no point in really running anyway...
    if (eps.empty()) return 0;

    // Try to init...
    // gDevice = InitDeviceOnce();

    InitDeviceOnce();

    if (!gDevice) return 0;
    
    log("Poopoo...\n");


    // Detect stages
    Stages stages = DetectStages(inputWGSL);

    // Compile shader modules
    wgpu::ShaderModule inputModule =
        dawn::utils::CreateShaderModule(gDevice, inputWGSL.c_str());

    // Get the entrypoint functions...


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

        for (auto& ep : eps) {
            switch (ep.stage) {
                case ShaderStage::Compute:
                    desc.compute.entryPoint = ep.name.c_str();
                    break;
                case ShaderStage::Vertex:
                    // desc.vertex.entryPoint = ep.name.c_str();
                    break;
                case ShaderStage::Fragment:
                    // log("We got this fragment entrypoint function here:\n");
                    // log(ep.name.c_str());
                    // desc.cFragment.entryPoint = ep.name.c_str();
                    break;
            }
        }

        // desc.compute.entryPoint = "main";

        wgpu::ComputePipeline pipeline =
            gDevice.CreateComputePipeline(&desc);

        if (pipeline) {
            wgpu::CommandEncoder enc = gDevice.CreateCommandEncoder();
            wgpu::ComputePassEncoder pass = enc.BeginComputePass();
            pass.SetPipeline(pipeline);

            // pass.DispatchWorkgroups(1);
            // pass.End();
            // wgpu::CommandBuffer cb = enc.Finish();
            // gDevice.GetQueue().Submit(1, &cb);
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

        // Now set the entrypoints here...

        for (auto& ep : eps) {
            switch (ep.stage) {
                case ShaderStage::Compute:
                    // desc.compute.entryPoint = ep.name.c_str();

                    // TODO: ????? How do we have the thing here ?????

                    break;
                case ShaderStage::Vertex:
                    desc.vertex.entryPoint = ep.name.c_str();
                    break;
                case ShaderStage::Fragment:
                    log("We got this fragment entrypoint function here:\n");
                    log(ep.name.c_str());
                    desc.cFragment.entryPoint = ep.name.c_str();
                    break;
            }
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

            // pass.Draw(3);
            // pass.End();
            // wgpu::CommandBuffer cb = enc.Finish();
            // gDevice.GetQueue().Submit(1, &cb);
        }
    }

    log("paskaaaaaa\n");

    gDevice.Tick();

    gDevice.Destroy();
    gDevice = nullptr; // Reset the thing...
    return 0;
}
