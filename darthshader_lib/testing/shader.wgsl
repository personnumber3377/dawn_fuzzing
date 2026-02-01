struct Params {
    scale : f32,
    bias  : f32,
};

@group(0) @binding(0)
var<uniform> params : Params;

fn transform(x : f32) -> f32 {
    let y = x * params.scale + params.bias;
    if (y > 1.0) {
        return y - 1.0;
    }
    return y;
}

@compute @workgroup_size(4, 4, 1)
fn main(@builtin(global_invocation_id) gid : vec3<u32>) {
    let x = f32(gid.x);
    let y = transform(x);
    let z = vec3<f32>(y, y * 0.5, y * 2.0);
}