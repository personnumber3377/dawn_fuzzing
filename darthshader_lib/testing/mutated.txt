struct S2343830421_ {
    @builtin(position) m0_: vec4<f32>,
    @builtin(sample_index) m1_: u32,
    @builtin(front_facing) m2_: bool,
}

struct S3159169591_ {
    @location(3) @interpolate(flat) m0_: i32,
    @location(1) @interpolate(flat) m1_: vec4<u32>,
    @location(0) @interpolate(flat) m2_: u32,
    @location(4) @interpolate(flat) m3_: u32,
    @location(2) @interpolate(linear) m4_: f32,
    @builtin(frag_depth) m5_: f32,
}

@group(47) @binding(209) 
var<storage, read_write> G169663393_: array<vec2<i32>, 5>;
var<workgroup> G1614295956_: atomic<u32>;
var<private> G2720354059_: vec4<i32>;
@group(214) @binding(31) 
var<uniform> G925821790_: f32;
@group(46) @binding(107) 
var<uniform> G747718523_: u32;
var<private> G2420242291_: i32;
var<private> G3775213536_: bool = false;
@group(206) @binding(175) 
var<uniform> G835424525_: f32;
@group(27) @binding(56) 
var<storage, read_write> G1248477847_: i32;

fn f2907162265_() {
    var loc1164004658_: bool;
    var loc2093663414_: bool;

    loop {
        switch u32() {
            case 1383370910u: {
                break;
            }
            case 1383370911u: {
                return;
            }
            case 1383370912u: {
                continue;
            }
            default: {
                return;
            }
        }
        {
            break;
        }
        continuing {
            loop {
                continue;
            }
            let _e9_ = G169663393_;
            G169663393_ = _e9_;
            switch u32() {
                case 3004365407u: {
                }
                default: {
                }
            }
            switch 4294967295u {
                case 886677109u: {
                }
                default: {
                }
            }
            loop {
                break;
            }
        }
    }
    switch u32() {
        case 3062102008u: {
            return;
        }
        default: {
            return;
        }
    }
    return;
}

fn f3580557952_(arg0_1_: f32) -> f32 {
    var loc1902266017_: f32;
    var loc1849534170_: f32;

    let _e11_ = vec2(3446984205u);
    let _e18_ = loc1902266017_;
    let _e21_ = (_e11_ < _e11_);
    let _e22_ = any(_e21_);
    let _e24_ = loc1849534170_;
    let _e25_ = vec4<f32>(_e24_, _e18_, _e18_, _e18_);
    switch -1577895482 {
        case -611856063: {
            loop {
                let _e26_ = loc1902266017_;
                loc1902266017_ = _e26_;
                continue;
                continuing {
                    loc1902266017_ = _e24_;
                    loc1902266017_ = arg0_1_;
                    break if all(_e21_);
                }
            }
            return arg0_1_;
        }
        case -611856062: {
            loop {
                loc1902266017_ = _e24_;
                continuing {
                    f2907162265_();
                    f2907162265_();
                    break if _e22_;
                }
            }
        }
        case -611856061: {
            if _e22_ {
                return arg0_1_;
            } else {
                f2907162265_();
                f2907162265_();
                return _e18_;
            }
            return arg0_1_;
        }
        case -611856060: {
            loop {
                return _e18_;
                continuing {
                    f2907162265_();
                    break if _e22_;
                }
            }
            if _e22_ {
                return _e24_;
            } else {
                return _e24_;
            }
        }
        default: {
            G3775213536_ = _e22_;
            G3775213536_ = _e22_;
        }
    }
    switch 0u {
        default: {
            let _e51_ = G747718523_;
            switch _e51_ {
                default: {
                    G3775213536_ = _e22_;
                }
            }
            if (0u != 0u) {
                G3775213536_ = _e22_;
            } else {
                G3775213536_ = _e22_;
            }
            let _e60_ = any(_e21_);
            loop {
                G3775213536_ = _e60_;
                continuing {
                    G3775213536_ = _e60_;
                    break if _e60_;
                }
            }
        }
    }
    return sqrt(f32());
}

fn f1114570659_() {
    var loc4107084015_: f32;
    var loc4020947327_: f32;
    var loc4238893534_: f32;

    {
        loop {
            let _e4_ = loc4238893534_;
            loc4238893534_ = _e4_;
            continuing {
                f2907162265_();
                let _e8_ = vec2<i32>(0, 0);
                loop {
                    break;
                    continuing {
                        f2907162265_();
                    }
                }
            }
        }
        return;
    }
}

fn f1312158175_(arg0_2_: ptr<private, bool>, arg1_1_: ptr<private, bool>) -> mat4x3<f32> {
    var loc4101518164_: mat4x3<f32>;
    var loc1193821337_: mat4x3<f32>;
    var loc1483851579_: mat4x3<f32>;
    var loc670363452_: mat4x3<f32>;

    f1114570659_();
    let _e8_1 = vec4(117.38958);
    let _e10 = f3580557952_(117.38958);
    {
        {
            f2907162265_();
            let _e11 = f3580557952_(_e10);
        }
    }
    let _e17_ = G3775213536_;
    let _e18_1 = vec3(f32());
    let _e19_ = G2420242291_;
    let _e20_ = (_e17_ || _e17_);
    let _e21_1 = (_e20_ || _e20_);
    switch _e19_ {
        case 1540887892: {
            f1114570659_();
            return mat4x3<f32>(_e18_1, _e18_1, _e18_1, _e18_1);
        }
        case 1540887893: {
            let _e21 = f3580557952_(117.38958);
        }
        case 1540887894: {
            let _e23 = f3580557952_(10.834647);
            G2420242291_ = _e19_;
            f1114570659_();
        }
        case 1540887895: {
            G3775213536_ = bool();
        }
        case 1540887896: {
            let _e28 = f3580557952_(f32());
        }
        default: {
            f2907162265_();
        }
    }
    let _e38_ = vec3(_e21_1);
    switch 1432368026 {
        case 472909590: {
            (*arg0_2_) = bool();
        }
        case 472909591: {
            let _e33 = f3580557952_(10.834647);
            f1114570659_();
        }
        case 472909592: {
            switch 3232581229u {
                case 1334651995u: {
                    (*arg0_2_) = bool();
                }
                case 1334651996u: {
                    (*arg0_2_) = bool();
                }
                default: {
                    (*arg0_2_) = bool();
                }
            }
            {
                let _e39 = f3580557952_(9410895000000.0);
            }
            if bool() {
                f2907162265_();
            } else {
                f2907162265_();
            }
        }
        case 472909593: {
            loop {
                f1114570659_();
                continuing {
                    let _e41 = f3580557952_(117.38958);
                    break if bool();
                }
            }
            switch 3232581229u {
                case 3585733006u: {
                    (*arg0_2_) = bool();
                }
                default: {
                    (*arg0_2_) = bool();
                }
            }
        }
        case 472909594: {
            (*arg0_2_) = bool();
        }
        default: {
            f2907162265_();
        }
    }
    (*arg0_2_) = bool();
    let _e51_1 = _e8_1.yzww;
    if bool() {
        switch 3232581229u {
            case 1760640624u: {
            }
            case 1431414403u: {
                (*arg1_1_) = bool();
            }
            case 3336157505u: {
                (*arg0_2_) = bool();
            }
            case 1804517461u: {
                (*arg0_2_) = bool();
            }
            case 955447919u: {
                f2907162265_();
            }
            case 489511598u: {
                f2907162265_();
            }
            default: {
                f2907162265_();
            }
        }
        let _e56_ = !(bool());
        let _e59_ = any(_e38_);
        let _e60_1 = G747718523_;
        loop {
            if _e59_ {
                (*arg0_2_) = _e56_;
            }
            continuing {
                switch 3232581229u {
                    case 2895524799u: {
                        f1114570659_();
                    }
                    default: {
                        (*arg1_1_) = _e56_;
                    }
                }
                switch vec4<i32>()[_e60_1] {
                    case 1751870476: {
                    }
                    case 1751870477: {
                        let _e63 = f3580557952_(-5.059388e-32);
                    }
                    default: {
                        (*arg1_1_) = all(_e38_);
                    }
                }
                break if all(_e38_);
            }
        }
        (*arg1_1_) = _e56_;
        {
            (*arg1_1_) = _e56_;
            f2907162265_();
        }
    } else {
        loop {
            continue;
            continuing {
                (*arg1_1_) = false;
                (*arg1_1_) = false;
                break if false;
            }
        }
        let _e69 = f3580557952_(117.38958);
        (*arg0_2_) = _e21_1;
        f1114570659_();
        if _e21_1 {
            let _e72 = f3580557952_(_e69);
            (*arg1_1_) = false;
            (*arg1_1_) = _e21_1;
        } else {
            f1114570659_();
            let _e76 = f3580557952_(select(_e69, _e69, false));
            (*arg0_2_) = _e17_;
        }
    }
    let _e77 = loc4101518164_;
    return _e77;
}

@fragment 
fn ep16104854_(@builtin(sample_mask) arg0_: u32, arg1_: S2343830421_) -> S3159169591_ {
    var loc4130532180_: S3159169591_;

    loop {
        discard;
        continuing {
            {
                f1114570659_();
            }
            f1114570659_();
            let _e7 = G3775213536_;
            f1114570659_();
            break if _e7;
        }
    }
    loop {
        {
            discard;
        }
        continuing {
            loop {
                break;
                continuing {
                    f1114570659_();
                }
            }
            let _e12 = dpdxCoarse(vec4<f32>().y);
            G1248477847_ = -(vec2<i32>()).x;
            let _e18 = f3580557952_(_e12);
            switch vec2<i32>().y {
                case 94542987: {
                    G1248477847_ = vec2<i32>().y;
                }
                case 436668599: {
                    f1114570659_();
                }
                case 1394111590: {
                    f1114570659_();
                }
                default: {
                    G1248477847_ = vec2<i32>().y;
                }
            }
            loop {
                continuing {
                    f2907162265_();
                    let _e29 = f1312158175_((&G3775213536_), (&G3775213536_));
                    switch -(-(vec2(-(vec2<i32>()).x)))[~(vec2<i32>().y)] {
                        case -1605922292: {
                            let _e32 = f1312158175_((&G3775213536_), (&G3775213536_));
                        }
                        default: {
                            G1248477847_ = -(-(vec2(-(vec2<i32>()).x)))[~(vec2<i32>().y)];
                        }
                    }
                    break if (_e12 != _e18);
                }
            }
        }
    }
    return S3159169591_();
}
