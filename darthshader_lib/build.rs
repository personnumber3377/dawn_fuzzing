use std::path::PathBuf;

fn build_wgsl() {
    let dir: PathBuf = ["tree-sitter-wgsl", "src"].iter().collect();

    println!("cargo:rerun-if-changed={}", dir.display());

    let mut build = cc::Build::new();

    build
        .cpp(true)                    // IMPORTANT: C++
        .compiler("clang++")           // IMPORTANT
        .include(&dir)
        .file(dir.join("parser.c"))
        .file(dir.join("scanner.cc"))
        .flag("-stdlib=libc++")        // IMPORTANT
        .flag("-fPIC")
        .flag_if_supported("-Wno-unused-parameter")
        .flag_if_supported("-Wno-unused-but-set-variable");

    build.compile("tree-sitter-wgsl");

    // Tell Rust to link libc++
    println!("cargo:rustc-link-lib=c++");
    println!("cargo:rustc-link-lib=c++abi");
}

fn main() {
    build_wgsl();
}