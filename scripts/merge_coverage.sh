#!/bin/sh

export PATH=/home/oof/llvminstall/LLVM-21.1.0-Linux-X64/bin:$PATH

llvm-profdata merge -sparse profraw/*.profraw -o dawn_webgsl_and_vulkan_backend_fuzzer.profdata


llvm-cov show ./dawn_webgsl_and_vulkan_backend_fuzzer \
  -instr-profile=dawn_webgsl_and_vulkan_backend_fuzzer.profdata \
  -format=html \
  -output-dir=coverage_html \
  -Xdemangler=c++filt