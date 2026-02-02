#!/bin/sh

rm dawn_webgsl_and_vulkan_backend_fuzzer.zip
cp /home/oof/dawn/out/fuzzing/dawn_webgsl_and_vulkan_backend_fuzzer .

zip -r dawn_webgsl_and_vulkan_backend_fuzzer.zip dawn_webgsl_and_vulkan_backend_fuzzer

rm dawn_webgsl_and_vulkan_backend_fuzzer

# ca