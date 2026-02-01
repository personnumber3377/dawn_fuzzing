mkdir -p profraw

export PATH=/home/oof/llvminstall/LLVM-21.1.0-Linux-X64/bin:$PATH

i=0
for f in corpus/*; do
  echo "[*] Running $f"
  i=$((i+1))
  LLVM_PROFILE_FILE="profraw/run_$i.profraw" \
    ./dawn_webgsl_and_vulkan_backend_fuzzer "$f" \
    -timeout=5 || true
done