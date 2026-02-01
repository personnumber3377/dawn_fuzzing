#!/bin/sh

# cp /home/oof/darthshader_library/darthshader/target/debug/libdarthshader_mutator.so .

cp /home/oof/darthshader_library/darthshader/target/release/libdarthshader_mutator.so .

clang++ test.c -o test

./test shader.wgsl

