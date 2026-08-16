#!/bin/bash -eu
#
# OSS-Fuzz build script for the KineGrant reference implementation.
# Compiles each *_fuzzer.py into a libFuzzer target using Atheris.

pip3 install .

for fuzzer in "$SRC"/kinegrant-protocol/fuzz/*_fuzzer.py; do
    compile_python_fuzzer "$fuzzer"
done
