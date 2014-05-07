#!/bin/sh

echo --- BUILDING... ---
mkdir -p build
pushd build
cmake ..
make
popd

echo --- TESTING... ---
build/test

echo --- DONE! ---
