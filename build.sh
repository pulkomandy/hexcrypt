#!/bin/sh

echo --- BUILDING... ---
mkdir -p build
cd build
	cmake ..
	make
cd ..

echo --- TESTING... ---
build/test

echo --- DONE! ---
