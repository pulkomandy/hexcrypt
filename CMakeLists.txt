cmake_minimum_required(VERSION 2.8)
project(hexcrypt)

include(cmake/CXX11.cmake)
enable_cxx11()

add_executable(test test.cpp)
add_executable(hexcrypt hexcrypt.cpp)
