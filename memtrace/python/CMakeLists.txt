cmake_minimum_required(VERSION 3.11.0)
project(memtrace_ext)
set(Boost_USE_STATIC_LIBS ON)
find_package(Boost REQUIRED COMPONENTS python)
find_package(PythonExtensions REQUIRED)
message(STATUS "Boost_INCLUDE_DIRS = ${Boost_INCLUDE_DIRS}")
message(STATUS "Boost_LIBRARIES = ${Boost_LIBRARIES}")
include_directories(${Boost_INCLUDE_DIRS})
add_library(memtrace_ext MODULE memtrace_ext/memtrace_ext.cpp)
target_compile_options(
    memtrace_ext
    PRIVATE -std=c++17
            -Wall
            -Wextra
            -Wconversion
            -Wdate-time
            -Wformat-security
            -pedantic
            -Werror
            -fstack-protector-strong
            -D_FORTIFY_SOURCE=2
)
target_link_libraries(memtrace_ext ${Boost_LIBRARIES})
target_link_libraries(memtrace_ext capstone)
python_extension_module(memtrace_ext)
install(TARGETS memtrace_ext LIBRARY DESTINATION memtrace_ext)
