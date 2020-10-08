cmake_minimum_required(VERSION 3.11.0)
project(_memtrace)
set(Boost_USE_STATIC_LIBS ON)
find_package(Boost REQUIRED COMPONENTS python)
find_package(PythonExtensions REQUIRED)
message(STATUS "Boost_INCLUDE_DIRS = ${Boost_INCLUDE_DIRS}")
message(STATUS "Boost_LIBRARIES = ${Boost_LIBRARIES}")
include_directories(${Boost_INCLUDE_DIRS})
add_library(_memtrace MODULE memtrace_ext/memtrace_ext.cc)
target_compile_options(
    _memtrace
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
target_link_libraries(_memtrace ${Boost_LIBRARIES})
target_link_libraries(_memtrace capstone)
python_extension_module(_memtrace)
install(TARGETS _memtrace LIBRARY DESTINATION memtrace)
