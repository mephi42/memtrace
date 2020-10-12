cmake_minimum_required(VERSION 3.11.0)
project(_memtrace)
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
set(uname ${CMAKE_HOST_SYSTEM_NAME}-${CMAKE_HOST_SYSTEM_PROCESSOR})
set(elfutils_build ${CMAKE_CURRENT_SOURCE_DIR}/build/${uname}/elfutils)
set(elfutils_install ${elfutils_build}/install)
target_include_directories(
    _memtrace
    SYSTEM
    PRIVATE ${elfutils_install}/include
)
target_link_directories(_memtrace PRIVATE ${elfutils_install}/lib)
target_link_libraries(_memtrace ${Boost_LIBRARIES} dw)
target_link_libraries(_memtrace capstone)
python_extension_module(_memtrace)
install(TARGETS _memtrace LIBRARY DESTINATION memtrace)
