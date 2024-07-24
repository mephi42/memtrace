cmake_minimum_required(VERSION 3.11.0)
project(_memtrace)
string(REPLACE "." ";" _VERSION "${PYTHON_VERSION_STRING}")
list(GET _VERSION 0 PYTHON_VERSION_MAJOR)
list(GET _VERSION 1 PYTHON_VERSION_MINOR)
find_package(
    Boost
    REQUIRED
    COMPONENTS "python${PYTHON_VERSION_MAJOR}${PYTHON_VERSION_MINOR}"
)
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
target_link_libraries(_memtrace ${Boost_LIBRARIES} capstone dw elf z)
python_extension_module(_memtrace)
install(TARGETS _memtrace LIBRARY DESTINATION memtrace)
