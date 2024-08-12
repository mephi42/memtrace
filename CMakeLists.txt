cmake_minimum_required(VERSION 3.12)
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
            -Wno-maybe-uninitialized
            -pedantic
            -Werror
            -fstack-protector-strong
            -D_FORTIFY_SOURCE=2
)
target_link_libraries(_memtrace ${Boost_LIBRARIES} capstone dw elf z)
python_extension_module(_memtrace)
install(TARGETS _memtrace LIBRARY DESTINATION memtrace)

add_custom_target(
    patch_valgrind
    COMMAND ${CMAKE_SOURCE_DIR}/patch-valgrind
)
set(valgrind_src ${CMAKE_SOURCE_DIR}/valgrind)
set(valgrind_tracer_src ${CMAKE_SOURCE_DIR}/valgrind-tracer)
set(uname ${CMAKE_SYSTEM_NAME}-${CMAKE_SYSTEM_PROCESSOR})
set(build ${CMAKE_SOURCE_DIR}/build/${uname})
set(valgrind_build ${build}/valgrind)
set(valgrind_install ${valgrind_build}/dist)
set(valgrind ${valgrind_install}/bin/valgrind)
add_custom_command(
    OUTPUT ${valgrind_src}/configure
    COMMAND ./autogen.sh
    DEPENDS patch_valgrind
            ${valgrind_src}/configure.ac
            ${valgrind_src}/Makefile.am
            ${valgrind_tracer_src}/Makefile.am
    WORKING_DIRECTORY ${valgrind_src}
)
execute_process(
    COMMAND ${CMAKE_C_COMPILER} -dumpmachine
    RESULT_VARIABLE err
    OUTPUT_VARIABLE host_triple
    OUTPUT_STRIP_TRAILING_WHITESPACE
)
if(NOT err EQUAL 0)
    message(SEND_ERROR "Could not determine the host triple")
endif()
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    set(valgrind_cflags -g0)
endif()
add_custom_command(
    OUTPUT ${valgrind_build}/Makefile
    COMMAND env
                AR=${CMAKE_AR}
                CFLAGS=${valgrind_cflags}
                ${valgrind_src}/configure
                    --host=${host_triple}
                    --prefix=${valgrind_install}
                    --with-mpicc=false
                    --with-gdbscripts-dir=no
                    ${VALGRIND_CONFIGURE_FLAGS}
    DEPENDS ${valgrind_src}/configure
    WORKING_DIRECTORY ${valgrind_build}
)
include(ProcessorCount)
ProcessorCount(nproc)
if(nproc EQUAL 0)
  set(nproc 1)
endif()
file(
    GLOB_RECURSE valgrind_source_files
    LIST_DIRECTORIES false
    ${valgrind_src}/*
    ${valgrind_tracer_src}/*
)
add_custom_command(
    OUTPUT ${valgrind}
    COMMAND make -j${nproc} install
    DEPENDS ${valgrind_build}/Makefile ${valgrind_source_files}
    WORKING_DIRECTORY ${valgrind_build}
)
add_custom_target(valgrind ALL DEPENDS ${valgrind})
install(DIRECTORY ${valgrind_install}/
        DESTINATION ${CMAKE_INSTALL_PREFIX}/memtrace/tracer/${uname}
        USE_SOURCE_PERMISSIONS)
