cmake_minimum_required(VERSION 3.20)
project(cfg_generator LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

option(CFGGEN_BUILD_STATIC_LINUX "Build static Linux binary when possible" ON)

find_package(LLVM 17 CONFIG REQUIRED)
find_package(Clang CONFIG REQUIRED)

message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
message(STATUS "Using LLVMConfig.cmake in: ${LLVM_DIR}")

# CFG Generator executable
add_executable(cfg_generator
    src/cfg_generator_main.cpp
    src/analysis_output.cpp
    src/cfg_generation.cpp
    src/serialization.cpp
)

target_include_directories(cfg_generator PRIVATE
    ${LLVM_INCLUDE_DIRS}
    ${CLANG_INCLUDE_DIRS}
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

add_definitions(${LLVM_DEFINITIONS})

target_link_libraries(cfg_generator PRIVATE
    LLVM
    clangTooling
    clangFrontend
    clangSerialization
    clangDriver
    clangParse
    clangSema
    clangAnalysis
    clangAST
    clangASTMatchers
    clangBasic
    clangLex
)

# Callgraph generator executable
add_executable(callgraph_generator
    src/callgraph_generator_main.cpp
    src/callgraph_analysis.cpp
)

target_include_directories(callgraph_generator PRIVATE
    ${LLVM_INCLUDE_DIRS}
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(callgraph_generator PRIVATE
    LLVM
)

# Runtime log callgraph generator executable
add_executable(runtime_callgraph_generator
    src/runtime_callgraph_generator_main.cpp
    src/serialization.cpp
)

target_include_directories(runtime_callgraph_generator PRIVATE
    ${LLVM_INCLUDE_DIRS}
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(runtime_callgraph_generator PRIVATE
    LLVM
)

if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND CFGGEN_BUILD_STATIC_LINUX)
    # Note: Alpine LLVM 17 only provides dynamic libraries, so static linking won't work
    # Disabling static link options
    # target_link_options(cfg_generator PRIVATE
    #     -static
    #     -static-libgcc
    #     -static-libstdc++
    # )
endif()

install(TARGETS cfg_generator callgraph_generator runtime_callgraph_generator RUNTIME DESTINATION bin)
