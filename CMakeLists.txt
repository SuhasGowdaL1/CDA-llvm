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

add_executable(cfg_generator
    src/main.cpp
)

target_include_directories(cfg_generator PRIVATE
    ${LLVM_INCLUDE_DIRS}
    ${CLANG_INCLUDE_DIRS}
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

if(CMAKE_SYSTEM_NAME STREQUAL "Linux" AND CFGGEN_BUILD_STATIC_LINUX)
    target_link_options(cfg_generator PRIVATE
        -static
        -static-libgcc
        -static-libstdc++
    )
endif()

install(TARGETS cfg_generator RUNTIME DESTINATION bin)
