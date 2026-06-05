cmake_minimum_required(VERSION 3.16)
project(shamir LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Pure, dependency-free core: the finite field + the secret-sharing scheme.
add_library(shamir_core STATIC
    src/core/gf256.cpp
    src/core/shamir.cpp)
target_include_directories(shamir_core PUBLIC src)

# Test suite (no dependencies — builds and runs anywhere).
enable_testing()
add_executable(shamir_tests tests/main.cpp tests/test_shamir.cpp)
target_link_libraries(shamir_tests PRIVATE shamir_core)
target_include_directories(shamir_tests PRIVATE tests src)
add_test(NAME core COMMAND shamir_tests)

# The terminal demo.
add_executable(shamir_demo src/main.cpp)
target_link_libraries(shamir_demo PRIVATE shamir_core)
target_include_directories(shamir_demo PRIVATE src)
