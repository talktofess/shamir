cmake_minimum_required(VERSION 3.16)
project(shamir LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Pure, dependency-free core: finite field, secret sharing, SHA-256, the secure
# RNG, and the share format.
add_library(shamir_core STATIC
    src/core/gf256.cpp
    src/core/shamir.cpp
    src/core/secure_rng.cpp
    src/core/sha256.cpp
    src/core/format.cpp
    src/core/mnemonic.cpp)
target_include_directories(shamir_core PUBLIC src)
if(WIN32)
    target_link_libraries(shamir_core PUBLIC advapi32)   # CryptGenRandom
endif()

# Test suite (no dependencies — builds and runs anywhere).
enable_testing()
add_executable(shamir_tests tests/main.cpp tests/test_shamir.cpp)
target_link_libraries(shamir_tests PRIVATE shamir_core)
target_include_directories(shamir_tests PRIVATE tests src)
add_test(NAME core COMMAND shamir_tests)

# The CLI: split / combine / demo.
add_executable(shamir src/main.cpp)
target_link_libraries(shamir PRIVATE shamir_core)
target_include_directories(shamir PRIVATE src)
