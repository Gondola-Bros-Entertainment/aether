cmake_minimum_required(VERSION 3.20)
project(aether CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)   # so clangd knows it's C++20
add_compile_options(-Wall -Wextra)

# Static lib: header-only parts live in include/, platform code in src/.
file(GLOB AETHER_SRC CONFIGURE_DEPENDS src/*.cpp)
add_library(aether STATIC ${AETHER_SRC})
target_include_directories(aether PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

enable_testing()
add_executable(aether_test test/roundtrip.cpp)
target_link_libraries(aether_test PRIVATE aether)
add_test(NAME roundtrip COMMAND aether_test)

# Umbrella-header compile check: aether.hpp must pull in the whole library on its own.
add_executable(aether_umbrella test/umbrella.cpp)
target_link_libraries(aether_umbrella PRIVATE aether)
add_test(NAME umbrella COMMAND aether_umbrella)

# Benchmark: built -O3 regardless of the rest, since unoptimized timings are meaningless.
add_executable(aether_bench bench/bench.cpp)
target_link_libraries(aether_bench PRIVATE aether)
target_compile_options(aether_bench PRIVATE -O3)
