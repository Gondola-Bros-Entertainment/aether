cmake_minimum_required(VERSION 3.20)
project(aether CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)   # so clangd knows it's C++20
add_compile_options(-Wall -Wextra)

# The library is header-only; src/ holds only the platform layer (one translation unit).
file(GLOB AETHER_SRC CONFIGURE_DEPENDS src/*.cpp)
add_library(aether STATIC ${AETHER_SRC})
target_include_directories(aether PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

enable_testing()

# --- header self-containment ---
# Every public header must compile on its own (include what you use). One generated translation
# unit per header, each including only that header; no main, because compiling IS the test. If a
# header forgets an include, this target fails to build.
file(GLOB AETHER_HEADERS CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/include/aether/*.hpp)
set(selfcontained_srcs "")
foreach(hdr ${AETHER_HEADERS})
    get_filename_component(name ${hdr} NAME_WE)
    set(tu ${CMAKE_CURRENT_BINARY_DIR}/selfcontained/${name}.cpp)
    file(WRITE ${tu} "#include <aether/${name}.hpp>\n")
    list(APPEND selfcontained_srcs ${tu})
endforeach()
add_library(aether_selfcontained OBJECT ${selfcontained_srcs})
target_include_directories(aether_selfcontained PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)

# --- ODR / inline check ---
# The umbrella header included in two translation units, linked into one shared library: a
# non-inline definition in any header would be a duplicate symbol and the link would fail. A
# shared library links its objects (an archive would not), so building this IS the test -- again
# no main.
add_library(aether_odr SHARED test/odr_tu_a.cpp test/odr_tu_b.cpp)
target_include_directories(aether_odr PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)

# --- behavior tests ---
add_executable(aether_test test/roundtrip.cpp)
target_link_libraries(aether_test PRIVATE aether)
add_test(NAME roundtrip COMMAND aether_test)

# Per-module tests: any test/<name>_test.cpp auto-registers with ctest.
file(GLOB AETHER_MODULE_TESTS CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/test/*_test.cpp)
foreach(t ${AETHER_MODULE_TESTS})
    get_filename_component(name ${t} NAME_WE)
    add_executable(${name} ${t})
    target_link_libraries(${name} PRIVATE aether)
    add_test(NAME ${name} COMMAND ${name})
endforeach()

# Benchmark: built -O3, since unoptimized timings are meaningless.
add_executable(aether_bench bench/bench.cpp)
target_link_libraries(aether_bench PRIVATE aether)
target_compile_options(aether_bench PRIVATE -O3)
