cmake_minimum_required(VERSION 3.23)   # FILE_SET HEADERS (install-interface header sets)
project(aether VERSION 0.1.0 LANGUAGES CXX)

include(GNUInstallDirs)   # CMAKE_INSTALL_{INCLUDEDIR,LIBDIR,BINDIR} for the install rules below

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)   # so clangd knows it's C++20
# Warnings always on; warnings-as-errors is opt-in (ON in CI, off for consumers, so a newer
# compiler's new warnings never break someone just using the library). add_compile_options appends,
# so MSVC keeps its default /EHsc -- passing -DCMAKE_CXX_FLAGS=/WX would clobber that and break it.
option(AETHER_WERROR "treat warnings as errors" OFF)
if(MSVC)
    add_compile_options(/W4)
    if(AETHER_WERROR)
        add_compile_options(/WX)
    endif()
else()
    add_compile_options(-Wall -Wextra)
    if(AETHER_WERROR)
        add_compile_options(-Werror)
    endif()
endif()

# Platform layer: the one translation unit. CMake selects the backend so neither file needs an
# #ifdef -- socket_posix.cpp (BSD sockets, mac/linux) or socket_win.cpp (Winsock).
if(WIN32)
    add_library(aether STATIC src/socket_win.cpp)
    target_link_libraries(aether PUBLIC ws2_32 bcrypt)
else()
    add_library(aether STATIC src/socket_posix.cpp)
endif()
# Public headers as a FILE_SET (also drives the self-containment check below). BASE_DIRS wires the
# build-interface include dir; install(... FILE_SET HEADERS) below adds the install-interface dir and
# ships the headers -- one declaration in place of a target_include_directories + install(DIRECTORY).
file(GLOB AETHER_HEADERS CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/include/aether/*.hpp)
target_sources(aether PUBLIC
    FILE_SET HEADERS
    BASE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/include
    FILES ${AETHER_HEADERS})
target_compile_features(aether PUBLIC cxx_std_20)   # exported: consumers get C++20 without setting it themselves
add_library(aether::aether ALIAS aether)   # same target name in-tree (add_subdirectory) and installed

enable_testing()

# --- header self-containment ---
# Every public header must compile on its own (include what you use). One generated translation
# unit per header, each including only that header; no main, because compiling IS the test. If a
# header forgets an include, this target fails to build.
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

# Benchmark: optimized (-O3, or /O2 on MSVC), since unoptimized timings are meaningless. /O2 is
# skipped in an MSVC Debug config though -- it collides with Debug's /RTC1 (error D8016). CI smoke-
# runs the bench in Debug (timings do not matter there); a real benchmark run uses a Release config.
add_executable(aether_bench bench/bench.cpp)
target_link_libraries(aether_bench PRIVATE aether)
target_compile_options(aether_bench PRIVATE $<IF:$<CXX_COMPILER_ID:MSVC>,$<$<NOT:$<CONFIG:Debug>>:/O2>,-O3>)
add_test(NAME bench COMMAND aether_bench)   # smoke: the bench must actually run (catches a DCE/UB regression)

# Opt-in comparison benchmark: aether vs zpp::bits. Fetches an external lib, so it is OFF by
# default and never touches the library's zero-dependency build:
#   cmake -B build -DAETHER_BENCH_COMPARE=ON && cmake --build build --target aether_bench_compare
option(AETHER_BENCH_COMPARE "Build the serializer comparison benchmark (fetches zpp::bits)" OFF)
if(AETHER_BENCH_COMPARE)
    include(FetchContent)
    FetchContent_Declare(zpp_bits
        GIT_REPOSITORY https://github.com/eyalz800/zpp_bits.git
        GIT_TAG v4.4.24
        GIT_SHALLOW TRUE)
    FetchContent_MakeAvailable(zpp_bits)
    add_executable(aether_bench_compare bench/compare.cpp)
    target_link_libraries(aether_bench_compare PRIVATE aether)
    target_include_directories(aether_bench_compare PRIVATE ${zpp_bits_SOURCE_DIR})
    target_compile_options(aether_bench_compare PRIVATE $<IF:$<CXX_COMPILER_ID:MSVC>,$<$<NOT:$<CONFIG:Debug>>:/O2>,-O3>)
endif()

# --- install / export ---
# Make aether consumable from outside the tree. An installed prefix exposes
# find_package(aether CONFIG) -> the imported target aether::aether, the same name the in-tree
# ALIAS gives add_subdirectory / FetchContent consumers. Default ON only when aether is the
# top-level build, so a parent project that pulls aether in does not inherit its install rules.
option(AETHER_INSTALL "Generate aether install + export rules" ${PROJECT_IS_TOP_LEVEL})

if(AETHER_INSTALL)
    include(CMakePackageConfigHelpers)
    set(AETHER_CMAKEDIR ${CMAKE_INSTALL_LIBDIR}/cmake/aether)

    install(TARGETS aether
        EXPORT aetherTargets
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
        LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
        RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
        FILE_SET HEADERS DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})   # ships the headers + the install-interface include dir

    install(EXPORT aetherTargets
        FILE aetherTargets.cmake
        NAMESPACE aether::
        DESTINATION ${AETHER_CMAKEDIR})

    configure_package_config_file(
        ${CMAKE_CURRENT_SOURCE_DIR}/cmake/aetherConfig.cmake.in
        ${CMAKE_CURRENT_BINARY_DIR}/aetherConfig.cmake
        INSTALL_DESTINATION ${AETHER_CMAKEDIR})

    write_basic_package_version_file(
        ${CMAKE_CURRENT_BINARY_DIR}/aetherConfigVersion.cmake
        VERSION ${PROJECT_VERSION}
        COMPATIBILITY SameMinorVersion)   # pre-1.0: each 0.x minor may break, so match major.minor

    install(FILES
        ${CMAKE_CURRENT_BINARY_DIR}/aetherConfig.cmake
        ${CMAKE_CURRENT_BINARY_DIR}/aetherConfigVersion.cmake
        DESTINATION ${AETHER_CMAKEDIR})
endif()
