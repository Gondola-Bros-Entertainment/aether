cmake_minimum_required(VERSION 3.23)
project(aether_package_test CXX)

# Consume aether exactly as an outside project would: find the installed package, link the imported
# target. NO CMAKE_CXX_STANDARD is set here on purpose -- linking aether::aether must pull in C++20
# via the exported target's compile features. If this configures, compiles, and links, the
# install/export rules are sound and the package is self-describing.
find_package(aether CONFIG REQUIRED)

add_executable(app main.cpp)
target_link_libraries(app PRIVATE aether::aether)
