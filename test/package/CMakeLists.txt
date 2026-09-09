cmake_minimum_required(VERSION 3.23)
project(aether_package_test CXX)

# Leave CMAKE_CXX_STANDARD unset: the imported target must propagate C++20.
find_package(aether CONFIG REQUIRED)

add_executable(app main.cpp)
target_link_libraries(app PRIVATE aether::aether)

enable_testing()
add_test(NAME installed_consumer COMMAND app)
