cmake_minimum_required(VERSION 3.15)
project(refuzz_logging CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
add_compile_options(-Wall -Wextra -Werror)

add_library(refuzz_logging
    src/host_logger.cpp
)
set_target_properties(refuzz_logging PROPERTIES POSITION_INDEPENDENT_CODE ON)

target_include_directories(refuzz_logging
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

install(TARGETS refuzz_logging
    EXPORT reFuzz_vm_targets
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
)

install(DIRECTORY include/
    DESTINATION include
)
