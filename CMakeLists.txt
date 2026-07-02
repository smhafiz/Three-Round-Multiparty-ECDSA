cmake_minimum_required(VERSION 3.29)
project(Three-Round-Multiparty-ECDSA LANGUAGES CXX)

option(TRECDSA_BUILD_TESTS "Build tests" ON)
option(TRECDSA_BUILD_BENCH "Build benchmark" OFF)
option(TRECDSA_WARNINGS_AS_ERRORS "Treat warnings as errors for project targets" OFF)
option(TRECDSA_ENABLE_SANITIZERS "Enable AddressSanitizer and UndefinedBehaviorSanitizer" OFF)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(TRECDSA_BICYCL_DIR "${CMAKE_CURRENT_SOURCE_DIR}/include/bicycl")
if(NOT EXISTS "${TRECDSA_BICYCL_DIR}/CMakeLists.txt")
    message(FATAL_ERROR "Could not find bicycl dependency under include/.")
endif()
add_subdirectory("${TRECDSA_BICYCL_DIR}" "${CMAKE_BINARY_DIR}/deps/bicycl" EXCLUDE_FROM_ALL)

get_target_property(BICYCL_INTERFACE_INCLUDES bicycl INTERFACE_INCLUDE_DIRECTORIES)
if(BICYCL_INTERFACE_INCLUDES)
    set_property(TARGET bicycl PROPERTY INTERFACE_SYSTEM_INCLUDE_DIRECTORIES "${BICYCL_INTERFACE_INCLUDES}")
endif()

find_library(GMP_LIBRARY gmp REQUIRED)
find_library(GMPXX_LIBRARY gmpxx REQUIRED)
find_package(OpenSSL REQUIRED)

add_library(trecdsa_project_options INTERFACE)

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(trecdsa_project_options INTERFACE -Wall -Wextra -Wpedantic -Wconversion)
    if(TRECDSA_WARNINGS_AS_ERRORS)
        target_compile_options(trecdsa_project_options INTERFACE -Werror)
    endif()
    target_compile_options(trecdsa_project_options INTERFACE
        $<$<CONFIG:Debug>:-O0 -g3 -fno-omit-frame-pointer>
        $<$<CONFIG:Release>:-O3 -DNDEBUG>
        $<$<CONFIG:RelWithDebInfo>:-O2 -g -DNDEBUG>
    )
    if(TRECDSA_ENABLE_SANITIZERS)
        target_compile_options(trecdsa_project_options INTERFACE -fsanitize=address,undefined -fno-omit-frame-pointer)
        target_link_options(trecdsa_project_options INTERFACE -fsanitize=address,undefined)
    endif()
elseif(MSVC)
    target_compile_options(trecdsa_project_options INTERFACE /W4 /permissive- /EHsc)
    if(TRECDSA_WARNINGS_AS_ERRORS)
        target_compile_options(trecdsa_project_options INTERFACE /WX)
    endif()
endif()

add_library(trecdsa_core
    src/protocol/protocol_unit.cpp
)

target_compile_features(trecdsa_core PUBLIC cxx_std_17)

target_include_directories(trecdsa_core
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(trecdsa_core
    PRIVATE
        trecdsa_project_options
        bicycl
        ${GMP_LIBRARY}
        ${GMPXX_LIBRARY}
        OpenSSL::SSL
    PUBLIC
        OpenSSL::Crypto
)

add_executable(trecdsa_cli apps/cli/main.cpp)
target_link_libraries(trecdsa_cli PRIVATE trecdsa_core trecdsa_project_options)
set_target_properties(trecdsa_cli PROPERTIES OUTPUT_NAME Three-Round-Multiparty-ECDSA)

if(TRECDSA_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()

if(TRECDSA_BUILD_BENCH)
    add_executable(trecdsa_bench apps/bench/main.cpp)
    target_link_libraries(trecdsa_bench PRIVATE trecdsa_core trecdsa_project_options)
    set_target_properties(trecdsa_bench PROPERTIES OUTPUT_NAME trecdsa-bench)
endif()
