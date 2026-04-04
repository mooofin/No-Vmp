cmake_minimum_required(VERSION 3.25)
project(NoVmp LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# LLVM (brew / apt / vcpkg / manual)
find_package(LLVM REQUIRED CONFIG)
message(STATUS "LLVM version: ${LLVM_PACKAGE_VERSION}")
llvm_map_components_to_libnames(LLVM_LIBS core support irreader passes analysis
    transformutils instcombine scalaropts)

# Capstone (system or vcpkg)
find_package(PkgConfig REQUIRED)
pkg_check_modules(CAPSTONE REQUIRED capstone)

# Submodules - note: linux-pe is in root, CLI11 needs to be added
if(EXISTS ${CMAKE_SOURCE_DIR}/linux-pe/CMakeLists.txt)
    add_subdirectory(linux-pe EXCLUDE_FROM_ALL)
else()
    message(WARNING "linux-pe submodule not found - PE parsing may not work")
endif()

# If CLI11 exists as submodule, use it, otherwise fetch it
if(EXISTS ${CMAKE_SOURCE_DIR}/third_party/CLI11)
    add_subdirectory(third_party/CLI11 EXCLUDE_FROM_ALL)
else()
    include(FetchContent)
    FetchContent_Declare(
        CLI11
        GIT_REPOSITORY https://github.com/CLIUtils/CLI11.git
        GIT_TAG v2.4.2
    )
    FetchContent_MakeAvailable(CLI11)
endif()

add_library(novmp_lib STATIC
    lib/disasm/stream.cpp
    lib/vmp/image_desc.cpp
    lib/vmp/vm_state.cpp
    lib/vmp/architecture.cpp
    lib/vmp/rkey.cpp
    lib/vmp/subroutines.cpp
    lib/vmp/lifter.cpp
    lib/ir/context.cpp
    lib/ir/vmp_to_llvm.cpp
    lib/emulator/emulator.cpp
    lib/emulator/rwx_allocator.cpp
)

target_include_directories(novmp_lib PUBLIC
    ${CMAKE_SOURCE_DIR}/lib
    ${CMAKE_SOURCE_DIR}/linux-pe/includes
    ${LLVM_INCLUDE_DIRS}
    ${CAPSTONE_INCLUDE_DIRS}
)

# Use llvm-config to get proper library linking for LLVM 22+
execute_process(COMMAND llvm-config --libs OUTPUT_VARIABLE LLVM_LINK_LIBS OUTPUT_STRIP_TRAILING_WHITESPACE)
execute_process(COMMAND llvm-config --ldflags OUTPUT_VARIABLE LLVM_LINK_FLAGS OUTPUT_STRIP_TRAILING_WHITESPACE)
string(STRIP "${LLVM_LINK_LIBS}" LLVM_LINK_LIBS)
string(STRIP "${LLVM_LINK_FLAGS}" LLVM_LINK_FLAGS)

target_link_libraries(novmp_lib PUBLIC
    ${LLVM_LINK_LIBS}
    ${CAPSTONE_LIBRARIES}
)

# Add LLVM link flags
target_link_options(novmp_lib PUBLIC ${LLVM_LINK_FLAGS})

target_compile_definitions(novmp_lib PUBLIC ${LLVM_DEFINITIONS})
target_compile_options(novmp_lib PRIVATE -Wall -Wextra -Wno-unused-parameter)

add_executable(novmp src/main.cpp)
target_link_libraries(novmp PRIVATE novmp_lib CLI11::CLI11)

# Platform-specific threading
find_package(Threads REQUIRED)
target_link_libraries(novmp PRIVATE Threads::Threads)

# Set include directories for the executable
target_include_directories(novmp PRIVATE ${CMAKE_SOURCE_DIR}/lib)
