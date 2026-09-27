# ns3sim/CMakeLists.txt
#
# Standalone CMake build against the system ns-3 packages (libns3-dev on
# Ubuntu/Debian, or a Homebrew-built ns-3 on macOS -- see README.md for
# both). Not integrated into ns-3's own `ns3`/waf build system, since the
# Ubuntu package ships headers/libs only, not the build scaffolding for
# out-of-tree modules -- a plain CMake project linking against them
# directly is the simplest thing that works the same way on Linux and
# macOS.
cmake_minimum_required(VERSION 3.16)
project(saf_ns3_sim CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

find_package(PkgConfig REQUIRED)
pkg_check_modules(NS3 REQUIRED
  ns3-core
  ns3-network
  ns3-internet
  ns3-point-to-point
  ns3-applications
  ns3-flow-monitor
)
find_package(OpenSSL REQUIRED)
find_package(nlohmann_json 3.9 REQUIRED)
# Some ns-3 packages (e.g. Homebrew's, which depends on open-mpi) are built
# with MPI support, and their exported library list then names the
# MPI::MPI_CXX imported target -- even though this project never calls
# into MPI itself. Not REQUIRED: on builds without MPI support (e.g. the
# apt libns3-dev package used in CI/this repo's dev container) NS3_LIBRARIES
# never references it, so nothing below needs the target to exist.
find_package(MPI COMPONENTS CXX)

add_executable(saf-ns3-sim
  src/saf-crypto.cc
  src/saf-broker-app.cc
  src/saf-client-app.cc
  src/saf-sim.cc
)
target_include_directories(saf-ns3-sim PRIVATE src ${NS3_INCLUDE_DIRS})
target_compile_options(saf-ns3-sim PRIVATE ${NS3_CFLAGS_OTHER})
target_link_libraries(saf-ns3-sim PRIVATE ${NS3_LIBRARIES} OpenSSL::SSL OpenSSL::Crypto
                                            nlohmann_json::nlohmann_json)
target_link_directories(saf-ns3-sim PRIVATE ${NS3_LIBRARY_DIRS})

add_executable(saf-crosscheck-hmac
  src/saf-crypto.cc
  tools/crosscheck_hmac.cc
)
target_include_directories(saf-crosscheck-hmac PRIVATE src)
target_link_libraries(saf-crosscheck-hmac PRIVATE OpenSSL::SSL OpenSSL::Crypto)
