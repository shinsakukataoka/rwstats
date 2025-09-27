cmake_minimum_required(VERSION 3.14)
project(rwstats CXX)
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

include_directories("$ENV{DR_HOME}/tools/include")
link_directories("$ENV{DR_HOME}/tools/lib64/release" "$ENV{DR_HOME}/lib64/release")

add_library(rwstats_creator SHARED rwstats_creator.cpp rwstats_tool.cpp)
target_link_libraries(rwstats_creator PRIVATE drmemtrace_analyzer)

set_target_properties(rwstats_creator PROPERTIES
  BUILD_RPATH "$ENV{DR_HOME}/tools/lib64/release;$ENV{DR_HOME}/lib64/release"
  INSTALL_RPATH "$ENV{DR_HOME}/tools/lib64/release;$ENV{DR_HOME}/lib64/release")
