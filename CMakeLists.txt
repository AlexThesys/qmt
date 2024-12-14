cmake_minimum_required (VERSION 3.10)
project (q_mem_tools)

file(GLOB SOURCES "src/*.h" "src/*.cpp")

set(SOURCE_DIR ${CMAKE_SOURCE_DIR})
set(DEST_DIR ${CMAKE_BINARY_DIR})

add_executable(${PROJECT_NAME} ${SOURCES})