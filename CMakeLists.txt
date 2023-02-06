cmake_minimum_required(VERSION 3.13)

project(
  grpc-testing
  VERSION 0.0.1
  DESCRIPTION "Testing gRPC"
  LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

list(INSERT CMAKE_MODULE_PATH 0 ${CMAKE_CURRENT_LIST_DIR}/cmake)

include(utils)

find_package(PkgConfig REQUIRED)
find_package(Threads REQUIRED)

pkg_search_module(PROTOBUF REQUIRED protobuf)
pkg_search_module(GRPC REQUIRED grpc)

set(COMMON_WARNING_FLAGS -Wall -Wextra -Werror -Wcast-qual)

set(COMMON_COMPILE_FLAGS ${COMMON_WARNING_FLAGS} -march=native -flto)

set(COVERAGE_FLAGS -ftest-coverage -fprofile-arcs -pg)

set(ASAN_FLAGS -fsanitize=address -fsanitize-address-use-after-scope
               -fsanitize-recover=address -fno-omit-frame-pointer)

set(TSAN_FLAGS -fsanitize=thread)

set(DEBUG_COMPILE_FLAGS -Og)

set(RELEASE_COMPILE_FLAGS)

set(COMMON_LINK_FLAGS -flto $<$<CONFIG:Debug>:${COVERAGE_FLAGS}>
                      ${CMAKE_THREAD_LIBS_INIT})

set(DEBUG_LINK_FLAGS)
set(RELEASE_LINK_FLAGS)

set(THIRD_PARTY_CFLAGS ${PROTOBUF_CFLAGS} ${GRPC_CFLGAS})

set(THIRD_PARTY_INCLUDE_DIRS ${PROTOBUF_INCLUDE_DIRS} ${GRPC_INCLUDE_DIRS})

set(THIRD_PARTY_LINK_DIRECTORIES ${PROTOBUF_LINK_DIRECTORIES}
                                 ${GRPC_LINK_DIRECTORIES})

set(THIRD_PARTY_LINK_LIBRARIES ${PROTOBUF_LIBRARIES} ${GRPC_LIBRARIES})

set(LIBRARY_OBJLIB ${PROJECT_NAME}_OBJLIB)
set(LIBRARY_SHARED ${PROJECT_NAME}_SHARED)
set(LIBRARY_STATIC ${PROJECT_NAME}_STATIC)
set(EXECUTABLE_CLIENT ${PROJECT_NAME}-client)
set(EXECUTABLE_SERVER ${PROJECT_NAME}-server)

add_library(${LIBRARY_OBJLIB} OBJECT)
add_library(${LIBRARY_SHARED} SHARED)
add_library(${LIBRARY_STATIC} STATIC)
add_executable(${EXECUTABLE_CLIENT})
add_executable(${EXECUTABLE_SERVER})

add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/include)
add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/src)

install(
  TARGETS ${LIBRARY_SHARED} ${LIBRARY_STATIC} ${EXECUTABLE_CLIENT}
          ${EXECUTABLE_SERVER}
  LIBRARY DESTINATION lib
  ARCHIVE DESTINATION lib
  RUNTIME DESTINATION bin
  PUBLIC_HEADER DESTINATION include)
