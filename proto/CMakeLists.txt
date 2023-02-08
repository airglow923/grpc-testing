find_package(Protobuf REQUIRED)
find_package(GRPC REQUIRED)

file(GLOB_RECURSE PROTO_FILES ${CMAKE_CURRENT_LIST_DIR}/*.proto)

add_library(${LIBRARY_PROTO} OBJECT ${PROTO_FILES})

set_target_properties(${LIBRARY_PROTO} PROPERTIES POSITION_INDEPENDENT_CODE ON)

target_compile_options(
  ${LIBRARY_PROTO}
  PUBLIC ${COMMON_COMPILE_FLAGS} $<$<CONFIG:Debug>:${DEBUG_COMPILE_FLAGS}>
         $<$<CONFIG:Release>:${RELEASE_COMPILE_FLAGS}>)

target_include_directories(${LIBRARY_PROTO} PUBLIC ${CMAKE_CURRENT_BINARY_DIR})

target_link_options(
  ${LIBRARY_PROTO} PUBLIC ${COMMON_LINK_FLAGS}
  $<$<CONFIG:Debug>:${DEBUG_LINK_FLAGS}>
  $<$<CONFIG:Release>:${RELEASE_LINK_FLAGS}>)

target_link_libraries(
  ${LIBRARY_PROTO} PUBLIC protobuf::libprotobuf GRPC::grpc++
                          GRPC::grpc++_reflection)

protobuf_generate(TARGET ${LIBRARY_PROTO} LANGUAGE cpp)

# cmake-format: off
protobuf_generate(
  TARGET ${LIBRARY_PROTO}
  LANGUAGE grpc
  GENERATE_EXTENSIONS .grpc.pb.h .grpc.pb.cc
  PLUGIN "protoc-gen-grpc=\$<TARGET_FILE:GRPC::grpc_cpp_plugin>")
# cmake-format: on
