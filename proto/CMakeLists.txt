find_package(Protobuf REQUIRED)
find_package(gRPC REQUIRED)

file(GLOB_RECURSE PROTO_FILES ${CMAKE_CURRENT_LIST_DIR}/*.proto)

add_library(${LIBRARY_PROTO} OBJECT ${PROTO_FILES})

set_target_properties(${LIBRARY_PROTO} PROPERTIES POSITION_INDEPENDENT_CODE ON)

target_include_directories(${LIBRARY_PROTO} PUBLIC ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(${LIBRARY_PROTO} PUBLIC protobuf::libprotobuf
                                              gRPC::grpc++)

protobuf_generate(TARGET ${LIBRARY_PROTO} LANGUAGE cpp)

# cmake-format: off
protobuf_generate(
  TARGET ${LIBRARY_PROTO}
  LANGUAGE grpc
  GENERATE_EXTENSIONS .grpc.pb.h .grpc.pb.cc
  PLUGIN "protoc-gen-grpc=\$<TARGET_FILE:gRPC::grpc_cpp_plugin>")
# cmake-format: on
