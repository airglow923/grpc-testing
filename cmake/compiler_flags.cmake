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
