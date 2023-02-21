set(COMMON_WARNING_FLAGS -Wall -Wextra -Werror -Wcast-qual -Wno-comment)

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

if(DO_ADDRESS_SANITIZER)
  set(COMMON_COMPILE_FLAGS ${COMMON_COMPILE_FLAGS} ${ASAN_FLAGS})
  set(COMMON_LINK_FLAGS ${COMMON_LINK_FLAGS} ${ASAN_FLAGS})
endif()

if(DO_THREAD_SANITIZER)
  set(COMMON_COMPILE_FLAGS ${COMMON_COMPILE_FLAGS} ${TSAN_FLAGS})
  set(COMMON_LINK_FLAGS ${COMMON_LINK_FLAGS} ${TSAN_FLAGS})
endif()
