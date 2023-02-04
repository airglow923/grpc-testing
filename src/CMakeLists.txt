set(EXES client server)

file(GLOB_RECURSE SOURCE_FILES ${CMAKE_CURRENT_LIST_DIR}/*.cc)

foreach(EXE ${EXES})
  set(${EXE}_SOURCE ${CMAKE_CURRENT_LIST_DIR}/hyundeok/grpc/${EXE}/main.cc)
  list(REMOVE_ITEM SOURCE_FILES ${${EXE}_SOURCE})
endforeach()

target_sources(${LIBRARY_OBJLIB} PRIVATE ${SOURCE_FILES})

set_target_properties(${LIBRARY_OBJLIB} PROPERTIES POSITION_INDEPENDENT_CODE ON)

target_compile_options(
  ${LIBRARY_OBJLIB}
  PUBLIC ${COMMON_COMPILE_FLAGS} $<$<CONFIG:Debug>:${DEBUG_COMPILE_FLAGS}>
         $<$<CONFIG:Release>:${RELEASE_COMPILE_FLAGS}> ${THIRD_PARTY_CFLAGS})

target_include_directories(
  ${LIBRARY_OBJLIB}
  PUBLIC $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
         $<INSTALL_INTERFACE:${PROJECT_SOURCE_DIR}/include>
         ${THIRD_PARTY_INCLUDE_DIRS})

target_link_options(
  ${LIBRARY_OBJLIB} PUBLIC ${COMMON_LINK_FLAGS}
  $<$<CONFIG:Debug>:${DEBUG_LINK_FLAGS}>
  $<$<CONFIG:Release>:${RELEASE_LINK_FLAGS}>)

target_link_directories(${LIBRARY_OBJLIB} PUBLIC
                        ${THIRD_PARTY_LINK_DIRECTORIES})

target_link_libraries(${LIBRARY_OBJLIB} PUBLIC ${THIRD_PARTY_LINK_LIBRARIES})

add_custom_command(
  OUTPUT ${SOURCE_FILES} POST_BUILD
  COMMAND
    ${CMAKE_COMMAND} -E copy_if_different
    ${CMAKE_BINARY_DIR}/compile_commands.json
    ${CMAKE_SOURCE_DIR}/compile_commands.json
  DEPENDS ${LIBRARY_OBJLIB})

target_link_libraries(${LIBRARY_SHARED} PUBLIC ${LIBRARY_OBJLIB})
target_link_libraries(${LIBRARY_STATIC} PUBLIC ${LIBRARY_OBJLIB})

set_target_properties(${LIBRARY_SHARED} ${LIBRARY_STATIC}
                      PROPERTIES OUTPUT_NAME "${PROJECT_NAME}")

foreach(EXE ${EXES})
  set(EXECUTABLE_NAME ${PROJECT_NAME}-${EXE})

  target_sources(${EXECUTABLE_NAME} PRIVATE ${${EXE}_SOURCE})

  target_link_libraries(${EXECUTABLE_NAME} PRIVATE ${LIBRARY_OBJLIB})
endforeach()
