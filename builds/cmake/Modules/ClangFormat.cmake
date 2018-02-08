# additional target to perform clang-format run, requires clang-format

# get all project files
file(GLOB_RECURSE ALL_SOURCE_FILES 
     RELATIVE ${CMAKE_CURRENT_BINARY_DIR} 
     ${CMAKE_SOURCE_DIR}/src/*.cpp ${CMAKE_SOURCE_DIR}/src/*.h ${CMAKE_SOURCE_DIR}/src/*.hpp 
     ${CMAKE_SOURCE_DIR}/tests/*.cpp ${CMAKE_SOURCE_DIR}/tests/*.h ${CMAKE_SOURCE_DIR}/tests/*.hpp 
     ${CMAKE_SOURCE_DIR}/perf/*.cpp ${CMAKE_SOURCE_DIR}/perf/*.h ${CMAKE_SOURCE_DIR}/perf/*.hpp 
     ${CMAKE_SOURCE_DIR}/tools/*.cpp ${CMAKE_SOURCE_DIR}/tools/*.h ${CMAKE_SOURCE_DIR}/tools/*.hpp 
     ${CMAKE_SOURCE_DIR}/include/*.h
    )

if("${CLANG_FORMAT}" STREQUAL "")
  set(CLANG_FORMAT "clang-format")
endif()

add_custom_target(
        clang-format
        COMMAND ${CLANG_FORMAT} -style=file -i ${ALL_SOURCE_FILES}
)

function(JOIN VALUES GLUE OUTPUT)
  string (REPLACE ";" "${GLUE}" _TMP_STR "${VALUES}")
  set (${OUTPUT} "${_TMP_STR}" PARENT_SCOPE)
endfunction()

configure_file(builds/cmake/clang-format-check.sh.in clang-format-check.sh @ONLY)

add_custom_target(
        clang-format-check
        COMMAND chmod +x clang-format-check.sh
        COMMAND ./clang-format-check.sh
        COMMENT "Checking correct formatting according to .clang-format file using ${CLANG_FORMAT}"
)

add_custom_target(
        clang-format-diff
        COMMAND ${CLANG_FORMAT} -style=file -i ${ALL_SOURCE_FILES}
        COMMAND git diff ${ALL_SOURCE_FILES}
        COMMENT "Formatting with clang-format (using ${CLANG_FORMAT}) and showing differences with latest commit"
)
