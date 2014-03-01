include_directories(BEFORE ${CMAKE_CURRENT_BINARY_DIR})

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

set(sqlite3_SRCS
    sqlite3.h
    sqlite3.c
)

add_library(sqlite3Static STATIC ${sqlite3_SRCS})
if (UNIX)
    # the output name of the static library shouldn't conflict with the
    # shared library because they use different extensions (.a versus .so)
    set_target_properties(sqlite3Static PROPERTIES OUTPUT_NAME sqlite3)
endif ()
target_link_libraries(sqlite3Static)
