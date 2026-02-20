# FindSqliteVec.cmake  –  Locate the sqlite-vec extension
#
# sqlite-vec is a SQLite extension that provides vector-search capabilities.
# It is typically installed as a shared library (vec0.so / sqlite_vec.so) and
# an optional header (sqlite-vec.h).
#
# This module defines:
#   SQLITEVEC_FOUND        - TRUE if the extension was found
#   SQLITEVEC_INCLUDE_DIRS - Include directory (if a header is present)
#   SQLITEVEC_LIBRARIES    - Full path to the shared extension library
#   SQLITEVEC_LIBRARY      - Same as SQLITEVEC_LIBRARIES (alias)
#
# Imported target:
#   SqliteVec::SqliteVec   - SHARED IMPORTED target ready for
#                            target_link_libraries()
#
# Hints:
#   Set SQLITEVEC_ROOT or CMAKE_PREFIX_PATH to guide the search.

include(FindPackageHandleStandardArgs)

# --- header (optional) -----------------------------------------------------
find_path(SQLITEVEC_INCLUDE_DIR
    NAMES sqlite-vec.h
    HINTS
        ${SQLITEVEC_ROOT}
        ENV SQLITEVEC_ROOT
    PATH_SUFFIXES include
)

# --- library ---------------------------------------------------------------
# The extension may be built as sqlite_vec.so, vec0.so, or libsqlite_vec.so
# depending on the distribution/build method.
find_library(SQLITEVEC_LIBRARY
    NAMES sqlite_vec vec0 libsqlite_vec
    HINTS
        ${SQLITEVEC_ROOT}
        ENV SQLITEVEC_ROOT
    PATH_SUFFIXES lib lib64 lib/sqlite3
)

# --- standard validation ---------------------------------------------------
find_package_handle_standard_args(SqliteVec
    REQUIRED_VARS SQLITEVEC_LIBRARY
    FAIL_MESSAGE  "sqlite-vec extension not found. Set SQLITEVEC_ROOT to the install prefix."
)

# --- exported variables -----------------------------------------------------
if(SQLITEVEC_FOUND)
    set(SQLITEVEC_LIBRARIES    ${SQLITEVEC_LIBRARY})
    set(SQLITEVEC_INCLUDE_DIRS ${SQLITEVEC_INCLUDE_DIR})

    if(NOT TARGET SqliteVec::SqliteVec)
        add_library(SqliteVec::SqliteVec UNKNOWN IMPORTED)
        set_target_properties(SqliteVec::SqliteVec PROPERTIES
            IMPORTED_LOCATION             "${SQLITEVEC_LIBRARY}"
        )
        if(SQLITEVEC_INCLUDE_DIR)
            set_target_properties(SqliteVec::SqliteVec PROPERTIES
                INTERFACE_INCLUDE_DIRECTORIES "${SQLITEVEC_INCLUDE_DIR}"
            )
        endif()
    endif()
endif()

mark_as_advanced(
    SQLITEVEC_INCLUDE_DIR
    SQLITEVEC_LIBRARY
)
