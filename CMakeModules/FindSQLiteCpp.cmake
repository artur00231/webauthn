include(${CMAKE_MODULE_PATH}LibFindMacros.cmake)

# Use pkg-config to get hints about paths
libfind_pkg_check_modules(SQLiteCpp_PKGCONF SQLiteCpp)

# Include dir
find_path(SQLiteCpp_INCLUDE_DIR
  NAMES SQLiteCpp/SQLiteCpp.h
  PATHS ${SQLiteCpp_PKGCONF_INCLUDE_DIRS}
)

# Finally the library itself
find_library(SQLiteCpp_LIBRARY
  NAMES SQLiteCpp
  PATHS ${SQLiteCpp_PKGCONF_LIBRARY_DIRS}
)

set(SQLiteCpp_PROCESS_INCLUDES SQLiteCpp_INCLUDE_DIR)
set(SQLiteCpp_PROCESS_LIBS SQLiteCpp_LIBRARY)

libfind_process(SQLiteCpp)