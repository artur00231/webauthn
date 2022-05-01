include(${CMAKE_MODULE_PATH}LibFindMacros.cmake)

# Use pkg-config to get hints about paths
libfind_pkg_check_modules(LIBFIDO2_PKGCONF libfido2)

# Include dir
find_path(LIBFIDO2_INCLUDE_DIR
  NAMES fido.h
  PATHS ${LIBFIDO2_PKGCONF_INCLUDE_DIRS}
)

# Finally the library itself
find_library(LIBFIDO2_LIBRARY
  NAMES fido2
  PATHS ${LIBFIDO2_PKGCONF_LIBRARY_DIRS}
)

set(LIBFIDO2_PROCESS_INCLUDES LIBFIDO2_INCLUDE_DIR)
set(LIBFIDO2_PROCESS_LIBS LIBFIDO2_LIBRARY)

libfind_process(libfido2)