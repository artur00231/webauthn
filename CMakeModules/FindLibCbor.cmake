include(${CMAKE_MODULE_PATH}LibFindMacros.cmake)

# Use pkg-config to get hints about paths
libfind_pkg_check_modules(LIBCBOR_PKGCONF libcbor)

# Include dir
find_path(LIBCBOR_INCLUDE_DIR
  NAMES cbor.h
  PATHS ${LIBCBOR_PKGCONF_INCLUDE_DIRS}
)

# Finally the library itself
find_library(LIBCBOR_LIBRARY
  NAMES libcbor LibCbor LIBCBOR cbor CBOR
  PATHS ${LIBCBOR_PKGCONF_LIBRARY_DIRS}
)

set(LIBCBOR_PROCESS_INCLUDES LIBCBOR_INCLUDE_DIR)
set(LIBCBOR_PROCESS_LIBS LIBCBOR_LIBRARY)

libfind_process(libcbor)