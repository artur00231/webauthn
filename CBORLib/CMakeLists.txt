
IF (WIN32)
	find_package(LibCbor REQUIRED)
ELSE()
	include(${CMAKE_MODULE_PATH}FindLibCbor.cmake)
ENDIF()

add_library(CBORLib
	CBORLib.cpp
)

target_link_libraries(CBORLib PRIVATE ${LIBCBOR_LIBRARY})

target_include_directories(CBORLib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR} ${LIBCBOR_INCLUDE_DIR})