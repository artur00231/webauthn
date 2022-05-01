cmake_minimum_required (VERSION 3.8)

project ("Webauthn")

include(FetchContent)
FetchContent_Declare(
	googletest
	# Specify the commit you depend on and update it regularly.
	URL https://github.com/google/googletest/archive/refs/tags/release-1.11.0.zip
)

# For Windows: Prevent overriding the parent project's compiler/linker settings
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

enable_testing()

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED True)

IF (WIN32)
ELSE()
	set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_CURRENT_SOURCE_DIR}/CMakeModules/")
ENDIF()

# Include sub-projects.
add_subdirectory(CBORLib)
add_subdirectory(CBORTests)
add_subdirectory(Crypto)
add_subdirectory(CryptoTests)
add_subdirectory(Webauthn)
add_subdirectory(WebauthnTests)