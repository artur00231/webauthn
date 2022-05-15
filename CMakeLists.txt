cmake_minimum_required (VERSION 3.15)

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

FetchContent_Declare(
	tl_expected
	# Specify the commit you depend on and update it regularly.
	URL https://github.com/TartanLlama/expected/archive/96d547c03d2feab8db64c53c3744a9b4a7c8f2c5.zip
)
FetchContent_MakeAvailable(tl_expected)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED True)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_CURRENT_SOURCE_DIR}/CMakeModules/")

if (MSVC)
    add_compile_options(/W4)
else()
    add_compile_options(-pedantic -Wall -Wextra -Wno-unused)
endif()

# Include sub-projects.
add_subdirectory(CBORLib)
add_subdirectory(CBORTests)
add_subdirectory(Crypto)
add_subdirectory(CryptoTests)
add_subdirectory(Webauthn)
add_subdirectory(WebauthnTests)
add_subdirectory(WebauthnClient)

if (${BUILD_EXAMPLE})
	add_subdirectory(Example)
endif()