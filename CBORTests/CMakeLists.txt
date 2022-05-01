
add_executable(CBORTests
	CBORTests.cpp
	pch.cpp
)

target_link_libraries(CBORTests PRIVATE gtest_main CBORLib)

include(GoogleTest)
gtest_discover_tests(CBORTests)