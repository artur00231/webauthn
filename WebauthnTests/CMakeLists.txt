
add_executable(WebauthnTests
	AttestationObjectTests.cpp
	pch.cpp
)

target_link_libraries(WebauthnTests PRIVATE gtest_main Webauthn CBORLib Crypto)

include(GoogleTest)
gtest_discover_tests(WebauthnTests)