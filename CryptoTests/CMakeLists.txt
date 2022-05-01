
add_executable(CryptoTests
	Base64Tests.cpp
	CertificateValidatorTests.cpp
	ECDSAKeyTests.cpp
	EdDSAKeyTests.cpp
	HashTests.cpp
	PublicKeyParserTests.cpp
	RSAKeyTests.cpp
	pch.cpp
)

target_link_libraries(CryptoTests PRIVATE gtest_main Crypto CBORLib)

include(GoogleTest)
gtest_discover_tests(CryptoTests)

#Copy test data to build directory
add_custom_command(TARGET CryptoTests POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_directory
        "${CMAKE_CURRENT_SOURCE_DIR}/test_data"
        $<TARGET_FILE_DIR:CryptoTests>/test_data)