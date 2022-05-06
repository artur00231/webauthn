
find_package(OpenSSL REQUIRED)

IF (${OPENSSL_VERSION} LESS 3.0.0)
	message(FATAL_ERROR "This library requires at leasst OpenSSL 3.0.0")
ENDIF()

add_library(Crypto
	CORE/PublicKey.cpp
	Base64.cpp
	CertificateValidator.cpp
	ECDSAKey.cpp
	EdDSAKey.cpp
	Hash.cpp
	OpenSSLErros.cpp
	RSAKey.cpp
	x509Cert.cpp
)

add_library(CryptoLite INTERFACE)

target_link_libraries(Crypto PRIVATE OpenSSL::Crypto CBORLib)

target_include_directories(Crypto PUBLIC ${CMAKE_CURRENT_SOURCE_DIR} "${CMAKE_CURRENT_SOURCE_DIR}/CORE")

target_include_directories(CryptoLite INTERFACE "${CMAKE_CURRENT_SOURCE_DIR}/CORE")

IF (MSVC)
	target_compile_options(CryptoLite INTERFACE /DPUBLICKEY_CRYPTO_LITE)
	target_compile_options(Crypto PUBLIC /DPUBLICKEY_CRYPTO_FORCE_FULL)
ELSE()
	target_compile_options(CryptoLite INTERFACE -DDPUBLICKEY_CRYPTO_LITE)
	target_compile_options(Crypto PUBLIC -DPUBLICKEY_CRYPTO_FORCE_FULL)
ENDIF()