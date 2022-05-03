
find_package(OpenSSL REQUIRED)

IF (${OPENSSL_VERSION} LESS 3.0.0)
	message(FATAL_ERROR "This library requires at leasst OpenSSL 3.0.0")
ENDIF()

add_library(Crypto
	Base64.cpp
	CertificateValidator.cpp
	Crypto.cpp
	ECDSAKey.cpp
	EdDSAKey.cpp
	Hash.cpp
	OpenSSLErros.cpp
	PublicKey.cpp
	RSAKey.cpp
	x509Cert.cpp
)

target_link_libraries(Crypto PRIVATE OpenSSL::Crypto CBORLib)

target_include_directories(Crypto PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})